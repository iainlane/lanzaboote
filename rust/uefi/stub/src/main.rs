#![no_main]
#![no_std]
#![deny(unsafe_op_in_unsafe_fn)]

extern crate alloc;

mod common;
mod thin;

use crate::thin::UkiComponents;
use alloc::{
    string::{String, ToString},
    vec::Vec,
};
use linux_bootloader::addons::{discover_cmdline_addons, encode_cmdline_utf16};
use linux_bootloader::companions::{
    discover_configuration_extensions, discover_credentials, discover_system_extensions,
    get_default_dropin_directory,
};
use linux_bootloader::cpio::pack_cpio_literal;
use linux_bootloader::efivars::{EfiLoaderFeatures, export_efi_variables, get_loader_features};
use linux_bootloader::measure::{measure_companion_initrds, measure_image, measure_load_options};
use linux_bootloader::tpm::tpm_available;
use linux_bootloader::uefi_helpers::{ParsedPe, booted_image_file};
use log::{info, warn};
use uefi::boot;
use uefi::prelude::*;

/// Lanzaboote stub name
pub static STUB_NAME: &str = concat!("lanzastub ", env!("CARGO_PKG_VERSION"));

/// Print the startup logo on boot.
fn print_logo() {
    info!(
        "
  _                      _                 _
 | |                    | |               | |
 | | __ _ _ __  ______ _| |__   ___   ___ | |_ ___
 | |/ _` | '_ \\|_  / _` | '_ \\ / _ \\ / _ \\| __/ _ \\
 | | (_| | | | |/ / (_| | |_) | (_) | (_) | ||  __/
 |_|\\__,_|_| |_/___\\__,_|_.__/ \\___/ \\___/ \\__\\___|

"
    );
}

#[entry]
fn main() -> Status {
    uefi::helpers::init().unwrap();

    print_logo();

    let is_tpm_available = tpm_available();
    let secure_boot_enabled = crate::common::get_secure_boot_status();
    let pe_in_memory = booted_image_file()
        .expect("Failed to extract the in-memory information about our own image");

    let components = UkiComponents::load_from_pe(&pe_in_memory)
        .expect("Failed to extract configuration from binary and load kernel/initrd from disk. Did you run lzbt?");

    if is_tpm_available {
        info!("TPM available, will proceed to measurements.");
        // Iterate over unified sections and measure them
        // For now, ignore failures during measurements.
        // TODO: in the future, devise a threat model where this can fail
        // and ensure this hard-fail correctly.
        let _ = measure_image(
            &pe_in_memory,
            &components.kernel_data,
            &components.initrd_data,
        );
    }

    if let Ok(features) = get_loader_features()
        && !features.contains(EfiLoaderFeatures::RandomSeed)
    {
        // FIXME: read the random seed from the ESP and pass it to the kernel.
        info!(
            "The boot loader does not handle the random seed, and lanzaboote does not support passing it yet."
        );
    }

    if export_efi_variables(STUB_NAME).is_err() {
        warn!(
            "Failed to export stub EFI variables, some features related to measured boot will not be available"
        );
    }

    // Resolve the kernel command line that will be used for booting, and
    // measure a custom one into PCR 12 before any addon measurements so the
    // event order is: load options, then addons.
    let resolved_cmdline = crate::common::get_cmdline(&components.cmdline);
    if resolved_cmdline.should_measure_in_pcr12 && is_tpm_available {
        let _ = measure_load_options(&resolved_cmdline.bytes);
    }

    // A list of dynamically assembled initrds, e.g. credential initrds or system extension
    // initrds.
    let mut dynamic_initrds: Vec<Vec<u8>> = Vec::new();

    // Extract .pcrsig and .pcrpkey from our own PE image and deliver them as
    // CPIO archives in the initrd. These are NOT measured as companions — .pcrsig
    // is excluded from measurement per spec, and .pcrpkey is already measured as a
    // PE section during measure_image().
    let parsed_pe =
        ParsedPe::from_pe_in_memory(&pe_in_memory).expect("Failed to parse our own PE image");
    let pcrsig_data = parsed_pe.section_data(".pcrsig");
    let pcrpkey_data = parsed_pe.section_data(".pcrpkey");

    if pcrsig_data.is_some() != pcrpkey_data.is_some() {
        warn!(
            "Only one of .pcrsig/.pcrpkey found in PE — PCR signature verification will not work"
        );
    }

    if let Some(pcrsig_data) = pcrsig_data {
        info!("Extracting .pcrsig section to initrd...");
        match pack_cpio_literal(
            &pcrsig_data,
            uefi::cstr16!("tpm2-pcr-signature.json").as_ref(),
            ".extra",
            0o555,
            0o444,
        ) {
            Ok(cpio) => dynamic_initrds.push(cpio.into_inner()),
            Err(e) => warn!("Failed to pack .pcrsig into CPIO archive: {:?}", e),
        }
    }

    if let Some(pcrpkey_data) = pcrpkey_data {
        info!("Extracting .pcrpkey section to initrd...");
        match pack_cpio_literal(
            &pcrpkey_data,
            uefi::cstr16!("tpm2-pcr-public-key.pem").as_ref(),
            ".extra",
            0o555,
            0o444,
        ) {
            Ok(cpio) => dynamic_initrds.push(cpio.into_inner()),
            Err(e) => warn!("Failed to pack .pcrpkey into CPIO archive: {:?}", e),
        }
    }

    let mut addon_cmdline: Option<alloc::string::String> = None;
    let uki_uname = parsed_pe
        .section_data(".uname")
        .and_then(|data| String::from_utf8(data).ok())
        .map(|uname| uname.trim_end_matches('\0').to_string());

    {
        // This is a block for doing filesystem operations once and for all, related to companion
        // files, nothing can open the LoadedImage protocol here.
        // Everything must use `filesystem`.
        let mut companions = Vec::new();
        let image_fs = uefi::boot::get_image_file_system(boot::image_handle());

        if let Ok(image_fs) = image_fs {
            let mut filesystem = uefi::fs::FileSystem::new(image_fs);
            let default_dropin_directory;

            if let Some(loaded_image_path) = pe_in_memory.file_path() {
                let discovered_default_dropin_dir =
                    get_default_dropin_directory(loaded_image_path, &mut filesystem);

                if discovered_default_dropin_dir.is_err() {
                    warn!("Failed to discover the default drop-in directory for companion files");
                }

                default_dropin_directory = discovered_default_dropin_dir.unwrap_or(None);
            } else {
                default_dropin_directory = None;
            }

            let dropin_ref = default_dropin_directory.as_ref().map(|x| x.as_ref());

            if let Ok(mut creds) = discover_credentials(&mut filesystem, dropin_ref) {
                companions.append(&mut creds);
            } else {
                warn!("Failed to discover any system credential");
            }

            if let Ok(mut sysexts) = discover_system_extensions(&mut filesystem, dropin_ref) {
                companions.append(&mut sysexts);
            } else {
                warn!("Failed to discover any system extension");
            }

            if let Ok(mut confexts) = discover_configuration_extensions(&mut filesystem, dropin_ref)
            {
                companions.append(&mut confexts);
            } else {
                warn!("Failed to discover any configuration extension");
            }

            // Discover .cmdline addons from addon PE files.
            if let Ok(addons) = discover_cmdline_addons(
                &mut filesystem,
                dropin_ref,
                uki_uname.as_deref(),
                secure_boot_enabled,
            ) {
                if !addons.is_empty() {
                    let combined: alloc::string::String = addons
                        .iter()
                        .map(|a| a.cmdline.as_str())
                        .collect::<Vec<_>>()
                        .join(" ");

                    info!("Addon command line: {}", combined);

                    // The addon command line is input to the boot, so it must
                    // be measured before use. Refuse it entirely if it cannot
                    // be encoded for measurement.
                    match encode_cmdline_utf16(&combined) {
                        Ok(addon_cmdline_utf16) => {
                            if is_tpm_available {
                                let _ = measure_load_options(addon_cmdline_utf16.as_bytes());
                            }
                            addon_cmdline = Some(combined);
                        }
                        Err(err) => {
                            warn!(
                                "Ignoring addon command line that cannot be encoded for measurement: {err:?}"
                            );
                        }
                    }
                }
            } else {
                warn!("Failed to discover command line addons");
            }

            if is_tpm_available {
                // TODO: in the future, devise a threat model where this can fail, see above
                // measurements to understand the context.
                let _ = measure_companion_initrds(&companions);
            }

            dynamic_initrds.append(
                &mut companions
                    .into_iter()
                    .map(|initrd| initrd.cpio.into_inner())
                    .collect(),
            );
        } else {
            warn!(
                "Failed to open the simple filesystem for the booted image, this is expected for netbooted systems, skipping companion extension..."
            );
        }
    }

    thin::boot_linux(
        boot::image_handle(),
        components,
        dynamic_initrds,
        resolved_cmdline.bytes,
        addon_cmdline.as_deref(),
    )
    .status()
}
