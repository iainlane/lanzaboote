use crate::{
    companions::{CompanionInitrd, CompanionInitrdType},
    efivars::BOOT_LOADER_VENDOR_UUID,
    tpm::{tpm_log_event_ascii, tpm_log_event_utf16},
    uefi_helpers::{ParsedPe, PeInMemory},
};
use alloc::{borrow::Cow, string::ToString, vec::Vec};
use lanzaboote_shared::unified_sections::{UnifiedSection, UnifiedSectionDataSource};
use log::info;
use uefi::{
    cstr16,
    proto::tcg::PcrIndex,
    runtime::{self, VariableAttributes},
};

const TPM_PCR_INDEX_BOOT_LOADER: PcrIndex = PcrIndex(4);
/// This is where any stub payloads are extended, e.g. kernel ELF image, embedded initrd
/// and so on.
/// Compared to PCR4, this contains only the unified sections rather than the whole PE image as-is.
///
/// Per the [UKI specification](https://uapi-group.org/specifications/specs/unified_kernel_image/#uki-tpm-pcr-measurements):
/// "For each section two measurements shall be made into PCR 11 with the event code EV_IPL:
///
/// 1. The section name in ASCII (including one trailing NUL byte)
/// 2. The (binary) section contents"
///
/// Measurements are made in canonical order, interleaved: section name, section data, next section name, etc.
pub const TPM_PCR_INDEX_KERNEL_IMAGE: PcrIndex = PcrIndex(11);
/// This is where lanzastub extends the kernel command line and any passed credentials into
pub const TPM_PCR_INDEX_KERNEL_CONFIG: PcrIndex = PcrIndex(12);
/// This is where we extend the initrd sysext images into which we pass to the booted kernel
pub const TPM_PCR_INDEX_SYSEXTS: PcrIndex = PcrIndex(13);

fn encode_pcr_index(pcr_index: PcrIndex) -> Vec<u8> {
    let mut encoded = pcr_index
        .0
        .to_string()
        .encode_utf16()
        .flat_map(|c| c.to_le_bytes())
        .collect::<Vec<u8>>();
    encoded.extend_from_slice(&[0, 0]);
    encoded
}

fn set_stub_pcr_variable(name: &uefi::CStr16, pcr_index: PcrIndex) -> uefi::Result<()> {
    runtime::set_variable(
        name,
        &BOOT_LOADER_VENDOR_UUID,
        VariableAttributes::BOOTSERVICE_ACCESS | VariableAttributes::RUNTIME_ACCESS,
        &encode_pcr_index(pcr_index),
    )?;
    Ok(())
}

fn ensure_utf16_bytes_with_nul(bytes: &[u8]) -> Cow<'_, [u8]> {
    if bytes.ends_with(&[0, 0]) {
        Cow::Borrowed(bytes)
    } else {
        let mut owned = bytes.to_vec();
        owned.extend_from_slice(&[0, 0]);
        Cow::Owned(owned)
    }
}

/// Measure arbitrary data into PCR 4 via an IPL event.
pub fn measure_boot_loader(buffer: &[u8], description: &str) -> uefi::Result<()> {
    tpm_log_event_ascii(TPM_PCR_INDEX_BOOT_LOADER, buffer, description)?;
    Ok(())
}

pub fn measure_image(
    image: &PeInMemory,
    kernel_data: &[u8],
    initrd_data: &[u8],
) -> uefi::Result<u32> {
    let pe = ParsedPe::from_pe_in_memory(image)?;
    // Build a list of unified_sections and sort by canonical order.
    // Per UKI spec: "shall measure the sections listed above, starting from the .linux section,
    // in the order as listed (which should be considered the canonical order)."
    let mut sections_to_measure = Vec::new();
    for section_name in pe.sections() {
        if let Ok(unified_section) = UnifiedSection::try_from(section_name) {
            if unified_section.should_be_measured() {
                sections_to_measure.push(unified_section);
            }
        }
    }
    sections_to_measure.sort();

    let mut measurements = 0;
    for unified_section in sections_to_measure {
        let section_name = unified_section.name();

        let section_data = pe.section_data(section_name);
        // Use kernel/initrd data that were loaded from file system to match systemd-stub's measuring
        let data = match unified_section.data_source() {
            UnifiedSectionDataSource::ExternalKernel => Some(kernel_data),
            UnifiedSectionDataSource::ExternalInitrd => Some(initrd_data),
            UnifiedSectionDataSource::Embedded => section_data.as_deref(),
        };

        if let Some(data) = data {
            info!("Measuring section `{}`...", section_name);

            // 1. "The section name in ASCII (including one trailing NUL byte)"
            let section_name_ascii = alloc::format!("{}\0", section_name);
            if tpm_log_event_ascii(
                TPM_PCR_INDEX_KERNEL_IMAGE,
                section_name_ascii.as_bytes(),
                section_name,
            )? {
                measurements += 1;
            }

            // 2. "The (binary) section contents"
            if tpm_log_event_ascii(TPM_PCR_INDEX_KERNEL_IMAGE, data, section_name)? {
                measurements += 1;
            }
        }
    }

    if measurements > 0 {
        set_stub_pcr_variable(cstr16!("StubPcrKernelImage"), TPM_PCR_INDEX_KERNEL_IMAGE)?;
    }

    Ok(measurements)
}

/// Measure a custom load-options string into PCR 12 using systemd-stub's event encoding.
/// The buffer is expected to contain UTF-16LE data suitable for Linux EFI handoff.
pub fn measure_load_options(load_options: &[u8]) -> uefi::Result<bool> {
    if load_options.is_empty() {
        return Ok(false);
    }

    let load_options = ensure_utf16_bytes_with_nul(load_options);

    if tpm_log_event_utf16(
        TPM_PCR_INDEX_KERNEL_CONFIG,
        load_options.as_ref(),
        load_options.as_ref(),
    )? {
        set_stub_pcr_variable(
            cstr16!("StubPcrKernelParameters"),
            TPM_PCR_INDEX_KERNEL_CONFIG,
        )?;
        return Ok(true);
    }

    Ok(false)
}

/// Performs all the expected measurements for any list of
/// companion initrds of any form.
///
/// Relies on the passed order of `companions` for measurements in the same PCR.
/// A stable order is expected for measurement stability.
pub fn measure_companion_initrds(companions: &[CompanionInitrd]) -> uefi::Result<u32> {
    let mut measurements = 0;
    let mut kernel_config_measured = false;
    let mut sysext_measured = false;
    let mut confext_measured = false;

    for initrd in companions {
        let (pcr, description) = match initrd.r#type {
            CompanionInitrdType::PcrSignature | CompanionInitrdType::PcrPublicKey => continue,
            CompanionInitrdType::Credentials => (TPM_PCR_INDEX_KERNEL_CONFIG, "Credentials initrd"),
            CompanionInitrdType::GlobalCredentials => {
                (TPM_PCR_INDEX_KERNEL_CONFIG, "Global credentials initrd")
            }
            CompanionInitrdType::SystemExtension => {
                (TPM_PCR_INDEX_SYSEXTS, "System extension initrd")
            }
            CompanionInitrdType::GlobalSystemExtension => {
                (TPM_PCR_INDEX_SYSEXTS, "Global system extension initrd")
            }
            CompanionInitrdType::ConfigurationExtension => (
                TPM_PCR_INDEX_KERNEL_CONFIG,
                "Configuration extension initrd",
            ),
            CompanionInitrdType::GlobalConfigurationExtension => (
                TPM_PCR_INDEX_KERNEL_CONFIG,
                "Global configuration extension initrd",
            ),
        };

        if tpm_log_event_ascii(pcr, initrd.cpio.as_ref(), description)? {
            measurements += 1;
            match initrd.r#type {
                CompanionInitrdType::Credentials | CompanionInitrdType::GlobalCredentials => {
                    kernel_config_measured = true;
                }
                CompanionInitrdType::SystemExtension
                | CompanionInitrdType::GlobalSystemExtension => {
                    sysext_measured = true;
                }
                CompanionInitrdType::ConfigurationExtension
                | CompanionInitrdType::GlobalConfigurationExtension => {
                    kernel_config_measured = true;
                    confext_measured = true;
                }
                CompanionInitrdType::PcrSignature | CompanionInitrdType::PcrPublicKey => {}
            }
        }
    }

    if kernel_config_measured {
        set_stub_pcr_variable(
            cstr16!("StubPcrKernelParameters"),
            TPM_PCR_INDEX_KERNEL_CONFIG,
        )?;
    }

    if sysext_measured {
        set_stub_pcr_variable(cstr16!("StubPcrInitRDSysExts"), TPM_PCR_INDEX_SYSEXTS)?;
    }

    if confext_measured {
        set_stub_pcr_variable(
            cstr16!("StubPcrInitRDConfExts"),
            TPM_PCR_INDEX_KERNEL_CONFIG,
        )?;
    }

    Ok(measurements)
}
