use alloc::{string::String, vec, vec::Vec};
use core::{mem::MaybeUninit, mem::size_of_val, slice};
use log::warn;
use uefi::{
    CStr16, CString16, Status, boot,
    boot::LoadImageSource,
    cstr16,
    fs::{Path, PathBuf},
    proto::{
        BootPolicy,
        device_path::{DevicePath, build},
        loaded_image::LoadedImage,
        shim::ShimLock,
    },
};

use crate::companions::find_files;
use crate::uefi_helpers::{ParsedPe, PeLayout};
use lanzaboote_shared::cmdline::{addon_matches_uki_uname, mangle_stub_cmdline};

/// A command line fragment extracted from an addon PE file.
pub struct CmdlineAddon {
    pub cmdline: String,
}

fn secure_load_addon_image(file_path: &Path) -> uefi::Result<Vec<u8>> {
    let loaded_image = boot::open_protocol_exclusive::<LoadedImage>(boot::image_handle())?;
    let device_handle = loaded_image
        .device()
        .ok_or_else(|| uefi::Error::new(Status::UNSUPPORTED, ()))?;
    let device_path = boot::open_protocol_exclusive::<DevicePath>(device_handle)?;

    let mut file_path_storage =
        vec![MaybeUninit::uninit(); size_of_val(file_path.to_cstr16().as_slice_with_nul()) + 32];
    let file_path_builder = build::DevicePathBuilder::with_buf(&mut file_path_storage)
        .push(&build::media::FilePath {
            path_name: file_path.to_cstr16(),
        })
        .map_err(|_| uefi::Status::OUT_OF_RESOURCES)?;
    let full_device_path = device_path
        .append_path(
            file_path_builder
                .finalize()
                .map_err(|_| uefi::Status::OUT_OF_RESOURCES)?,
        )
        .map_err(|_| uefi::Status::OUT_OF_RESOURCES)?;

    let image_handle = boot::load_image(
        boot::image_handle(),
        LoadImageSource::FromDevicePath {
            device_path: &full_device_path,
            boot_policy: BootPolicy::ExactMatch,
        },
    )?;

    let pe_data = {
        let loaded_addon = boot::open_protocol_exclusive::<LoadedImage>(image_handle)?;
        let (image_base, image_size) = loaded_addon.info();
        let image_size = usize::try_from(image_size).map_err(|_| uefi::Status::LOAD_ERROR)?;
        unsafe { slice::from_raw_parts(image_base.cast::<u8>(), image_size) }.to_vec()
    };

    boot::unload_image(image_handle)?;
    Ok(pe_data)
}

fn read_addon_image(
    fs: &mut uefi::fs::FileSystem,
    file_path: &Path,
    secure_boot_enabled: bool,
) -> Option<(Vec<u8>, PeLayout)> {
    fn verify_with_shim(file_path: &Path, pe_data: &[u8]) -> uefi::Result<()> {
        let shim = boot::get_handle_for_protocol::<ShimLock>()
            .and_then(boot::open_protocol_exclusive::<ShimLock>)?;
        shim.verify(pe_data)?;
        log::info!("Verified addon {file_path} with shim lock protocol");
        Ok(())
    }

    match secure_load_addon_image(file_path) {
        // LoadImage hands back the relocated in-memory representation.
        Ok(data) => Some((data, PeLayout::Loaded)),
        Err(err) if !secure_boot_enabled => {
            warn!("Falling back to direct read for addon {file_path}: {err:?}");
            match fs.read(file_path) {
                Ok(data) => Some((data, PeLayout::Disk)),
                Err(read_err) => {
                    warn!("Failed to read addon {file_path}: {read_err:?}");
                    None
                }
            }
        }
        Err(err) => {
            warn!("Failed to securely load addon {file_path}: {err:?}");

            let pe_data = match fs.read(file_path) {
                Ok(data) => data,
                Err(read_err) => {
                    warn!("Failed to read addon {file_path}: {read_err:?}");
                    return None;
                }
            };

            match verify_with_shim(file_path, &pe_data) {
                Ok(()) => Some((pe_data, PeLayout::Disk)),
                Err(shim_err) => {
                    warn!(
                        "Failed to verify addon {file_path} with shim lock protocol: {shim_err:?}"
                    );
                    None
                }
            }
        }
    }
}

fn load_addon_files(
    fs: &mut uefi::fs::FileSystem,
    directory: &CStr16,
    addons: &mut Vec<CmdlineAddon>,
    uki_uname: Option<&str>,
    secure_boot_enabled: bool,
) {
    if !fs.try_exists(directory).unwrap_or(false) {
        return;
    }

    let mut files = match find_files(fs, directory.as_ref(), ".addon.efi") {
        Ok(files) => files,
        Err(err) => {
            warn!("Failed to read addon directory {directory}: {err:?}");
            return;
        }
    };

    files.sort();
    collect_cmdline_addons(fs, &files, addons, uki_uname, secure_boot_enabled);
}

/// Discover .addon.efi files from the global addons directory and the image-specific
/// drop-in directory, extract their .cmdline PE sections, and return them in a
/// deterministic order (global first, then image-specific, sorted by filename within
/// each group).
///
/// Addons that contain a .linux section are rejected (they are UKIs, not addons).
pub fn discover_cmdline_addons(
    fs: &mut uefi::fs::FileSystem,
    default_dropin_dir: Option<&Path>,
    uki_uname: Option<&str>,
    secure_boot_enabled: bool,
) -> uefi::Result<Vec<CmdlineAddon>> {
    let mut addons = Vec::new();

    load_addon_files(
        fs,
        cstr16!("\\loader\\addons"),
        &mut addons,
        uki_uname,
        secure_boot_enabled,
    );

    if let Some(dropin_dir) = default_dropin_dir {
        load_addon_files(
            fs,
            dropin_dir.to_cstr16(),
            &mut addons,
            uki_uname,
            secure_boot_enabled,
        );
    }

    Ok(addons)
}

fn collect_cmdline_addons(
    fs: &mut uefi::fs::FileSystem,
    files: &[PathBuf],
    addons: &mut Vec<CmdlineAddon>,
    uki_uname: Option<&str>,
    secure_boot_enabled: bool,
) {
    for file_path in files {
        let Some((pe_data, layout)) = read_addon_image(fs, file_path.as_ref(), secure_boot_enabled)
        else {
            continue;
        };

        let parsed = match layout {
            PeLayout::Loaded => ParsedPe::from_loaded_data(&pe_data),
            PeLayout::Disk => ParsedPe::from_disk_data(&pe_data),
        };
        let Ok(pe) = parsed else {
            warn!("Skipping {file_path}: failed to parse addon PE");
            continue;
        };

        if pe.section_data(".linux").is_some() {
            warn!("Skipping {file_path}: contains .linux section (UKI, not addon)");
            continue;
        }

        if let Some(addon_uname) = pe
            .section_data(".uname")
            .and_then(|data| String::from_utf8(data).ok())
        {
            let addon_uname = addon_uname.trim_end_matches('\0');
            if !addon_matches_uki_uname(uki_uname, Some(addon_uname)) {
                warn!("Skipping {file_path}: .uname mismatch between addon and UKI");
                continue;
            }
        }

        match pe
            .section_data(".cmdline")
            .and_then(|data| String::from_utf8(data).ok())
        {
            Some(cmdline) => {
                let cmdline = mangle_stub_cmdline(cmdline.trim_end_matches('\0'));
                if !cmdline.is_empty() {
                    addons.push(CmdlineAddon { cmdline });
                }
            }
            None => warn!("Addon {file_path} has no .cmdline section, skipping"),
        }
    }
}

pub fn encode_cmdline_utf16(cmdline: &str) -> uefi::Result<CString16> {
    CString16::try_from(cmdline).map_err(|_| uefi::Status::INVALID_PARAMETER.into())
}
