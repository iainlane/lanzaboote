use crate::cpio::{Cpio, pack_cpio};
use alloc::{format, string::String, string::ToString, vec::Vec};
use uefi::{
    CStr16, CString16, cstr16,
    fs::{Path, PathBuf},
    proto::device_path::{
        DevicePath,
        text::{AllowShortcuts, DisplayOnly},
    },
};

const GLOBAL_CREDENTIALS_DIR: &CStr16 = cstr16!("\\loader\\credentials");
const GLOBAL_EXTENSIONS_DIR: &CStr16 = cstr16!("\\loader\\extensions");

/// Locate files with ASCII filenames and matching the suffix passed as a parameter.
/// Returns a list of their paths.
pub fn find_files(
    fs: &mut uefi::fs::FileSystem,
    search_path: &Path,
    suffix: &str,
) -> uefi::Result<Vec<PathBuf>> {
    find_files_filtered(fs, search_path, suffix, None)
}

/// Locate files with ASCII filenames and matching the suffix passed as a parameter, while
/// excluding a more specific suffix if requested.
pub fn find_files_filtered(
    fs: &mut uefi::fs::FileSystem,
    search_path: &Path,
    suffix: &str,
    excluded_suffix: Option<&str>,
) -> uefi::Result<Vec<PathBuf>> {
    let mut results = Vec::new();

    for maybe_entry in fs.read_dir(search_path).unwrap() {
        let entry = maybe_entry?;
        if entry.is_regular_file() {
            let fname = entry.file_name();
            if fname.is_ascii() {
                let filename = fname.to_string();
                if filename_matches_suffix(&filename, suffix, excluded_suffix) {
                    let mut full_path = CString16::from(search_path.to_cstr16());
                    full_path.push_str(cstr16!("\\"));
                    full_path.push_str(fname);
                    results.push(full_path.into());
                }
            }
        }
    }

    Ok(results)
}

fn filename_matches_suffix(filename: &str, suffix: &str, excluded_suffix: Option<&str>) -> bool {
    filename
        .get(filename.len().saturating_sub(suffix.len())..)
        .is_some_and(|tail| tail.eq_ignore_ascii_case(suffix))
        && excluded_suffix.is_none_or(|excluded| {
            filename
                .get(filename.len().saturating_sub(excluded.len())..)
                .is_none_or(|tail| !tail.eq_ignore_ascii_case(excluded))
        })
}

fn strip_automatic_boot_assessment_counter(stem: &str) -> &str {
    let Some((prefix, tail)) = stem.rsplit_once('+') else {
        return stem;
    };
    let Some((tries_left, tries_done)) = tail.split_once('-') else {
        return stem;
    };

    if !tries_left.is_empty()
        && !tries_done.is_empty()
        && tries_left.chars().all(|c| c.is_ascii_digit())
        && tries_done.chars().all(|c| c.is_ascii_digit())
    {
        prefix
    } else {
        stem
    }
}

fn image_dropin_directory_path(image_path: &str) -> String {
    let Some((directory, filename)) = image_path.rsplit_once('\\') else {
        return format!(
            "{}.extra.d",
            strip_automatic_boot_assessment_counter(image_path)
        );
    };
    let Some(stem) = filename.strip_suffix(".efi") else {
        return format!("{image_path}.extra.d");
    };

    format!(
        "{}\\{}.efi.extra.d",
        directory,
        strip_automatic_boot_assessment_counter(stem)
    )
}

fn legacy_image_dropin_directory_path(image_path: &str) -> String {
    format!("{image_path}.extra")
}

/// Returns the preferred image-specific companion drop-in directory if it exists.
/// The systemd-stub-compatible `<image>.efi.extra.d/` directory is preferred, while the
/// historical lanzaboote `<image>.extra/` directory is retained as a compatibility fallback.
pub fn get_default_dropin_directory(
    loaded_image_file_path: &DevicePath,
    fs: &mut uefi::fs::FileSystem,
) -> uefi::Result<Option<PathBuf>> {
    let image_path = loaded_image_file_path
        .to_string16(DisplayOnly(false), AllowShortcuts(false))
        .map_err(|_dpp_error| {
            log::warn!("Failed to obtain string representation of the loaded image file path");
            uefi::Error::new(uefi::Status::NOT_FOUND, ())
        })?
        .to_string();

    for candidate in [
        image_dropin_directory_path(&image_path),
        legacy_image_dropin_directory_path(&image_path),
    ] {
        let target_directory = CString16::try_from(candidate.as_str()).map_err(|_| {
            log::warn!("Failed to encode image-specific companion directory");
            uefi::Error::new(uefi::Status::NOT_FOUND, ())
        })?;

        if fs
            .metadata(target_directory.as_ref())
            .ok()
            .is_some_and(|metadata| metadata.is_directory())
        {
            return Ok(Some(PathBuf::from(target_directory)));
        }
    }

    Ok(None)
}

pub enum CompanionInitrdType {
    Credentials,
    GlobalCredentials,
    SystemExtension,
    GlobalSystemExtension,
    ConfigurationExtension,
    GlobalConfigurationExtension,
    PcrSignature,
    PcrPublicKey,
}

/// Potential companion initrd assembled on the fly
/// during discovery workflows, e.g. finding files in drop-in directories.
pub struct CompanionInitrd {
    pub r#type: CompanionInitrdType,
    pub cpio: Cpio,
}

/// Collect all credentials and return them as CPIO archive.
///
/// There are two variants of credentials:
///   - global: `$ESP/loader/credentials/*.cred`
///   - image-specific: `<image>.efi.extra.d/*.cred`
/// These are later measured into PCR 12 when TPM support is available.
pub fn discover_credentials(
    fs: &mut uefi::fs::FileSystem,
    default_dropin_dir: Option<&Path>,
) -> uefi::Result<Vec<CompanionInitrd>> {
    let mut companions = Vec::new();

    if fs.try_exists(GLOBAL_CREDENTIALS_DIR).unwrap_or(false) {
        let metadata = fs.metadata(GLOBAL_CREDENTIALS_DIR).map_err(|_err| {
            log::warn!("Failed to obtain metadata on `\\loader\\credentials` path (which is supposed to exist)");
            uefi::Error::new(uefi::Status::VOLUME_CORRUPTED, ())
        })?;
        if metadata.is_directory() {
            let global_credentials = find_files(fs, GLOBAL_CREDENTIALS_DIR.as_ref(), ".cred")?;

            if !global_credentials.is_empty() {
                companions.push(CompanionInitrd {
                    r#type: CompanionInitrdType::GlobalCredentials,
                    cpio: pack_cpio(
                        fs,
                        global_credentials,
                        ".extra/global_credentials",
                        0o500,
                        0o400,
                    )
                    .map_err(|_err| uefi::Status::LOAD_ERROR)?,
                });
            }
        }
    }

    if let Some(default_dropin_dir) = default_dropin_dir {
        let local_credentials = find_files(fs, default_dropin_dir, ".cred")?;

        if !local_credentials.is_empty() {
            companions.push(CompanionInitrd {
                r#type: CompanionInitrdType::Credentials,
                cpio: pack_cpio(fs, local_credentials, ".extra/credentials", 0o500, 0o400)
                    .map_err(|_err| uefi::Status::LOAD_ERROR)?,
            });
        }
    }

    Ok(companions)
}

/// Discover extension images (sysexts or confexts) from the image-specific drop-in directory
/// and the global extensions directory.
///
/// CPIOs are guaranteed to be stable and independent of file discovery order.
fn discover_extensions(
    fs: &mut uefi::fs::FileSystem,
    default_dropin_dir: Option<&Path>,
    suffix: &str,
    excluded_suffix: Option<&str>,
    local_cpio_target: &str,
    global_cpio_target: &str,
    local_type: CompanionInitrdType,
    global_type: CompanionInitrdType,
) -> uefi::Result<Vec<CompanionInitrd>> {
    let mut companions = Vec::new();

    if fs.try_exists(GLOBAL_EXTENSIONS_DIR).unwrap_or(false) {
        let metadata = fs.metadata(GLOBAL_EXTENSIONS_DIR).map_err(|_err| {
            log::warn!("Failed to obtain metadata on `\\loader\\extensions` path (which is supposed to exist)");
            uefi::Error::new(uefi::Status::VOLUME_CORRUPTED, ())
        })?;
        if metadata.is_directory() {
            let global_files =
                find_files_filtered(fs, GLOBAL_EXTENSIONS_DIR.as_ref(), suffix, excluded_suffix)?;
            if !global_files.is_empty() {
                companions.push(CompanionInitrd {
                    r#type: global_type,
                    cpio: pack_cpio(fs, global_files, global_cpio_target, 0o555, 0o444)
                        .map_err(|_err| uefi::Status::LOAD_ERROR)?,
                });
            }
        }
    }

    if let Some(dropin_dir) = default_dropin_dir {
        let local_files = find_files_filtered(fs, dropin_dir, suffix, excluded_suffix)?;
        if !local_files.is_empty() {
            companions.push(CompanionInitrd {
                r#type: local_type,
                cpio: pack_cpio(fs, local_files, local_cpio_target, 0o555, 0o444)
                    .map_err(|_err| uefi::Status::LOAD_ERROR)?,
            });
        }
    }

    Ok(companions)
}

/// Discover system extension images (*.raw, excluding *.confext.raw) from the local drop-in
/// directory next to the image and from the global `\loader\extensions\` directory.
pub fn discover_system_extensions(
    fs: &mut uefi::fs::FileSystem,
    default_dropin_dir: Option<&Path>,
) -> uefi::Result<Vec<CompanionInitrd>> {
    discover_extensions(
        fs,
        default_dropin_dir,
        ".raw",
        Some(".confext.raw"),
        ".extra/sysext",
        ".extra/global_sysext",
        CompanionInitrdType::SystemExtension,
        CompanionInitrdType::GlobalSystemExtension,
    )
}

/// Discover configuration extension images (*.confext.raw) from the local drop-in directory
/// next to the image and from the global `\loader\extensions\` directory.
pub fn discover_configuration_extensions(
    fs: &mut uefi::fs::FileSystem,
    default_dropin_dir: Option<&Path>,
) -> uefi::Result<Vec<CompanionInitrd>> {
    discover_extensions(
        fs,
        default_dropin_dir,
        ".confext.raw",
        None,
        ".extra/confext",
        ".extra/global_confext",
        CompanionInitrdType::ConfigurationExtension,
        CompanionInitrdType::GlobalConfigurationExtension,
    )
}

#[cfg(test)]
mod tests {
    use super::{
        filename_matches_suffix, image_dropin_directory_path, legacy_image_dropin_directory_path,
        strip_automatic_boot_assessment_counter,
    };

    #[test]
    fn strips_boot_assessment_counter_from_image_name() {
        assert_eq!(
            image_dropin_directory_path("\\EFI\\Linux\\nixos-generation-1+3-1.efi"),
            "\\EFI\\Linux\\nixos-generation-1.efi.extra.d"
        );
    }

    #[test]
    fn keeps_plain_image_name_for_dropin_directory() {
        assert_eq!(
            image_dropin_directory_path("\\EFI\\Linux\\nixos-generation-1.efi"),
            "\\EFI\\Linux\\nixos-generation-1.efi.extra.d"
        );
    }

    #[test]
    fn keeps_legacy_dropin_path_shape_for_compatibility() {
        assert_eq!(
            legacy_image_dropin_directory_path("\\EFI\\Linux\\nixos-generation-1.efi"),
            "\\EFI\\Linux\\nixos-generation-1.efi.extra"
        );
    }

    #[test]
    fn only_strips_valid_automatic_boot_assessment_suffixes() {
        assert_eq!(strip_automatic_boot_assessment_counter("foo+3-0"), "foo");
        assert_eq!(
            strip_automatic_boot_assessment_counter("foo+3-bar"),
            "foo+3-bar"
        );
        assert_eq!(strip_automatic_boot_assessment_counter("foo"), "foo");
    }

    #[test]
    fn excludes_confexts_from_sysext_scan() {
        assert!(filename_matches_suffix(
            "addon.sysext.raw",
            ".raw",
            Some(".confext.raw")
        ));
        assert!(!filename_matches_suffix(
            "addon.confext.raw",
            ".raw",
            Some(".confext.raw")
        ));
    }

    #[test]
    fn suffix_matching_is_case_insensitive() {
        assert!(filename_matches_suffix("KERNEL.CRED", ".cred", None));
        assert!(filename_matches_suffix(
            "addon.CONFEXT.RAW",
            ".confext.raw",
            None
        ));
        assert!(!filename_matches_suffix(
            "addon.CONFEXT.RAW",
            ".raw",
            Some(".confext.raw")
        ));
    }
}
