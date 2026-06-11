use alloc::{format, string::String};

/// Whether a filename ends with `suffix` (ASCII case-insensitive) while not
/// ending with the more specific `excluded_suffix`.
pub fn filename_matches_suffix(
    filename: &str,
    suffix: &str,
    excluded_suffix: Option<&str>,
) -> bool {
    filename
        .get(filename.len().saturating_sub(suffix.len())..)
        .is_some_and(|tail| tail.eq_ignore_ascii_case(suffix))
        && excluded_suffix.is_none_or(|excluded| {
            filename
                .get(filename.len().saturating_sub(excluded.len())..)
                .is_none_or(|tail| !tail.eq_ignore_ascii_case(excluded))
        })
}

/// Remove an Automatic Boot Assessment counter (`+tries` or `+tries-done`)
/// from the end of an image name stem.
pub fn strip_automatic_boot_assessment_counter(stem: &str) -> &str {
    let Some((prefix, tail)) = stem.rsplit_once('+') else {
        return stem;
    };

    let (tries_left, tries_done) = match tail.split_once('-') {
        Some(parts) => parts,
        None => (tail, "0"),
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

/// The image-specific companion drop-in directory (`<image>.efi.extra.d`),
/// with any boot assessment counter removed from the image name.
pub fn image_dropin_directory_path(image_path: &str) -> String {
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

/// The historical lanzaboote drop-in directory (`<image>.extra`).
pub fn legacy_image_dropin_directory_path(image_path: &str) -> String {
    format!("{image_path}.extra")
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
        assert_eq!(strip_automatic_boot_assessment_counter("foo+3"), "foo");
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
