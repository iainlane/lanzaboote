use alloc::string::String;

fn shall_be_whitespace(c: char) -> bool {
    c <= '\u{20}' || c == '\u{7f}'
}

/// Normalise a kernel command line fragment for hand-off to the kernel.
///
/// Leading and trailing whitespace is removed and every inner control
/// character becomes a plain space.
pub fn mangle_stub_cmdline(cmdline: &str) -> String {
    let mut result = String::new();
    let mut last_non_whitespace_len = 0;

    for c in cmdline.chars().skip_while(|c| shall_be_whitespace(*c)) {
        if shall_be_whitespace(c) {
            result.push(' ');
        } else {
            result.push(c);
            last_non_whitespace_len = result.len();
        }
    }

    // Chop off trailing whitespace.
    result.truncate(last_non_whitespace_len);

    result
}

/// Whether an addon's `.uname` is compatible with the booted UKI's `.uname`.
///
/// An addon without a `.uname` section applies to every kernel; a UKI
/// without one accepts every addon.
pub fn addon_matches_uki_uname(uki_uname: Option<&str>, addon_uname: Option<&str>) -> bool {
    match (uki_uname, addon_uname) {
        (Some(uki_uname), Some(addon_uname)) => addon_uname == uki_uname,
        _ => true,
    }
}

#[cfg(test)]
mod tests {
    use super::{addon_matches_uki_uname, mangle_stub_cmdline};

    #[test]
    fn mangles_stub_cmdline() {
        assert_eq!(mangle_stub_cmdline("  foo\tbar\nbaz  "), "foo bar baz");
        assert_eq!(mangle_stub_cmdline(""), "");
        assert_eq!(mangle_stub_cmdline(" \x7f "), "");
    }

    #[test]
    fn addon_uname_matching() {
        assert!(addon_matches_uki_uname(None, None));
        assert!(addon_matches_uki_uname(None, Some("6.12.0")));
        assert!(addon_matches_uki_uname(Some("6.12.0"), None));
        assert!(addon_matches_uki_uname(Some("6.12.0"), Some("6.12.0")));
        assert!(!addon_matches_uki_uname(
            Some("6.12.0"),
            Some("definitely-not-6.12.0"),
        ));
    }
}
