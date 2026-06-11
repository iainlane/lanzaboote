use core::{fmt, str::FromStr};

/// List of PE sections that have a special meaning with respect to the UKI specification.
///
/// The declaration order of these enum variants defines the canonical order for PCR 11
/// measurements. Per the
/// [UKI spec](https://uapi-group.org/specifications/specs/unified_kernel_image/#uki-tpm-pcr-measurements):
/// "shall measure the sections listed above, starting from the .linux section, in the order as
/// listed (which should be considered the canonical order)."
///
/// !!! DO NOT REORDER !!!
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
#[repr(u8)]
pub enum UnifiedSection {
    Linux = 0,
    OsRel = 1,
    CmdLine = 2,
    Initrd = 3,
    Ucode = 4,
    Splash = 5,
    Dtb = 6,
    Uname = 7,
    Sbat = 8,
    PcrSig = 9,
    PcrPkey = 10,
    Profile = 11,
    DtbAuto = 12,
    Hwids = 13,
    EfiFw = 14,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UnifiedSectionDataSource {
    Embedded,
    ExternalKernel,
    ExternalInitrd,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ParseUnifiedSectionError;

pub const UNIFIED_SECTION_ORDER: [UnifiedSection; 15] = [
    UnifiedSection::Linux,
    UnifiedSection::OsRel,
    UnifiedSection::CmdLine,
    UnifiedSection::Initrd,
    UnifiedSection::Ucode,
    UnifiedSection::Splash,
    UnifiedSection::Dtb,
    UnifiedSection::Uname,
    UnifiedSection::Sbat,
    UnifiedSection::PcrSig,
    UnifiedSection::PcrPkey,
    UnifiedSection::Profile,
    UnifiedSection::DtbAuto,
    UnifiedSection::Hwids,
    UnifiedSection::EfiFw,
];

// If you add a new variant to UnifiedSection, you must also add it here.
// This assertion catches drift at compile time: array length must equal the
// highest discriminant + 1.
const _: () = assert!(
    UNIFIED_SECTION_ORDER.len() == UnifiedSection::EfiFw as usize + 1,
    "UNIFIED_SECTION_ORDER length does not match UnifiedSection variant count"
);

impl TryFrom<&str> for UnifiedSection {
    type Error = ParseUnifiedSectionError;

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        Ok(match value {
            ".linux" => Self::Linux,
            ".osrel" => Self::OsRel,
            ".cmdline" => Self::CmdLine,
            ".initrd" => Self::Initrd,
            ".ucode" => Self::Ucode,
            ".splash" => Self::Splash,
            ".dtb" => Self::Dtb,
            ".uname" => Self::Uname,
            ".sbat" => Self::Sbat,
            ".pcrsig" => Self::PcrSig,
            ".pcrpkey" => Self::PcrPkey,
            ".profile" => Self::Profile,
            ".dtbauto" => Self::DtbAuto,
            ".hwids" => Self::Hwids,
            ".efifw" => Self::EfiFw,
            _ => return Err(ParseUnifiedSectionError),
        })
    }
}

impl FromStr for UnifiedSection {
    type Err = ParseUnifiedSectionError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        Self::try_from(value)
    }
}

impl fmt::Display for ParseUnifiedSectionError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("invalid unified section name")
    }
}

impl UnifiedSection {
    /// Whether this section should be measured into PCR 11.
    pub const fn should_be_measured(self) -> bool {
        !matches!(self, Self::PcrSig | Self::DtbAuto)
    }

    pub const fn data_source(self) -> UnifiedSectionDataSource {
        match self {
            Self::Linux => UnifiedSectionDataSource::ExternalKernel,
            Self::Initrd => UnifiedSectionDataSource::ExternalInitrd,
            _ => UnifiedSectionDataSource::Embedded,
        }
    }

    pub const fn name(self) -> &'static str {
        match self {
            Self::Linux => ".linux",
            Self::OsRel => ".osrel",
            Self::CmdLine => ".cmdline",
            Self::Initrd => ".initrd",
            Self::Ucode => ".ucode",
            Self::Splash => ".splash",
            Self::Dtb => ".dtb",
            Self::Uname => ".uname",
            Self::Sbat => ".sbat",
            Self::PcrSig => ".pcrsig",
            Self::PcrPkey => ".pcrpkey",
            Self::Profile => ".profile",
            Self::DtbAuto => ".dtbauto",
            Self::Hwids => ".hwids",
            Self::EfiFw => ".efifw",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{
        ParseUnifiedSectionError, UNIFIED_SECTION_ORDER, UnifiedSection, UnifiedSectionDataSource,
    };

    #[test]
    fn canonical_order_starts_with_linux() {
        assert_eq!(UNIFIED_SECTION_ORDER[0], UnifiedSection::Linux);
        assert_eq!(UNIFIED_SECTION_ORDER[3], UnifiedSection::Initrd);
    }

    #[test]
    fn skips_unmeasurable_sections() {
        assert!(!UnifiedSection::PcrSig.should_be_measured());
        assert!(!UnifiedSection::DtbAuto.should_be_measured());
        assert!(UnifiedSection::Profile.should_be_measured());
    }

    #[test]
    fn uses_external_data_for_thin_stub_payloads() {
        assert_eq!(
            UnifiedSection::Linux.data_source(),
            UnifiedSectionDataSource::ExternalKernel
        );
        assert_eq!(
            UnifiedSection::Initrd.data_source(),
            UnifiedSectionDataSource::ExternalInitrd
        );
        assert_eq!(
            UnifiedSection::CmdLine.data_source(),
            UnifiedSectionDataSource::Embedded
        );
    }

    #[test]
    fn parses_section_names() {
        assert_eq!(
            UnifiedSection::try_from(".linux"),
            Ok(UnifiedSection::Linux)
        );
        assert_eq!(".initrd".parse(), Ok(UnifiedSection::Initrd));
        assert_eq!(
            UnifiedSection::try_from(".not-a-section"),
            Err(ParseUnifiedSectionError)
        );
    }
}
