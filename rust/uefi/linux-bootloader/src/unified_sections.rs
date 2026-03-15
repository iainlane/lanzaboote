/// List of PE sections that have a special meaning with respect to the UKI specification.
///
/// The declaration order of these enum variants defines the canonical order for PCR 11 measurements.
/// Per the [UKI spec](https://uapi-group.org/specifications/specs/unified_kernel_image/#uki-tpm-pcr-measurements):
/// "shall measure the sections listed above, starting from the .linux section, in the order as listed
/// (which should be considered the canonical order)."
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

impl TryFrom<&str> for UnifiedSection {
    type Error = uefi::Error;
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
            _ => return Err(uefi::Status::INVALID_PARAMETER.into()),
        })
    }
}

impl UnifiedSection {
    /// Whether this section should be measured into TPM.
    pub fn should_be_measured(&self) -> bool {
        // .pcrsig is never measured per spec.
        //
        // .dtbauto requires hardware matching logic during section selection to identify the
        // chosen devicetree. Lanzaboote does not implement that selection yet, so measuring all
        // .dtbauto payloads would diverge further from systemd-stub.
        !matches!(self, UnifiedSection::PcrSig | UnifiedSection::DtbAuto)
    }

    /// Returns the PE section name for this unified section.
    pub fn name(&self) -> &'static str {
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
    use super::UnifiedSection;

    #[test]
    fn skips_unmeasurable_sections() {
        assert!(!UnifiedSection::PcrSig.should_be_measured());
        assert!(!UnifiedSection::DtbAuto.should_be_measured());
        assert!(UnifiedSection::Profile.should_be_measured());
        assert!(UnifiedSection::EfiFw.should_be_measured());
    }
}
