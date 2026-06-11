//! Confidential VM detection.

/// Whether we are running inside a confidential VM (AMD SEV or Intel TDX).
///
/// Data provided by the host, such as the SMBIOS tables, is not covered by
/// the attestation of a confidential VM and must not be trusted there.
///
/// Detection is only implemented for x86_64; other architectures report
/// `false`.
pub fn is_confidential_vm() -> bool {
    #[cfg(target_arch = "x86_64")]
    {
        x86_64::is_confidential_vm()
    }

    #[cfg(not(target_arch = "x86_64"))]
    {
        false
    }
}

#[cfg(target_arch = "x86_64")]
mod x86_64 {
    use core::arch::x86_64::{__cpuid, __cpuid_count};

    const CPUID_PROCESSOR_INFO_AND_FEATURE_BITS: u32 = 0x1;
    const CPUID_FEATURE_HYPERVISOR: u32 = 1 << 31;

    const CPUID_GET_HIGHEST_FUNCTION: u32 = 0x8000_0000;
    const CPUID_AMD_GET_ENCRYPTED_MEMORY_CAPABILITIES: u32 = 0x8000_001f;
    const EAX_SEV: u32 = 1 << 1;
    const MSR_AMD64_SEV: u32 = 0xc001_0131;
    const MSR_SEV: u64 = 1 << 0;
    const MSR_SEV_ES: u64 = 1 << 1;
    const MSR_SEV_SNP: u64 = 1 << 2;

    const CPUID_INTEL_TDX_ENUMERATION: u32 = 0x21;

    const CPUID_HYPERV_VENDOR_AND_MAX_FUNCTIONS: u32 = 0x4000_0000;
    const CPUID_HYPERV_FEATURES: u32 = 0x4000_0003;
    const CPUID_HYPERV_ISOLATION_CONFIG: u32 = 0x4000_000c;
    const CPUID_HYPERV_MIN: u32 = 0x4000_0005;
    const CPUID_HYPERV_MAX: u32 = 0x4000_ffff;
    const CPUID_HYPERV_CPU_MANAGEMENT: u32 = 1 << 12;
    const CPUID_HYPERV_ISOLATION: u32 = 1 << 22;
    const CPUID_HYPERV_ISOLATION_TYPE_MASK: u32 = 0xf;
    const CPUID_HYPERV_ISOLATION_TYPE_SNP: u32 = 2;
    const CPUID_HYPERV_ISOLATION_TYPE_TDX: u32 = 3;

    const CPUID_SIG_AMD: &[u8; 12] = b"AuthenticAMD";
    const CPUID_SIG_INTEL: &[u8; 12] = b"GenuineIntel";
    const CPUID_SIG_INTEL_TDX: &[u8; 12] = b"IntelTDX    ";
    const CPUID_SIG_HYPERV: &[u8; 12] = b"Microsoft Hv";

    pub(super) fn is_confidential_vm() -> bool {
        if !cpuid_in_hypervisor() {
            return false;
        }

        let (_, sig) = cpuid_signature_swapped(0);

        if &sig == CPUID_SIG_AMD {
            return detect_sev();
        }
        if &sig == CPUID_SIG_INTEL {
            return detect_tdx();
        }

        false
    }

    fn cpuid_in_hypervisor() -> bool {
        if __cpuid(0).eax < CPUID_PROCESSOR_INFO_AND_FEATURE_BITS {
            return false;
        }

        let features = __cpuid(CPUID_PROCESSOR_INFO_AND_FEATURE_BITS);
        features.ecx & CPUID_FEATURE_HYPERVISOR != 0
    }

    /// Read a CPUID vendor signature in EBX, EDX, ECX register order, as
    /// used by the processor vendor string. Returns EAX alongside it.
    fn cpuid_signature_swapped(leaf: u32) -> (u32, [u8; 12]) {
        let result = __cpuid_count(leaf, 0);

        let mut sig = [0u8; 12];
        sig[0..4].copy_from_slice(&result.ebx.to_le_bytes());
        sig[4..8].copy_from_slice(&result.edx.to_le_bytes());
        sig[8..12].copy_from_slice(&result.ecx.to_le_bytes());

        (result.eax, sig)
    }

    /// Read a CPUID vendor signature in EBX, ECX, EDX register order, as
    /// used by the Hyper-V vendor string. Returns EAX alongside it.
    fn cpuid_signature(leaf: u32) -> (u32, [u8; 12]) {
        let result = __cpuid_count(leaf, 0);

        let mut sig = [0u8; 12];
        sig[0..4].copy_from_slice(&result.ebx.to_le_bytes());
        sig[4..8].copy_from_slice(&result.ecx.to_le_bytes());
        sig[8..12].copy_from_slice(&result.edx.to_le_bytes());

        (result.eax, sig)
    }

    fn rdmsr(index: u32) -> u64 {
        let low: u32;
        let high: u32;

        // SAFETY: UEFI applications run at CPL 0, where RDMSR is permitted.
        // This is only reached on AMD CPUs that advertise the SEV feature,
        // which implies the SEV status MSR exists.
        unsafe {
            core::arch::asm!(
                "rdmsr",
                in("ecx") index,
                out("eax") low,
                out("edx") high,
                options(nomem, nostack, preserves_flags),
            );
        }

        (u64::from(high) << 32) | u64::from(low)
    }

    fn detect_sev() -> bool {
        if __cpuid(CPUID_GET_HIGHEST_FUNCTION).eax < CPUID_AMD_GET_ENCRYPTED_MEMORY_CAPABILITIES {
            return false;
        }

        let capabilities = __cpuid(CPUID_AMD_GET_ENCRYPTED_MEMORY_CAPABILITIES);

        // Azure blocks this CPUID leaf from its SEV-SNP guests, so fall back
        // to the Hyper-V specific CPUID checks.
        if capabilities.eax & EAX_SEV == 0 {
            return detect_hyperv_cvm(CPUID_HYPERV_ISOLATION_TYPE_SNP);
        }

        rdmsr(MSR_AMD64_SEV) & (MSR_SEV_SNP | MSR_SEV_ES | MSR_SEV) != 0
    }

    fn detect_tdx() -> bool {
        if __cpuid(CPUID_GET_HIGHEST_FUNCTION).eax < CPUID_INTEL_TDX_ENUMERATION {
            return false;
        }

        let (_, sig) = cpuid_signature_swapped(CPUID_INTEL_TDX_ENUMERATION);
        if &sig == CPUID_SIG_INTEL_TDX {
            return true;
        }

        detect_hyperv_cvm(CPUID_HYPERV_ISOLATION_TYPE_TDX)
    }

    fn detect_hyperv_cvm(isolation_type: u32) -> bool {
        let (max_function, sig) = cpuid_signature(CPUID_HYPERV_VENDOR_AND_MAX_FUNCTIONS);

        if !(CPUID_HYPERV_MIN..=CPUID_HYPERV_MAX).contains(&max_function) {
            return false;
        }

        if &sig != CPUID_SIG_HYPERV {
            return false;
        }

        let features = __cpuid(CPUID_HYPERV_FEATURES);
        if features.ebx & CPUID_HYPERV_ISOLATION == 0
            || features.ebx & CPUID_HYPERV_CPU_MANAGEMENT != 0
        {
            return false;
        }

        let isolation_config = __cpuid(CPUID_HYPERV_ISOLATION_CONFIG);
        isolation_config.ebx & CPUID_HYPERV_ISOLATION_TYPE_MASK == isolation_type
    }
}
