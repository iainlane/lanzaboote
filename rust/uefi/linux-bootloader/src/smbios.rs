//! Minimal SMBIOS support: locating the structure table through the EFI
//! configuration tables and reading Type 11 (OEM strings) entries.

use alloc::string::{String, ToString};
use core::ffi::c_void;

use lanzaboote_shared::cmdline::mangle_stub_cmdline;
use uefi::{system, table::cfg::ConfigTableEntry};

/// Size of the header common to all SMBIOS structures: type, length and
/// handle.
const SMBIOS_HEADER_SIZE: usize = 4;

/// SMBIOS structure type carrying free-form OEM strings.
const SMBIOS_TYPE_OEM_STRINGS: u8 = 11;

/// SMBIOS structure type marking the end of the structure table.
const SMBIOS_TYPE_END_OF_TABLE: u8 = 127;

/// Size of the SMBIOS 3 (64-bit) entry point structure.
const SMBIOS3_ENTRY_POINT_SIZE: usize = 24;

/// Size of the legacy SMBIOS (32-bit) entry point structure.
const SMBIOS_ENTRY_POINT_SIZE: usize = 31;

/// OEM string prefix carrying extra kernel command line arguments.
const KERNEL_CMDLINE_EXTRA_PREFIX: &str = "io.systemd.stub.kernel-cmdline-extra=";

/// Extra kernel command line arguments passed in through the SMBIOS Type 11
/// OEM strings, already mangled into stub command line form.
///
/// SMBIOS OEM strings are controlled by the host (e.g. via QEMU's
/// `-smbios type=11,value=...`), so callers must not trust them inside a
/// confidential VM.
pub fn kernel_cmdline_extra() -> Option<String> {
    let value = find_oem_string(KERNEL_CMDLINE_EXTRA_PREFIX)?;
    let mangled = mangle_stub_cmdline(&value);

    (!mangled.is_empty()).then_some(mangled)
}

/// Find the first OEM string (SMBIOS Type 11) that begins with `prefix` and
/// return the remainder of that string.
pub fn find_oem_string(prefix: &str) -> Option<String> {
    let mut table = find_structure_table()?;

    loop {
        if table.len() < SMBIOS_HEADER_SIZE {
            return None;
        }

        let structure_type = table[0];
        let formatted_length = table[1] as usize;

        if structure_type == SMBIOS_TYPE_END_OF_TABLE || table.len() < formatted_length {
            return None;
        }

        if structure_type == SMBIOS_TYPE_OEM_STRINGS
            && formatted_length >= SMBIOS_HEADER_SIZE + size_of::<u8>()
        {
            return find_prefixed_string(&table[formatted_length..], prefix);
        }

        let next = structure_end(table)?;
        table = &table[next..];
    }
}

/// Iterate the NUL-terminated string set of a structure and return the
/// remainder of the first string starting with `prefix`.
fn find_prefixed_string(strings: &[u8], prefix: &str) -> Option<String> {
    let mut rest = strings;

    loop {
        let end = rest.iter().position(|&b| b == 0)?;
        if end == 0 {
            // Double NUL byte: end of the string set.
            return None;
        }

        if let Ok(s) = core::str::from_utf8(&rest[..end])
            && let Some(suffix) = s.strip_prefix(prefix)
        {
            return Some(suffix.to_string());
        }

        rest = &rest[end + 1..];
    }
}

/// Given a structure at the start of `table`, return the offset just past
/// the end of this structure (i.e. the start of the next one), accounting
/// for the formatted area and the trailing string set (terminated by a
/// double NUL byte). Returns `None` if the structure is malformed or runs
/// past the end of the table.
fn structure_end(table: &[u8]) -> Option<usize> {
    if table.len() < SMBIOS_HEADER_SIZE {
        return None;
    }

    let formatted_length = table[1] as usize;
    if table.len() < formatted_length {
        return None;
    }

    // Special case: if there are no strings appended, we'll see two NUL bytes.
    if table.len() >= formatted_length + 2
        && table[formatted_length..formatted_length + 2] == [0, 0]
    {
        return Some(formatted_length + 2);
    }

    // Skip over a populated string table.
    let mut offset = formatted_length;
    let mut first = true;
    loop {
        let next_nul = table[offset..].iter().position(|&b| b == 0)?;
        if !first && next_nul == 0 {
            // Double NUL byte: end of the string set.
            return Some(offset + 1);
        }

        offset += next_nul + 1;
        first = false;
    }
}

/// Locate the SMBIOS structure table via the EFI configuration tables,
/// preferring the SMBIOS 3 (64-bit) entry point over the legacy one.
fn find_structure_table() -> Option<&'static [u8]> {
    let (address, size) = system::with_config_table(|tables| {
        let find = |guid| {
            tables
                .iter()
                .find(|entry| entry.guid == guid)
                .map(|entry| entry.address)
        };

        find(ConfigTableEntry::SMBIOS3_GUID)
            .and_then(parse_smbios3_entry_point)
            .or_else(|| find(ConfigTableEntry::SMBIOS_GUID).and_then(parse_smbios_entry_point))
    })?;

    if address == 0 || size == 0 {
        return None;
    }

    // SAFETY: the firmware-provided entry point describes the location and
    // maximum size of the structure table, and memory is identity mapped
    // while boot services are active.
    Some(unsafe { core::slice::from_raw_parts(address as *const u8, size) })
}

/// Parse an SMBIOS 3 (64-bit) entry point and return the address and
/// maximum size of the structure table.
fn parse_smbios3_entry_point(entry_point: *const c_void) -> Option<(u64, usize)> {
    if entry_point.is_null() {
        return None;
    }

    // SAFETY: the configuration table entry points at the firmware's entry
    // point structure, which is at least this large.
    let ep =
        unsafe { core::slice::from_raw_parts(entry_point.cast::<u8>(), SMBIOS3_ENTRY_POINT_SIZE) };

    let anchor_matches = &ep[0..5] == b"_SM3_";
    let entry_point_length = ep[6] as usize;
    if !anchor_matches || entry_point_length > SMBIOS3_ENTRY_POINT_SIZE {
        return None;
    }

    let size = u32::from_le_bytes(ep[12..16].try_into().ok()?) as usize;
    let address = u64::from_le_bytes(ep[16..24].try_into().ok()?);

    Some((address, size))
}

/// Parse a legacy SMBIOS (32-bit) entry point and return the address and
/// size of the structure table.
fn parse_smbios_entry_point(entry_point: *const c_void) -> Option<(u64, usize)> {
    if entry_point.is_null() {
        return None;
    }

    // SAFETY: the configuration table entry points at the firmware's entry
    // point structure, which is at least this large.
    let ep =
        unsafe { core::slice::from_raw_parts(entry_point.cast::<u8>(), SMBIOS_ENTRY_POINT_SIZE) };

    let anchor_matches = &ep[0..4] == b"_SM_";
    let entry_point_length = ep[5] as usize;
    if !anchor_matches || entry_point_length > SMBIOS_ENTRY_POINT_SIZE {
        return None;
    }

    let size = u16::from_le_bytes(ep[22..24].try_into().ok()?) as usize;
    let address = u64::from(u32::from_le_bytes(ep[24..28].try_into().ok()?));

    Some((address, size))
}
