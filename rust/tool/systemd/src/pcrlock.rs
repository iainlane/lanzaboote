use std::borrow::Cow;
use std::collections::BTreeSet;
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use anyhow::{Context, Result, anyhow, bail, ensure};
use lanzaboote_shared::unified_sections::{
    UNIFIED_SECTION_ORDER, UnifiedSection, UnifiedSectionDataSource,
};
use lanzaboote_tool::pe::{read_section_as_string, read_section_data, resolve_efi_path};
use lanzaboote_tool::utils::file_hash;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

pub struct LockThinStubArgs {
    pub systemd: PathBuf,
    pub esp: PathBuf,
    pub pcrlock: PathBuf,
    pub stub: PathBuf,
}

pub struct LockBootLoaderArgs {
    pub systemd: PathBuf,
    pub esp: PathBuf,
    pub pcrlock: PathBuf,
}

pub struct GcArgs {
    pub systemd: PathBuf,
    pub pcrlock: PathBuf,
    pub keep: Vec<String>,
}

/// Output describing what lock-boot-loader or lock-thin-stub did.
pub struct LockResult {
    /// SHA-256 hex digest of the PE binary that was locked.
    pub pe_hash: String,
}

pub fn lock_boot_loader(args: LockBootLoaderArgs) -> Result<LockResult> {
    let boot_loader_path = discover_boot_loader(&args.esp)?;
    let pe_hash = hex_string(&file_hash(&boot_loader_path)?);

    let pcrlock_path = resolve_pcrlock_path(&args.pcrlock, &pe_hash);
    if pcrlock_path.exists() {
        return Ok(LockResult { pe_hash });
    }

    let records = run_pcrlock(&args.systemd, &["lock-pe"], Some(&boot_loader_path), None)?;
    write_pcrlock(&pcrlock_path, &records)?;
    Ok(LockResult { pe_hash })
}

pub fn lock_thin_stub(args: LockThinStubArgs) -> Result<LockResult> {
    let pe_hash = hex_string(&file_hash(&args.stub)?);

    let pcrlock_path = resolve_pcrlock_path(&args.pcrlock, &pe_hash);
    if pcrlock_path.exists() {
        return Ok(LockResult { pe_hash });
    }

    let records = generate_records(&args.systemd, &args.esp, &args.stub)?;
    write_pcrlock(&pcrlock_path, &records)?;
    Ok(LockResult { pe_hash })
}

fn hex_string(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// Remove pcrlock variant files for PE binaries that are neither installed
/// nor part of the currently booted state.
///
/// A variant is retained when its hash is in `keep` (the binary is still
/// present), or when every digest it records appears in the current TPM
/// event log: such a binary participated in this boot, and the policy must
/// keep recognising the booted state until the next reboot, even if the
/// binary itself has already been replaced.
pub fn gc(args: GcArgs) -> Result<()> {
    let log_digests = read_event_log_digests(&args.systemd);

    for entry in fs::read_dir(&args.pcrlock)
        .with_context(|| format!("Failed to read {}", args.pcrlock.display()))?
    {
        let path = entry?.path();
        if path
            .extension()
            .is_none_or(|extension| extension != "pcrlock")
        {
            continue;
        }
        let Some(stem) = path.file_stem().and_then(|stem| stem.to_str()) else {
            continue;
        };

        if args.keep.iter().any(|keep| keep == stem) {
            continue;
        }

        if let Some(log_digests) = &log_digests
            && variant_is_in_log(&path, log_digests)
        {
            continue;
        }

        fs::remove_file(&path).with_context(|| format!("Failed to remove {}", path.display()))?;
    }

    Ok(())
}

/// All digest-shaped strings from the current TPM event log, or None when
/// the log cannot be read (e.g. while building an image without a TPM).
/// Collecting liberally only makes the garbage collection more conservative.
fn read_event_log_digests(systemd: &Path) -> Option<BTreeSet<String>> {
    let systemd_pcrlock = systemd.join("lib/systemd/systemd-pcrlock");
    let output = Command::new(&systemd_pcrlock)
        .args(["log", "--json=short"])
        .output()
        .ok()?;
    if !output.status.success() {
        return None;
    }

    let value: Value = serde_json::from_slice(&output.stdout).ok()?;
    let mut digests = BTreeSet::new();
    collect_digest_strings(&value, &mut digests);
    Some(digests)
}

fn looks_like_digest(value: &str) -> bool {
    matches!(value.len(), 40 | 64 | 96 | 128) && value.chars().all(|c| c.is_ascii_hexdigit())
}

fn collect_digest_strings(value: &Value, digests: &mut BTreeSet<String>) {
    match value {
        Value::String(string) if looks_like_digest(string) => {
            digests.insert(string.to_lowercase());
        }
        Value::Array(values) => {
            for value in values {
                collect_digest_strings(value, digests);
            }
        }
        Value::Object(map) => {
            for value in map.values() {
                collect_digest_strings(value, digests);
            }
        }
        _ => {}
    }
}

/// Whether every digest recorded in the variant file appears in the event
/// log. Unreadable or empty variants are not considered part of the log.
fn variant_is_in_log(path: &Path, log_digests: &BTreeSet<String>) -> bool {
    let Ok(bytes) = fs::read(path) else {
        return false;
    };
    let Ok(value) = serde_json::from_slice::<Value>(&bytes) else {
        return false;
    };

    let mut digests = BTreeSet::new();
    collect_record_digests(&value, &mut digests);

    !digests.is_empty() && digests.is_subset(log_digests)
}

fn collect_record_digests(value: &Value, digests: &mut BTreeSet<String>) {
    match value {
        Value::Array(values) => {
            for value in values {
                collect_record_digests(value, digests);
            }
        }
        Value::Object(map) => {
            if let Some(Value::String(digest)) = map.get("digest")
                && looks_like_digest(digest)
            {
                digests.insert(digest.to_lowercase());
            }
            for value in map.values() {
                collect_record_digests(value, digests);
            }
        }
        _ => {}
    }
}

/// If `pcrlock` is a directory, return `<dir>/<pe_hash>.pcrlock`; otherwise use it as-is.
fn resolve_pcrlock_path(pcrlock: &Path, pe_hash: &str) -> PathBuf {
    if pcrlock.is_dir() {
        pcrlock.join(format!("{pe_hash}.pcrlock"))
    } else {
        pcrlock.to_path_buf()
    }
}

fn write_pcrlock(path: &Path, records: &[Value]) -> Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)
            .with_context(|| format!("Failed to create {}", parent.display()))?;
    }
    let output = serde_json::to_vec_pretty(&json!({ "records": records }))
        .context("Failed to serialize pcrlock records")?;
    fs::write(path, output).with_context(|| format!("Failed to write {}", path.display()))?;
    Ok(())
}

fn generate_records(systemd: &Path, esp: &Path, stub: &Path) -> Result<Vec<Value>> {
    let stub_bytes =
        fs::read(stub).with_context(|| format!("Failed to read stub {}", stub.display()))?;

    let kernel_path = resolve_section_efi_path(esp, &stub_bytes, UnifiedSection::Linux)?;
    let initrd_path = resolve_section_efi_path(esp, &stub_bytes, UnifiedSection::Initrd)?;
    let kernel_bytes = read_external_payload(&stub_bytes, &kernel_path, ".linuxh", "kernel")?;
    let initrd_bytes = read_external_payload(&stub_bytes, &initrd_path, ".initrdh", "initrd")?;

    let mut records = run_pcrlock(systemd, &["lock-pe"], Some(stub), None)?;

    for section in UNIFIED_SECTION_ORDER {
        if !section.should_be_measured() {
            continue;
        }

        let section_bytes = match section.data_source() {
            UnifiedSectionDataSource::ExternalKernel => {
                Some(Cow::Borrowed(kernel_bytes.as_slice()))
            }
            UnifiedSectionDataSource::ExternalInitrd => {
                Some(Cow::Borrowed(initrd_bytes.as_slice()))
            }
            UnifiedSectionDataSource::Embedded => {
                read_section_data(&stub_bytes, section.name()).map(Cow::Owned)
            }
        };
        let Some(section_bytes) = section_bytes else {
            continue;
        };

        let mut section_name = section.name().as_bytes().to_vec();
        section_name.push(0);
        records.extend(run_pcrlock(
            systemd,
            &["lock-raw", "--pcr=11"],
            None,
            Some(&section_name),
        )?);

        records.extend(run_pcrlock(
            systemd,
            &["lock-raw", "--pcr=11"],
            None,
            Some(section_bytes.as_ref()),
        )?);
    }

    Ok(records)
}

fn discover_boot_loader(esp: &Path) -> Result<PathBuf> {
    let candidates = [
        esp.join("EFI/BOOT/BOOTX64.EFI"),
        esp.join("EFI/BOOT/BOOTAA64.EFI"),
        esp.join("EFI/systemd/systemd-bootx64.efi"),
        esp.join("EFI/systemd/systemd-bootaa64.efi"),
    ];

    candidates
        .into_iter()
        .find(|path| path.is_file())
        .ok_or_else(|| anyhow!("Failed to locate a systemd-boot PE on {}", esp.display()))
}

fn resolve_section_efi_path(
    esp: &Path,
    stub_bytes: &[u8],
    section: UnifiedSection,
) -> Result<PathBuf> {
    let raw_path = read_section_as_string(stub_bytes, section.name())
        .ok_or_else(|| anyhow!("Missing {} section", section.name()))?;
    resolve_efi_path(esp, raw_path.as_bytes())
}

fn read_external_payload(
    stub_bytes: &[u8],
    path: &Path,
    hash_section: &str,
    name: &str,
) -> Result<Vec<u8>> {
    let expected = read_section_data(stub_bytes, hash_section)
        .ok_or_else(|| anyhow!("Missing {hash_section} section"))?;

    // Read once and hash the buffer: the records must describe exactly the
    // bytes that were verified.
    let payload = fs::read(path)
        .with_context(|| format!("Failed to read {name} payload {}", path.display()))?;
    let actual = Sha256::digest(&payload);

    ensure!(
        expected.as_slice() == actual.as_slice(),
        "{name} payload {} does not match embedded {hash_section}",
        path.display()
    );

    Ok(payload)
}

fn run_pcrlock(
    systemd: &Path,
    args: &[&str],
    file: Option<&Path>,
    stdin: Option<&[u8]>,
) -> Result<Vec<Value>> {
    let systemd_pcrlock = systemd.join("lib/systemd/systemd-pcrlock");
    let mut cmd = Command::new(&systemd_pcrlock);
    cmd.args(args);
    if let Some(file) = file {
        cmd.arg(file);
    }
    if stdin.is_some() {
        cmd.stdin(Stdio::piped());
    }
    cmd.stdout(Stdio::piped());
    cmd.stderr(Stdio::piped());

    let mut child = cmd
        .spawn()
        .with_context(|| format!("Failed to spawn {}", systemd_pcrlock.display()))?;

    if let Some(stdin_data) = stdin {
        let mut child_stdin = child.stdin.take().context("Failed to open child stdin")?;
        child_stdin
            .write_all(stdin_data)
            .context("Failed to write to systemd-pcrlock stdin")?;
    }

    let output = child
        .wait_with_output()
        .with_context(|| format!("Failed to wait for {}", systemd_pcrlock.display()))?;

    if !output.status.success() {
        bail!(
            "systemd-pcrlock {} failed: {}",
            args.join(" "),
            String::from_utf8_lossy(&output.stderr)
        );
    }

    parse_records(&output.stdout)
}

fn parse_records(bytes: &[u8]) -> Result<Vec<Value>> {
    let value: Value = serde_json::from_slice(bytes).context("Failed to parse pcrlock JSON")?;
    let records = value
        .get("records")
        .and_then(Value::as_array)
        .ok_or_else(|| anyhow!("pcrlock output is missing a records array"))?;
    Ok(records.clone())
}

pub struct PcrlockPaths {
    /// The directory containing the Lanzaboote `.pclock` config files for systemd-pcrlock.
    pcrlock: PathBuf,
    lanzaboote: PathBuf,
    bootloader: PathBuf,
}

impl PcrlockPaths {
    pub fn new(pcrlock: impl AsRef<Path>) -> Self {
        let pcrlock = pcrlock.as_ref().to_path_buf();
        Self {
            pcrlock: pcrlock.clone(),
            lanzaboote: pcrlock.join("635-lanzaboote.pcrlock.d"),
            bootloader: pcrlock.join("630-bootloader.pcrlock.d"),
        }
    }

    pub fn lanzaboote(&self) -> &Path {
        &self.lanzaboote
    }

    /// Return the path to a pcrlock measurement file inside the pcrlock directory for Lanzaboote.
    pub fn bootloader_measurement(&self, name: impl AsRef<str>) -> PathBuf {
        self.bootloader.join(format!("{}.pcrlock", name.as_ref()))
    }

    /// Return the path to a pcrlock measurement file inside the pcrlock directory for Lanzaboote.
    pub fn lanzaboote_measurement(&self, name: impl AsRef<str>) -> PathBuf {
        self.lanzaboote.join(format!("{}.pcrlock", name.as_ref()))
    }

    /// Return all pcrlock paths.
    ///
    /// This is useful for including the leading directories in the GC roots.
    pub fn iter(&self) -> std::array::IntoIter<&PathBuf, 2> {
        [&self.pcrlock, &self.lanzaboote].into_iter()
    }
}

/// Lock a PE binary with systemd-pcrlock and write the pcrlock component.
///
/// This calls `systemd-pcrlock lock-pe` and writes the component to `pcrlock_component`.
pub fn lock_pe(binary_path: impl AsRef<Path>, pcrlock_component: impl AsRef<Path>) -> Result<()> {
    let status = Command::new("systemd-pcrlock")
        .arg("lock-pe")
        .arg(binary_path.as_ref())
        .arg("--pcrlock")
        .arg(pcrlock_component.as_ref())
        .status()
        .context("Failed to run systemd-pcrlock. Most likely, the binary is not on PATH")?;
    if !status.success() {
        bail!(
            "Failed to lock PE binary {} via systemd-pcrlock and write pcrlock component to {}",
            binary_path.as_ref().display(),
            pcrlock_component.as_ref().display()
        );
    }

    Ok(())
}
