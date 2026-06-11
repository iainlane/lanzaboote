//! Random seed handling.
//!
//! Reads the random seed file from the boot partition, mixes it with entropy
//! from the firmware and hands a fresh seed to the kernel via the
//! `LINUX_EFI_RANDOM_SEED_TABLE` configuration table. The seed file is
//! refreshed on disk before the seed is passed on, so that the same seed is
//! never given to the kernel twice.

use alloc::vec;
use core::ffi::c_void;

use linux_bootloader::efivars::BOOT_LOADER_VENDOR_UUID;
use log::warn;
use sha2::{Digest, Sha256};
use uefi::{
    CStr16, Guid, Status, StatusExt, boot,
    boot::MemoryType,
    cstr16, guid,
    proto::{
        media::file::{Directory, File, FileAttribute, FileInfo, FileMode, RegularFile},
        rng::Rng,
    },
    runtime, system,
};

/// Path of the random seed file, relative to the root of the boot partition.
const RANDOM_SEED_PATH: &CStr16 = cstr16!("\\loader\\random-seed");

/// Seed files shorter than this are treated like freshly created, empty ones.
const RANDOM_MAX_SIZE_MIN: u64 = 32;

/// Seed files larger than this are rejected.
const RANDOM_MAX_SIZE_MAX: u64 = 32 * 1024;

/// The Linux RNG is 256 bits, so provide this much.
const DESIRED_SEED_SIZE: usize = 32;

/// Basic domain separation in case somebody uses this data elsewhere.
const HASH_LABEL: &[u8] = b"systemd-boot random seed label v1";

/// GUID of the configuration table the kernel reads its boot-time entropy
/// from, defined in the kernel's `include/linux/efi.h`. The table is a `u32`
/// seed size followed by the seed bytes.
static LINUX_EFI_RANDOM_SEED_TABLE_GUID: Guid = guid!("1ce1e5bc-7ceb-42f2-81e5-8aadf180f57b");

/// Refresh the random seed on the boot partition and pass a fresh seed to
/// the kernel.
///
/// All failures are non-fatal so that the system still boots without a seed.
pub fn refresh_random_seed(secure_boot_enabled: bool) {
    // Without a filesystem to load from (e.g. when netbooted), there is no
    // seed file to process.
    let Ok(mut file_system) = boot::get_image_file_system(boot::image_handle()) else {
        return;
    };

    let Ok(mut root_dir) = file_system.open_volume() else {
        return;
    };

    let _ = process_random_seed(&mut root_dir, secure_boot_enabled);
}

fn process_random_seed(root_dir: &mut Directory, secure_boot_enabled: bool) -> uefi::Result {
    // hash = LABEL || size(input1) || input1 || ... || size(inputN) || inputN
    let mut hash = Sha256::new();
    hash.update(HASH_LABEL);

    // Mix in the seed a previous boot stage may already have passed along.
    // The old table is only erased at the very end, once a new one has been
    // installed, so that the kernel still receives a seed if we abort.
    let previous_table = find_previous_seed_table();
    let mut seeded_by_efi = false;
    match previous_table {
        None => hash_chunk(&mut hash, &[]),
        Some((address, size)) => {
            seeded_by_efi = size >= DESIRED_SEED_SIZE;
            // SAFETY: the seed bytes follow the `u32` size field.
            let previous_seed =
                unsafe { core::slice::from_raw_parts(address.add(size_of::<u32>()), size) };
            hash_chunk(&mut hash, previous_seed);
        }
    }

    // Entropy from the firmware RNG protects against a seed file that was
    // mistakenly replicated into many images.
    let mut random_bytes = [0u8; DESIRED_SEED_SIZE];
    match acquire_rng(&mut random_bytes) {
        Ok(()) => {
            seeded_by_efi = true;
            hash_chunk(&mut hash, &random_bytes);
        }
        Err(err) => {
            if err.status() != Status::NOT_READY {
                warn!("Failed to acquire RNG data, proceeding without: {err:?}");
            }

            // Without firmware entropy the only input is the mutable boot
            // partition. Under Secure Boot that must not be trusted alone.
            if !seeded_by_efi && secure_boot_enabled {
                return Err(Status::NOT_FOUND.into());
            }

            hash_chunk(&mut hash, &[]);
        }
    }

    // A system-specific token the installer may have placed in an EFI
    // variable. It survives duplication or replacement of disk images.
    match runtime::get_variable_boxed(cstr16!("LoaderSystemToken"), &BOOT_LOADER_VENDOR_UUID) {
        Ok((mut token, _)) => {
            if token.len() < DESIRED_SEED_SIZE && !seeded_by_efi {
                return Err(Status::NOT_FOUND.into());
            }

            hash_chunk(&mut hash, &token);
            erase(&mut token);
        }
        Err(err) => {
            if err.status() != Status::NOT_FOUND {
                warn!("Failed to read LoaderSystemToken EFI variable: {err:?}");
            }

            if !seeded_by_efi {
                return Err(err.status().into());
            }

            hash_chunk(&mut hash, &[]);
        }
    }

    let mut created = false;
    let mut open_result = root_dir.open(
        RANDOM_SEED_PATH,
        FileMode::ReadWrite,
        FileAttribute::empty(),
    );

    // If the file does not exist, but we are reasonably well seeded, create
    // the seed file.
    if matches!(&open_result, Err(err) if err.status() == Status::NOT_FOUND) && seeded_by_efi {
        created = true;
        open_result = root_dir.open(
            RANDOM_SEED_PATH,
            FileMode::CreateReadWrite,
            FileAttribute::empty(),
        );
    }

    let mut file = match open_result {
        Ok(handle) => handle
            .into_regular_file()
            .ok_or(Status::INVALID_PARAMETER)?,
        Err(err) => {
            // A missing seed file is not an error, just skip quietly.
            if !matches!(err.status(), Status::NOT_FOUND | Status::WRITE_PROTECTED) {
                warn!("Failed to open random seed file: {err:?}");
            }

            return Err(err);
        }
    };

    let mut file_size = 0u64;
    if !created {
        let info = file.get_boxed_info::<FileInfo>().map_err(|err| {
            warn!("Failed to get file info for random seed: {err:?}");
            err
        })?;

        // Treat a short file just like a freshly created one for robustness:
        // a previous run may have created the file and then been interrupted
        // before writing it, leaving it in place but too short.
        file_size = info.file_size();
        created = file_size < RANDOM_MAX_SIZE_MIN;
    }

    if created {
        hash_chunk(&mut hash, &[]);
    } else {
        if file_size > RANDOM_MAX_SIZE_MAX {
            warn!("Random seed file is too large.");
            return Err(Status::INVALID_PARAMETER.into());
        }

        let size = file_size as usize;
        let mut seed = vec![0u8; size];
        let read = file.read(&mut seed).map_err(|err| {
            warn!("Failed to read random seed file: {err:?}");
            err
        })?;
        if read != size {
            erase(&mut seed);
            warn!("Short read on random seed file.");
            return Err(Status::PROTOCOL_ERROR.into());
        }

        hash_chunk(&mut hash, &seed);
        erase(&mut seed);

        file.set_position(0).map_err(|err| {
            warn!("Failed to seek to beginning of random seed file: {err:?}");
            err
        })?;
    }

    // The firmware's monotonic counter is supposed to increase on every
    // single boot, so even if the changes to the boot partition should not be
    // persistent for some reason, the seed we generate still differs on every
    // boot.
    match next_monotonic_count() {
        Ok(counter) => hash_chunk(&mut hash, &counter.to_le_bytes()),
        Err(err) => {
            if !seeded_by_efi {
                warn!("Failed to acquire UEFI monotonic counter: {err:?}");
                return Err(err);
            }

            hash_chunk(&mut hash, &0u64.to_le_bytes());
        }
    }

    // The wall clock is known to be flaky, so don't bark on error.
    match runtime::get_time() {
        Ok(now) => hash_chunk(&mut hash, &time_entropy_bytes(&now)),
        Err(_) => hash_chunk(&mut hash, &[]),
    }

    // hash_key = HASH(hash)
    let hash_key: [u8; 32] = hash.finalize().into();

    // The value written back to disk and the value handed to the kernel are
    // derived from the same key but must never be equal, so that observing
    // one does not reveal the other: file_seed = HASH(hash_key || 0),
    // table_seed = HASH(hash_key || 1).
    let file_seed: [u8; DESIRED_SEED_SIZE] = Sha256::new()
        .chain_update(hash_key)
        .chain_update([0u8])
        .finalize()
        .into();

    // If the file is larger than what we write, zero out the remaining bytes
    // on disk. Truncating would be less wasteful, but EFI filesystem drivers
    // are flimsy; userspace eventually rewrites the file with a proper size.
    if !created && (DESIRED_SEED_SIZE as u64) < file_size {
        write_seed_file_tail_zeros(&mut file, file_size)?;
    }

    // Update the random seed on disk before we use it. If this fails the
    // seed must not be handed to the kernel: it would be replayed on the
    // next boot.
    file.write(&file_seed).map_err(|err| {
        warn!("Failed to write random seed file: {err:?}");
        err.to_err_without_payload()
    })?;
    file.flush().map_err(|err| {
        warn!("Failed to flush random seed file: {err:?}");
        err
    })?;

    let table_seed: [u8; DESIRED_SEED_SIZE] = Sha256::new()
        .chain_update(hash_key)
        .chain_update([1u8])
        .finalize()
        .into();
    install_seed_table(&table_seed).map_err(|err| {
        warn!("Failed to install EFI table for random seed: {err:?}");
        err
    })?;

    // Now that the new table is installed, the old one can safely be erased.
    if let Some((address, size)) = previous_table {
        // SAFETY: the previous table is no longer referenced by the
        // configuration table and is exclusively ours to erase.
        let previous = unsafe {
            core::slice::from_raw_parts_mut(address, size_of::<u32>().saturating_add(size))
        };
        erase(previous);
    }

    Ok(())
}

/// Zero the bytes of the seed file past the freshly written seed, then seek
/// back to the beginning.
fn write_seed_file_tail_zeros(file: &mut RegularFile, file_size: u64) -> uefi::Result {
    file.set_position(DESIRED_SEED_SIZE as u64).map_err(|err| {
        warn!("Failed to seek to offset of random seed file: {err:?}");
        err
    })?;

    let zeros = vec![0u8; (file_size as usize) - DESIRED_SEED_SIZE];
    file.write(&zeros).map_err(|err| {
        warn!("Failed to write random seed file: {err:?}");
        err.to_err_without_payload()
    })?;
    file.flush().map_err(|err| {
        warn!("Failed to flush random seed file: {err:?}");
        err
    })?;

    file.set_position(0).map_err(|err| {
        warn!("Failed to seek to beginning of random seed file: {err:?}");
        err
    })
}

/// Hash a length-prefixed chunk of input data:
/// `hash <- hash || size(data) || data`.
fn hash_chunk(hash: &mut Sha256, data: &[u8]) {
    hash.update((data.len() as u64).to_le_bytes());
    hash.update(data);
}

/// Overwrite a sensitive buffer so the data does not linger in memory.
fn erase(buffer: &mut [u8]) {
    for byte in buffer {
        // SAFETY: `byte` is a valid, exclusive reference.
        unsafe { core::ptr::write_volatile(byte, 0) };
    }
}

/// Find a previously installed random seed configuration table.
///
/// Returns the table address and the size of the seed it carries.
fn find_previous_seed_table() -> Option<(*mut u8, usize)> {
    let address = system::with_config_table(|tables| {
        tables
            .iter()
            .find(|entry| entry.guid == LINUX_EFI_RANDOM_SEED_TABLE_GUID)
            .map(|entry| entry.address)
    })?;

    if address.is_null() {
        return None;
    }

    let address = address.cast_mut().cast::<u8>();
    // SAFETY: the table starts with a `u32` seed size.
    let size = unsafe { address.cast::<u32>().read_unaligned() } as usize;

    Some((address, size))
}

/// Acquire entropy from the UEFI RNG protocol.
fn acquire_rng(buffer: &mut [u8]) -> uefi::Result {
    let handle = boot::get_handle_for_protocol::<Rng>()?;
    let mut rng = boot::open_protocol_exclusive::<Rng>(handle)?;
    rng.get_rng(None, buffer)
}

/// Query the firmware's monotonic counter, which is supposed to increase on
/// every boot.
fn next_monotonic_count() -> uefi::Result<u64> {
    let system_table = uefi::table::system_table_raw().ok_or(Status::UNSUPPORTED)?;
    // SAFETY: the pointer returned by `system_table_raw` is valid during boot.
    let system_table = unsafe { system_table.as_ref() };

    let boot_services = system_table.boot_services;
    if boot_services.is_null() {
        return Err(Status::UNSUPPORTED.into());
    }

    let mut count = 0u64;
    // SAFETY: `boot_services` points to the firmware's boot services table.
    unsafe { ((*boot_services).get_next_monotonic_count)(&mut count) }.to_result_with_val(|| count)
}

/// Serialize the current time for use as (weak) entropy input.
fn time_entropy_bytes(time: &runtime::Time) -> [u8; 16] {
    let mut out = [0u8; 16];
    out[0..2].copy_from_slice(&time.year().to_le_bytes());
    out[2] = time.month();
    out[3] = time.day();
    out[4] = time.hour();
    out[5] = time.minute();
    out[6] = time.second();
    out[8..12].copy_from_slice(&time.nanosecond().to_le_bytes());
    out[12..14].copy_from_slice(&time.time_zone().unwrap_or(0).to_le_bytes());
    out[14] = time.daylight().bits();
    out
}

/// Install a new random seed configuration table carrying `seed`.
fn install_seed_table(seed: &[u8; DESIRED_SEED_SIZE]) -> uefi::Result {
    let size = size_of::<u32>() + DESIRED_SEED_SIZE;
    let allocation = boot::allocate_pool(MemoryType::ACPI_RECLAIM, size)?;
    let ptr = allocation.as_ptr();

    // SAFETY: we write exactly `size` bytes into the fresh allocation.
    unsafe {
        core::ptr::copy_nonoverlapping(
            (DESIRED_SEED_SIZE as u32).to_le_bytes().as_ptr(),
            ptr,
            size_of::<u32>(),
        );
        core::ptr::copy_nonoverlapping(seed.as_ptr(), ptr.add(size_of::<u32>()), DESIRED_SEED_SIZE);
    }

    // SAFETY: the allocation is handed over to the configuration table and
    // is neither modified nor freed afterwards.
    unsafe {
        boot::install_configuration_table(
            &LINUX_EFI_RANDOM_SEED_TABLE_GUID,
            ptr.cast::<c_void>().cast_const(),
        )
    }
}
