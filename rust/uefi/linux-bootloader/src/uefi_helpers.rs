use alloc::{borrow::ToOwned, vec::Vec};
use core::{cmp::min, ffi::c_void};

use goblin::pe::{PE, options::ParseOptions, section_table::SectionTable};
use uefi::{
    Result, boot,
    proto::{
        device_path::{DevicePath, FfiDevicePath},
        loaded_image::LoadedImage,
    },
};

#[derive(Debug, Clone, Copy)]
pub struct PeInMemory {
    image_device_path: Option<*const FfiDevicePath>,
    image_base: *const c_void,
    image_size: usize,
}

impl PeInMemory {
    /// Return a reference to the currently running image.
    ///
    /// # Safety
    ///
    /// The returned slice covers the whole loaded image in which we
    /// currently execute. This means the safety guarantees of
    /// [`core::slice::from_raw_parts`] that we use in this function
    /// are only guaranteed, if we we don't mutate anything in this
    /// range. This means no modification of global variables or
    /// anything.
    unsafe fn as_slice(&self) -> &'static [u8] {
        unsafe { core::slice::from_raw_parts(self.image_base as *const u8, self.image_size) }
    }

    /// Return optionally a reference to the device path
    /// relative to this image's simple file system.
    pub fn file_path(&self) -> Option<&DevicePath> {
        // SAFETY:
        //
        // The returned reference to the device path will be alive as long
        // as `self` is alive as it relies on the thin internal pointer to remain around,
        // which is guaranteed as long as the structure is not dropped.
        //
        // This means that the safety guarantees of [`uefi::device_path::DevicePath::from_ffi_ptr`]
        // are guaranteed.
        unsafe {
            self.image_device_path
                .map(|ptr| DevicePath::from_ffi_ptr(ptr))
        }
    }
}

/// Open the currently executing image as a file.
pub fn booted_image_file() -> Result<PeInMemory> {
    let loaded_image = boot::open_protocol_exclusive::<LoadedImage>(boot::image_handle())?;
    let (image_base, image_size) = loaded_image.info();

    Ok(PeInMemory {
        image_device_path: loaded_image.file_path().map(|dp| dp.as_ffi_ptr()),
        image_base,
        image_size: usize::try_from(image_size).map_err(|_| uefi::Status::INVALID_PARAMETER)?,
    })
}

/// How a PE binary's bytes are laid out in the buffer being parsed.
///
/// Sections of an image that the firmware loaded live at their virtual
/// addresses, while sections of a file read from disk live at their raw
/// file offsets. Extracting section data with the wrong layout reads
/// unrelated bytes or runs out of bounds.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PeLayout {
    Loaded,
    Disk,
}

/// An analyzed PE
pub struct ParsedPe<'a> {
    data: &'a [u8],
    parsed: PE<'a>,
    layout: PeLayout,
}

impl<'a> ParsedPe<'a> {
    /// Parse the currently running image.
    pub fn from_pe_in_memory(pe_in_memory: &PeInMemory) -> uefi::Result<Self> {
        // SAFETY: We get a slice that represents our currently running
        // image and then parse the PE data structures from it. This is
        // safe, because we don't touch any data in the data sections that
        // might conceivably change while we look at the slice.
        // (data sections := all unified sections that can be measured.)
        let data = unsafe { pe_in_memory.as_slice() };

        Self::parse(data, PeLayout::Loaded)
    }

    /// Parse a PE image that the firmware loaded into memory, e.g. an addon
    /// verified and loaded via LoadImage.
    pub fn from_loaded_data(data: &'a [u8]) -> uefi::Result<Self> {
        Self::parse(data, PeLayout::Loaded)
    }

    /// Parse a PE binary in its on-disk representation, e.g. a file read
    /// straight from the ESP.
    pub fn from_disk_data(data: &'a [u8]) -> uefi::Result<Self> {
        Self::parse(data, PeLayout::Disk)
    }

    fn parse(data: &'a [u8], layout: PeLayout) -> uefi::Result<Self> {
        let mut parse_options = ParseOptions::default();
        // Don't parse attribute certificates: they are not mapped in loaded
        // images (the security directory points at file offsets), and addons
        // don't need them parsed either, since signature verification happens
        // via LoadImage or the shim protocol before we ever look at sections.
        parse_options.parse_attribute_certificates = false;
        let parsed = goblin::pe::PE::parse_with_opts(data, &parse_options)
            .map_err(|_| uefi::Status::INVALID_PARAMETER)?;

        Ok(Self {
            data,
            parsed,
            layout,
        })
    }

    /// Extracts the data of a section of a loaded PE file based on the section name.
    pub fn section_data(&self, section_name: &str) -> Option<Vec<u8>> {
        self.parsed
            .sections
            .iter()
            .find(|s| s.name().map(|n| n == section_name).unwrap_or(false))
            .and_then(|s| read_data_from_section_table(self.data, s, self.layout))
    }

    /// Iterator over all section names of the PE.
    pub fn sections(&self) -> impl IntoIterator<Item = &str> {
        self.parsed.sections.iter().filter_map(|s| s.name().ok())
    }
}

/// Extracts the data of a section in a PE binary based on the section table.
fn read_data_from_section_table(
    pe_data: &[u8],
    section: &SectionTable,
    layout: PeLayout,
) -> Option<Vec<u8>> {
    let section_start: usize = match layout {
        PeLayout::Loaded => section.virtual_address,
        PeLayout::Disk => section.pointer_to_raw_data,
    }
    .try_into()
    .ok()?;

    // virtual_size can be larger than size_of_raw_data when
    // zero-padding is required. virtual_size can also be smaller due
    // to alignment requirements in the file.
    let stored_len: usize =
        usize::try_from(min(section.virtual_size, section.size_of_raw_data)).ok()?;
    let section_data_end = section_start.checked_add(stored_len)?;

    let mut section_data = pe_data.get(section_start..section_data_end)?.to_owned();
    section_data.resize(section.virtual_size.try_into().ok()?, 0);

    Some(section_data)
}
