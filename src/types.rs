use std::ffi::CStr;

use windows::Win32::Foundation::HANDLE;

use crate::errors::Errors;
use std::collections::HashMap;

/// Represents metadata for a specific module (DLL or EXE) within a process.
///
/// This structure is marked with `#[repr(C)]` to ensure a stable and predictable 
/// memory layout
#[repr(C)]
#[derive(Debug, Clone, Default)]
pub struct ModuleData {
    pub module_name: String,
    pub module_addr: usize,
    pub module_size: usize,
}
/// A container for process-specific information and its associated system handle.
///
/// This structure centralizes the identification ([`u32`]), access ([`HANDLE`]), 
/// and memory map ([`HashMap`]) of a target process.
///
/// # Type Parameters
///
/// * `K` - The type of the key used in the `module_list`. A [`String`] 
///   representing the module name or a [`usize`] for its base address.
///
/// # Safety and Resource Management
///
/// - **Handle Ownership**: The `handle` field is a raw Win32 [`HANDLE`]. This struct 
///   does **not** automatically close the handle upon being dropped. The caller 
///   must ensure [`close_handle`](crate::close_handle) is called to prevent resource leaks.
/// - **Memory Layout**: Marked with `#[repr(C)]` for a fixed field order, aiding 
///   integration with external analysis tools.
#[repr(C)]
#[derive(Debug, Clone, Default)]
pub struct ProcessData<K> {
    pub handle: HANDLE,
    pub id: u32,
    pub module_list: HashMap<K, ModuleData>,
}
/// A trait for converting raw identifiers or buffers into normalized, lowercase strings.
///
/// This trait is primarily used to handle the conversion of null-terminated byte 
/// arrays (from Win32 API calls) into safe, manageable Rust [`String`] objects.
pub trait TransformName {
    /// Converts the underlying data into a lowercase [`String`].
    ///
    /// # Returns
    ///
    /// * `Ok(String)` - The successfully decoded and lowercased string.
    /// * `Err(Errors)` - An error if the data contains invalid UTF-8 sequences 
    ///   or lacks a proper null terminator (depending on the implementation).
    fn to_string_lowercase(&self) -> Result<String, Errors<'_>>;
}

/// Implementation of [`TransformName`] for byte slices.
///
/// This provides a safe way to convert raw null-terminated byte buffers 
/// (commonly returned by Windows APIs like `GetModuleBaseNameA`) into 
/// owned Rust strings.
impl TransformName for [u8] {
    /// Decodes a null-terminated byte slice and converts it to a lowercase [`String`].
    ///
    /// # Process
    /// 1. **Null-check**: Locates the first null terminator (`\0`) using [`CStr::from_bytes_until_nul`].
    /// 2. **UTF-8 Validation**: Ensures the content before the null byte is valid UTF-8.
    /// 3. **Normalization**: Converts the resulting string to lowercase for consistent comparisons.
    ///
    /// # Errors
    ///
    /// Returns [`Errors::NoNulByte`] if no null terminator is found in the slice, 
    /// or [`Errors::InvalidUtf8`] if the sequence is not valid UTF-8.
    fn to_string_lowercase(&self) -> Result<String, Errors<'_>> {
        Ok(CStr::from_bytes_until_nul(self)?
            .to_str()?
            .to_ascii_lowercase())
    }
}
