use std::ffi::CStr;

use windows::Win32::Foundation::HANDLE;

use crate::errors::Errors;
use std::collections::HashMap;

#[repr(C)]
#[derive(Debug, Clone, Default)]
pub struct ModuleData {
    pub module_name: String,
    pub module_addr: usize,
    pub module_size: usize,
}

#[repr(C)]
#[derive(Debug, Clone, Default)]
pub struct ProcessData<K> {
    pub handle: HANDLE,
    pub id: u32,
    pub module_list: HashMap<K, ModuleData>,
}
pub trait TransformName {
    fn to_string_lowercase(&self) -> Result<String, Errors<'_>>;
}

impl TransformName for [u8] {
    fn to_string_lowercase(&self) -> Result<String, Errors<'_>> {
        Ok(CStr::from_bytes_until_nul(self)?
            .to_str()?
            .to_ascii_lowercase())
    }
}
