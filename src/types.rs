use windows::Win32::Foundation::HANDLE;

#[repr(C)]
#[derive(Debug, Clone, Default)]
pub struct ModuleList {
    pub module_name: String,
    pub module_addr: usize,
    pub module_size: usize,
}

#[repr(C)]
#[derive(Debug, Clone, Default)]
pub struct ProcessData {
    pub handle: HANDLE,
    pub id: u32,
    pub module_list: Vec<ModuleList>,
}
