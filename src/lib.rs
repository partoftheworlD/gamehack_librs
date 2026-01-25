mod errors;
mod tests;
pub mod types;
pub mod utils;

use std::ptr::{self, addr_of, addr_of_mut};

use windows::{
    Win32::{
        Foundation::{CloseHandle, HANDLE, HMODULE},
        System::{
            Diagnostics::Debug::{ReadProcessMemory, WriteProcessMemory},
            ProcessStatus::{EnumProcesses, GetModuleBaseNameA},
            Threading::{OpenProcess, PROCESS_ALL_ACCESS, PROCESS_QUERY_INFORMATION},
        },
    },
    core::Error,
};

use errors::Errors;
use types::ProcessData;

use crate::utils::{TransformName, process_modules};

pub fn get_process_handle(pid: u32) -> Result<HANDLE, Error> {
    unsafe { OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_ALL_ACCESS, false, pid) }
}

pub fn close_handle(handle: HANDLE) {
    unsafe {
        let _ = CloseHandle(handle);
    }
}

pub fn find_process(process_name: &str) -> Result<ProcessData, Errors<'_>> {
    let mut pid_list = [0u32; 1024];
    let mut cb_needed = 0;
    let mut process_data = ProcessData::default();

    unsafe {
        let _ = EnumProcesses(
            pid_list.as_mut_ptr().cast(),
            size_of_val(&pid_list) as u32,
            addr_of_mut!(cb_needed),
        );
    }

    let limit = cb_needed as usize / size_of::<u32>();

    for (pid, handle) in pid_list
        .iter()
        .take(limit)
        .filter(|&&pid| pid != 0)
        .filter_map(|&pid| get_process_handle(pid).ok().map(|h| (pid, h)))
    {
        let hmod = HMODULE::default();
        let mut module_name = [0u8; 256];

        unsafe {
            let _ = GetModuleBaseNameA(handle, Some(hmod), &mut module_name);
        }

        if module_name
            .to_string_lowercase()
            .unwrap_or("<Module Name>".to_string())
            == process_name.to_ascii_lowercase()
        {
            process_data.handle = handle;
            process_data.id = pid;
            process_modules(handle, &mut process_data);
        }
    }

    if process_data.id == 0 {
        Err(Errors::ProcessNotFound)
    } else {
        Ok(process_data)
    }
}

pub fn read<T: Copy>(handle: HANDLE, addr: usize, offsets: &[u32], buffer: *mut T) {
    let size = size_of::<usize>();
    let mut next_addr = 0usize;

    unsafe {
        let _ = ReadProcessMemory(
            handle,
            addr as *const _,
            addr_of_mut!(next_addr).cast(),
            size,
            None,
        );

        for &offset in offsets {
            let _ = ReadProcessMemory(
                handle,
                (next_addr.wrapping_add(offset as usize)) as *const _,
                addr_of_mut!(next_addr).cast(),
                size,
                None,
            );
        }
        ptr::write(buffer.cast(), next_addr);
    }
}

pub fn write<T: Copy>(handle: HANDLE, addr: usize, value: &T) {
    unsafe {
        let _ = WriteProcessMemory(
            handle,
            addr as *const _,
            addr_of!(value).cast(),
            size_of::<T>(),
            None,
        );
    }
}
