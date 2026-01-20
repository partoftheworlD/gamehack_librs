use windows::{
    Wdk::System::{
        SystemInformation::{NtQuerySystemInformation, SYSTEM_INFORMATION_CLASS},
        Threading::{NtQueryInformationProcess, ProcessBasicInformation},
    },
    Win32::{
        Foundation::{HANDLE, HMODULE},
        System::{
            Diagnostics::Debug::ReadProcessMemory,
            Memory::{MEM_FREE, MEMORY_BASIC_INFORMATION, VirtualQueryEx},
            ProcessStatus::{EnumProcessModules, GetModuleInformation, MODULEINFO},
            Threading::PROCESS_BASIC_INFORMATION,
            WindowsProgramming::SYSTEM_PROCESS_INFORMATION,
        },
    },
};

use crate::errors::Errors;
use std::ptr::null_mut;

pub fn get_module_information(handle: HANDLE) -> MODULEINFO {
    let mut module_info = MODULEINFO::default();
    let mut module = HMODULE::default();
    unsafe {
        let _ = EnumProcessModules(handle, &mut module, size_of::<HMODULE>() as u32, null_mut());

        let _ = GetModuleInformation(
            handle,
            module,
            &mut module_info,
            size_of::<MODULEINFO>() as u32,
        );
    }
    module_info
}

pub fn get_process_information(handle: HANDLE) -> PROCESS_BASIC_INFORMATION {
    let mut pbi = PROCESS_BASIC_INFORMATION::default();
    let _ntstatus = unsafe {
        NtQueryInformationProcess(
            handle,
            ProcessBasicInformation,
            &raw mut pbi as _,
            size_of::<PROCESS_BASIC_INFORMATION>() as u32,
            null_mut(),
        )
    };
    pbi
}

pub fn get_system_information(
    infoclass: &SYSTEM_INFORMATION_CLASS,
    buffer: &mut Vec<u8>,
    buffer_size: u32,
) {
    let _ntstatus = unsafe {
        NtQuerySystemInformation(
            *infoclass,
            buffer.as_mut_ptr().cast(),
            buffer_size,
            null_mut(),
        )
    };
}

pub fn read_pwstr(process: &SYSTEM_PROCESS_INFORMATION) -> Result<String, Errors<'_>> {
    if process.ImageName.Buffer.is_null() {
        return Err(Errors::EmptyBuffer("process.ImageName.Buffer is empty"));
    }
    Ok(String::from_utf16_lossy(unsafe {
        process.ImageName.Buffer.as_wide()
    }))
}

pub fn find_signature(
    handle: HANDLE,
    base: usize,
    size: usize,
    sign: &[u8],
    mask: &str,
) -> usize {
    let mut mbi = MEMORY_BASIC_INFORMATION::default();
    let mut offset = 0;

    while offset < size {
        unsafe {
            let address = (base + offset) as *const _;
            VirtualQueryEx(
                handle,
                Some(address),
                &raw mut mbi,
                size_of::<MEMORY_BASIC_INFORMATION>(),
            );

            if mbi.State != MEM_FREE {
                let region_size = mbi.RegionSize;
                let mut buffer = vec![0u8; region_size];

                let _ = ReadProcessMemory(
                    handle,
                    address,
                    buffer.as_mut_ptr().cast(),
                    region_size,
                    Some(null_mut()),
                );

                for i in 0..region_size {
                    if data_compare(&buffer[i..], sign, mask) {
                        return (mbi.BaseAddress as usize).wrapping_add(i);
                    }
                }
            }
        }
        offset += mbi.RegionSize;
    }
    0
}

pub fn data_compare(data: &[u8], sign: &[u8], mask: &str) -> bool {
    if data.len() < mask.len() || sign.len() < mask.len() {
        return false;
    }
    mask.chars()
        .enumerate()
        .all(|(i, m)| m != 'x' || data[i] == sign[i])
}
