use windows::Win32::{
    Foundation::{HANDLE, HMODULE},
    System::{
        Diagnostics::Debug::ReadProcessMemory,
        Memory::{MEM_FREE, MEMORY_BASIC_INFORMATION, VirtualQueryEx},
        ProcessStatus::{EnumProcessModules, GetModuleBaseNameA, GetModuleInformation, MODULEINFO},
    },
};

use crate::types::{CastPointers, ModuleList, ProcessData};
use std::{ffi::CStr, ptr::null_mut};

#[must_use]
pub fn transform_name(bytes: &[u8]) -> String {
    CStr::from_bytes_until_nul(bytes)
        .unwrap_or_default()
        .to_str()
        .unwrap_or_default()
        .to_ascii_lowercase()
}

#[must_use]
pub fn find_signature(handle: HANDLE, base: usize, size: usize, sign: &[u8], mask: &str) -> usize {
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

#[must_use]
pub fn data_compare(data: &[u8], sign: &[u8], mask: &str) -> bool {
    if data.len() < mask.len() || sign.len() < mask.len() {
        return false;
    }
    mask.chars()
        .enumerate()
        .all(|(i, m)| m != 'x' || data[i] == sign[i])
}

pub fn process_modules(handle: HANDLE, process_data: &mut ProcessData) {
    let mut mod_list = [HMODULE::default(); 1024];
    let mut cb_needed = 0;

    unsafe {
        let _ = EnumProcessModules(
            handle,
            mod_list.as_mut_ptr().cast(),
            size_of_val(&mod_list) as u32,
            &raw mut cb_needed,
        );
    }

    for &mod_handle in mod_list
        .iter()
        .take(cb_needed as usize / size_of::<HMODULE>())
    {
        let mut name = [0u8; 256];
        let mut mi = MODULEINFO::default();

        unsafe {
            let _ = GetModuleBaseNameA(handle, Some(mod_handle), &mut name);
        }

        unsafe {
            let _ = GetModuleInformation(
                handle,
                mod_handle,
                &raw mut mi,
                size_of::<MODULEINFO>() as u32,
            );
        }

        process_data.module_list.push(ModuleList {
            module_name: transform_name(&name),
            module_addr: mi.lpBaseOfDll as usize,
            module_size: mi.SizeOfImage as usize,
        });
    }
}
