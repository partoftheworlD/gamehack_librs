use windows::Win32::{
    Foundation::{HANDLE, HMODULE},
    System::{
        Diagnostics::Debug::ReadProcessMemory,
        Memory::{MEM_FREE, MEMORY_BASIC_INFORMATION, VirtualQueryEx},
        ProcessStatus::{EnumProcessModules, GetModuleBaseNameA, GetModuleInformation, MODULEINFO},
    },
};

use crate::{
    errors::Errors,
    types::{ModuleData, ProcessData},
};
use std::ptr::{addr_of_mut, null_mut};

use crate::types::TransformName;

pub fn find_signature<'a>(
    handle: HANDLE,
    base: usize,
    size: usize,
    sign: &'a [u8],
    mask: &'a str,
) -> Result<usize, Errors<'a>> {
    let mut mbi = MEMORY_BASIC_INFORMATION::default();
    let mut offset = 0;

    while offset < size {
        unsafe {
            let address = (base + offset) as *const _;
            VirtualQueryEx(
                handle,
                Some(address),
                addr_of_mut!(mbi),
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

                if let Some(offset) = buffer
                    .windows(sign.len())
                    .position(|buffer| data_compare(buffer, sign, mask))
                {
                    return Ok((mbi.BaseAddress as usize).wrapping_add(offset));
                }
            }
        }
        offset += mbi.RegionSize;
    }
    Err(Errors::SignatureNotFound)
}

#[must_use]
pub fn data_compare(data: &[u8], sign: &[u8], mask: &str) -> bool {
    if data.len() < mask.len() || sign.len() < mask.len() {
        return false;
    }
    mask.chars()
        .enumerate()
        .all(|(idx, c)| c != 'x' || data[idx] == sign[idx])
}

pub fn process_modules(process_data: &mut ProcessData<String>) {
    let mut mod_list = [HMODULE::default(); 1024];
    let mut cb_needed = 0;
    let handle = process_data.handle;

    unsafe {
        let _ = EnumProcessModules(
            handle,
            mod_list.as_mut_ptr().cast(),
            size_of_val(&mod_list) as u32,
            addr_of_mut!(cb_needed),
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
            let _ = GetModuleInformation(
                handle,
                mod_handle,
                addr_of_mut!(mi),
                size_of::<MODULEINFO>() as u32,
            );
        }

        let name = name
            .to_string_lowercase()
            .unwrap_or("<Module Name>".to_string());

        process_data.module_list.insert(
            name.clone(),
            ModuleData {
                module_name: name,
                module_addr: mi.lpBaseOfDll as usize,
                module_size: mi.SizeOfImage as usize,
            },
        );
    }
}
