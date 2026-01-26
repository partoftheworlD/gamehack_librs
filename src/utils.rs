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

/// Searches for a byte pattern (signature) within a specific memory range of a process.
///
/// This function iterates through memory regions of a target process using [`VirtualQueryEx`],
/// reads non-free memory segments, and attempts to find a match for a provided byte 
/// signature and mask.
///
/// # Arguments
///
/// * `handle` - A valid [`HANDLE`] to the target process with `PROCESS_VM_READ` and `PROCESS_QUERY_INFORMATION` access.
/// * `base` - The starting memory address for the scan.
/// * `size` - The total size of the memory range to scan.
/// * `sign` - A byte slice (`&[u8]`) representing the pattern to search for.
/// * `mask` - A string slice where `'?'` represents a wildcard (skip) and `'x'` represents an exact match for the corresponding byte in `sign`.
///
/// # Returns
///
/// * `Ok(usize)` - The absolute memory address where the signature starts.
/// * `Err(Errors::SignatureNotFound)` - If the pattern was not found within the specified range.
///
/// # Technical Details
///
/// 1. **Region Traversal**: Uses [`VirtualQueryEx`] to identify allocated memory pages, skipping `MEM_FREE` regions to improve performance and avoid errors.
/// 2. **Scanning**: For each valid region, it copies the entire memory block into a local buffer before performing the pattern match.
/// 3. **Comparison**: Uses `data_compare` (internally) to evaluate the signature against the buffer using the provided mask.
///
/// # Performance Warning
/// 
/// This function allocates a `Vec<u8>` the size of each memory region (often 4KB or more) per iteration. For very large search ranges, this may cause significant temporary memory pressure
/// 
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

/// Compares a block of memory against a byte pattern using a mask.
///
/// This is a utility function used for "Array of Bytes" (AOB) scanning.
/// It checks if the `data` matches the `sign` pattern, skipping bytes where
/// the `mask` contains wildcards.
///
/// # Arguments
///
/// * `data` - The actual memory bytes to check.
/// * `sign` - The pattern bytes to match against.
/// * `mask` - A string where `'x'` denotes an exact match and any other character 
///   (usually `'?'`) denotes a wildcard.
///
/// # Returns
///
/// Returns `true` if the `data` matches the `sign` under the given `mask`.
/// Returns `false` if the inputs are inconsistent or the pattern doesn't match.
#[must_use]
pub fn data_compare(data: &[u8], sign: &[u8], mask: &str) -> bool {
    if data.len() < mask.len() || sign.len() < mask.len() {
        return false;
    }
    mask.chars()
        .enumerate()
        .all(|(idx, c)| c != 'x' || data[idx] == sign[idx])
}

/// Populates the provided [`ProcessData`] with a list of all loaded modules.
///
/// This function enumerates all modules (DLLs and the main executable) within 
/// the context of the process identified by the handle in `process_data`. It 
/// gathers the name, base address, and image size for each module.
///
/// # Arguments
///
/// * `process_data` - A mutable reference to a [`ProcessData`] struct. The 
///   `handle` field must be a valid process handle with `PROCESS_QUERY_INFORMATION` 
///   and `PROCESS_VM_READ` access.
///
/// # Behavior
///
/// 1. **Enumeration**: Calls `EnumProcessModules` to retrieve up to 1024 module handles.
/// 2. **Metadata Collection**: For each module, it queries the base name via 
///    `GetModuleBaseNameA` and memory information via `GetModuleInformation`.
/// 3. **State Mutation**: Updates the `module_list` hash map within the `process_data` 
///    struct. Module names are normalized to lowercase.
///
/// # Safety
///
/// This function internally uses `unsafe` blocks to interface with the Windows API. 
/// It assumes the `process_data.handle` is valid and has not been closed.
///
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
