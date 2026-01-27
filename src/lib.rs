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
use types::{ProcessData, TransformName};
use utils::process_modules;

/// Opens a local process and returns a handle with full access rights.
///
/// This function wraps the Win32 [`OpenProcess`] call. It is used to obtain a
/// handle that allows for extensive operations, including reading/writing memory
/// and querying process information.
///
/// # Arguments
///
/// * `pid` - The unique process identifier (PID) of the target process.
///
/// # Returns
///
/// * `Ok(HANDLE)` - A valid, open handle to the process if successful.
/// * `Err(Error)` - An error indicating failure, such as if the process does not exist
///   or the current user lacks sufficient privileges (e.g., `ERROR_ACCESS_DENIED`).
///
/// # Security Warning
///
/// This function requests **`PROCESS_ALL_ACCESS`**. In modern Windows environments (2026),
/// this may require the calling process to have `SeDebugPrivilege` enabled or to
/// be running with Administrative privileges. Excessive permissions may
/// also trigger Attack Surface Reduction (ASR) rules or EDR alerts.
///
/// # Safety
///
/// This function uses an `unsafe` block to call a foreign API. It is considered
/// a safe wrapper because:
/// 1. It validates the return value of `OpenProcess`.
/// 2. It converts the null-handle failure state into a standard Rust [`Result`].
///
/// **Note:** The caller is responsible for eventually closing the returned handle
/// using [`close_handle`] to prevent resource leaks.
pub fn get_process_handle(pid: u32) -> Result<HANDLE, Error> {
    unsafe { OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_ALL_ACCESS, false, pid) }
}

/// Closes an open object handle.
///
/// This is a safe wrapper around the Win32 [`CloseHandle`] function. It ensures
/// that system resources associated with the handle are released.
///
/// # Arguments
///
/// * `handle` - A valid [`HANDLE`] to an open object (e.g., process, thread, or file).
///
/// # Side Effects
///
/// Closing a handle invalidates the handle value, making it unusable for further calls.
/// Note that for some objects, like threads or processes, closing the handle does not
/// terminate the object; it only removes your access to it.
///
/// # Safety
///
/// While this function is marked as `pub`, it wraps an `unsafe` block. It assumes
/// that the provided `handle` is either a valid open handle or `NULL`.
/// Passing a pseudo-handle or an already closed handle may lead to undefined
/// behavior in some Windows environments, although `CloseHandle` usually
/// just returns an error.
pub fn close_handle(handle: HANDLE) {
    unsafe {
        // We ignore the return value (BOOL) as there is often little
        // recovery logic possible if a handle fails to close.
        let _ = CloseHandle(handle);
    }
}

/// Searches for a process by its name and retrieves its system data.
///
/// This function enumerates all active processes on the system, compares their
/// names (case-insensitive) with the provided `process_name`, and populates
/// a [`ProcessData`] struct for the first matching instance.
///
/// # Arguments
///
/// * `process_name` - A string slice containing the name of the executable
///   (e.g., "discord.exe").
///
/// # Returns
///
/// * `Ok(ProcessData<String>)` - Contains the handle, PID, and module list
///   of the found process.
/// * `Err(Errors::ProcessNotFound)` - Returned if no process matches the name
///   or if the matching process could not be opened.
///
/// # Technical Details
///
/// 1. **Enumeration**: Uses `EnumProcesses` with a static buffer limit of 1024 PIDs.
/// 2. **Filtering**: Automatically skips PIDs that cannot be opened with
///    `PROCESS_ALL_ACCESS` (via [`get_process_handle`]).
/// 3. **Comparison**: Performs a case-insensitive match against the base module name.
/// 4. **Deep Scan**: If a match is found, [`process_modules`] is called to
///    populate additional module information.
///
/// # Safety
///
/// While the function is safe to call, it internally handles raw pointers and
/// Win32 API calls. It relies on [`get_process_handle`] and ensures handles are
/// managed within the [`ProcessData`] context.
pub fn find_process(process_name: &str) -> Result<ProcessData<String>, Errors<'_>> {
    let mut pid_list = [0u32; 1024];
    let mut cb_needed = 0;
    let mut process_data = ProcessData::default();

    unsafe {
        let _ = EnumProcesses(
            pid_list.as_mut_ptr().cast(),
            u32::try_from(size_of_val(&pid_list))?,
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
            process_modules(&mut process_data);
        }
    }

    if process_data.id == 0 {
        Err(Errors::ProcessNotFound)
    } else {
        Ok(process_data)
    }
}

/// Performs a multi-level pointer traversal and reads the final value into a buffer.
///
/// This function follows a chain of pointers starting from a base `addr`,
/// applying a sequence of `offsets`, and finally writing the resulting address
/// (or value) into the provided `buffer`.
///
/// # Arguments
///
/// * `handle` - A valid [`HANDLE`] to the target process with `PROCESS_VM_READ` access.
/// * `addr` - The initial base address to start the pointer chain.
/// * `offsets` - A slice of [`u32`] offsets to be applied sequentially during traversal.
/// * `buffer` - A raw pointer to a location of type `T` where the final address will be written.
///
/// # Traversal Logic
///
/// 1. Reads a `usize` from `addr` into an internal temporary address.
/// 2. For each `offset` in `offsets`:
///    - Adds the offset to the temporary address (using wrapping addition).
///    - Reads the next `usize` from that location.
/// 3. Finally, writes the last resolved address into `buffer`.
///
/// # Safety
///
/// This function is **high-risk** and marked `pub` despite containing an `unsafe` block:
/// * **Pointer Dereferencing**: It assumes that every step in the chain results in a readable memory location. If any pointer in the chain is invalid, `ReadProcessMemory` will fail, and the function will continue with stale data.
/// * **Buffer Validity**: The caller must ensure that `buffer` points to valid, initialized memory capable of holding a value of type `T`.
/// * **Type Size**: Note that this function specifically reads `size_of::<usize>()` at each step, regardless of the size of `T`.
///
pub fn read<T: Copy + Sized>(handle: HANDLE, addr: usize, offsets: &[u32], buffer: *mut T) {
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

/// Writes a value of type `T` to a specific memory address in the target process.
///
/// This function is a high-level wrapper around the Win32 [`WriteProcessMemory`] API.
/// It uses generics to allow writing any type that implements [`Copy`].
///
/// # Arguments
///
/// * `handle` - A valid [`HANDLE`] to the target process with `PROCESS_VM_WRITE`
///   and `PROCESS_VM_OPERATION` access rights.
/// * `addr` - The base address in the specified process to which data is written.
/// * `value` - A reference to the value of type `T` to be written to the target process.
///
/// # Type Constraints
///
/// * `T: Copy` - Ensures that the type can be safely copied bitwise. This prevents
///   passing types with complex ownership (like `String` or `Vec`), which would
///   result in writing pointers that are invalid in the target process's address space.
///
/// # Safety and Side Effects
///
/// Although this function is not marked `unsafe`, it performs an operation that
/// can cause the target process to crash if the address or data is incorrect.
/// * **Memory Protection**: If the target memory page is read-only, the write
///   will fail silently (as the result is currently ignored).
/// * **Pointer Validity**: The caller must ensure that `addr` is valid within
///   the context of the target process, not the current one.
pub fn write<T: Copy + Sized>(handle: HANDLE, addr: usize, value: &T) {
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
