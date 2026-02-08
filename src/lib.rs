mod errors;
mod tests;
pub mod types;
pub mod utils;

use std::ptr::{self, addr_of, addr_of_mut};

use windows::Win32::{
    Foundation::{CloseHandle, HANDLE, HMODULE},
    System::{
        Diagnostics::Debug::{ReadProcessMemory, WriteProcessMemory},
        ProcessStatus::{EnumProcesses, GetModuleBaseNameA},
        Threading::{OpenProcess, PROCESS_ALL_ACCESS, PROCESS_QUERY_INFORMATION},
    },
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
/// * `Ok(HANDLE)` - A valid handle to the specified process on success.
///
/// # Errors
/// * `Err(Errors::AccessDenied(HRESULT))` - An error containing the Windows System Error Code
///   (e.g., `5` for `ERROR_ACCESS_DENIED`) if the process cannot be opened.
///
///
/// # Security Considerations
///
/// Requesting **`PROCESS_ALL_ACCESS`** is a highly privileged operation.
/// In modern Windows environments, this call is likely to fail unless:
/// * The current process is running with **Administrative privileges**.
/// * The `SeDebugPrivilege` is explicitly enabled in the process token.
/// * The target process is not protected (e.g., by Anti-Cheat or EDR solutions).
///
/// # Safety
///
/// While this function uses `unsafe` internally to invoke the FFI call, it is
/// exposed as a safe interface because it:
/// 1. Correctly handles null/invalid handles returned by the OS.
/// 2. Transforms Win32 error states into a type-safe Rust [`Result`].
///
/// **Note:** The caller is responsible for eventually closing the returned handle
/// using [`close_handle`] to prevent resource leaks.
pub fn get_process_handle(pid: u32) -> Result<HANDLE, Errors<'static>> {
    unsafe {
        match OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_ALL_ACCESS, false, pid) {
            Ok(handle) => Ok(handle),
            Err(err) => Err(Errors::AccessDenied(err.code())),
        }
    }
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
///
/// # Errors
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
    if process_name.is_empty() {
        return Err(Errors::ProcessNotFound);
    }
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

    if process_data.is_empty() {
        Err(Errors::ProcessNotFound)
    } else {
        Ok(process_data)
    }
}

/// Performs a multi-level pointer traversal and reads the final value into a provided buffer.
///
/// This function follows a chain of pointers starting from the base `addr`,
/// sequentially applying a series of `offsets`. The value found at the final
/// resolved address is copied into the `buffer`.
///
/// # Arguments
///
/// * `handle` - A valid [`HANDLE`] to the target process with `PROCESS_VM_READ` access.
/// * `addr` - The initial base address to start the pointer chain.
/// * `offsets` - A slice of [`u32`] offsets applied sequentially during traversal.
/// * `buffer` - A mutable reference to a value of type `T` where the final result will be stored.
///
/// # Traversal Logic
///
/// 1. **Initial Seed**: Reads a `usize` value from the base `addr` to establish the starting pointer.
/// 2. **Offset Chain**: For each `offset` in `offsets`:
///    - Calculates the next target address using `wrapping_add` of the `offset`.
///    - Reads a chunk of memory of size **`size_of::<T>()`** from that address to update the internal pointer.
/// 3. **Finalization**: Copies the last resolved value into the `buffer` using non-overlapping memory copy.
///
/// # Safety
///
/// This function is **high-risk** as it performs raw memory manipulation:
/// * **Pointer Validity**: The caller must ensure that every step in the offset chain results in a readable memory location within the target process.
///
pub fn read<T: Copy>(handle: HANDLE, addr: usize, offsets: &[u32], buffer: &mut T) {
    unsafe {
        let mut next_addr = 0usize;

        let _ = ReadProcessMemory(
            handle,
            addr as *const _,
            addr_of_mut!(next_addr).cast(),
            size_of::<usize>(),
            None,
        );

        for &offset in offsets {
            let _ = ReadProcessMemory(
                handle,
                (next_addr.wrapping_add(offset as usize)) as *const _,
                addr_of_mut!(next_addr).cast(),
                size_of::<T>(),
                None,
            );
        }

        ptr::copy_nonoverlapping(
            (addr_of!(next_addr)).cast::<u8>(),
            ptr::from_mut(buffer).cast(),
            size_of::<T>(),
        );
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
