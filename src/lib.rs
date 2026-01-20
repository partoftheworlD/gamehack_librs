mod errors;
mod tests;
pub mod types;
pub mod utils;

use windows::{
    Wdk::System::{SystemInformation::SYSTEM_INFORMATION_CLASS, Threading::PROCESSINFOCLASS},
    Win32::{
        Foundation::{CloseHandle, HANDLE},
        System::{
            Diagnostics::Debug::{ReadProcessMemory, WriteProcessMemory},
            Threading::{
                OpenProcess, PEB, PROCESS_ALL_ACCESS, PROCESS_BASIC_INFORMATION,
                PROCESS_QUERY_INFORMATION,
            },
            WindowsProgramming::SYSTEM_PROCESS_INFORMATION,
        },
    },
    core::Error,
};

use errors::Errors;
use types::ProcessThings;
use utils::{get_system_information, read_pwstr};

use crate::{
    types::InfoClass,
    utils::{get_module_information, get_process_information},
};

pub fn get_process_handle(pid: u32) -> Result<HANDLE, Error> {
    unsafe { OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_ALL_ACCESS, false, pid) }
}

pub fn close_handle(handle: HANDLE) {
    unsafe {
        let _ = CloseHandle(handle);
    }
}

pub fn find_process(process_name: &str) -> Result<Vec<ProcessThings>, Errors<'_>> {
    const SYSPROCESSINFO: SYSTEM_INFORMATION_CLASS =
        SYSTEM_INFORMATION_CLASS(InfoClass::SysProcessList as i32);

    const BUFFER_SIZE: usize = 0x100000;

    if process_name.is_empty() {
        return Err(Errors::ProcessNotFound);
    }

    let mut process_list: Vec<ProcessThings> = Vec::new();
    let mut system_information = vec![0; BUFFER_SIZE];
    let mut count = 0u32;

    get_system_information(
        &SYSPROCESSINFO,
        &mut system_information,
        BUFFER_SIZE.try_into().unwrap(),
    );

    loop {
        let sysinfo: SYSTEM_PROCESS_INFORMATION = unsafe {
            *(system_information
                .as_ptr()
                .offset(count.try_into().unwrap())
                .cast())
        };
        if !sysinfo.ImageName.Buffer.is_null() {
            let name = match read_pwstr(&sysinfo) {
                Ok(process_name) => process_name,
                Err(why) => panic!("{why}"),
            };

            if name.to_ascii_lowercase() == process_name {
                if let Ok(handle) = get_process_handle(sysinfo.UniqueProcessId.0 as u32) {
                    let pbi = get_process_information(handle);
                    let mi = get_module_information(handle);

                    process_list.push(ProcessThings {
                        sysinfo,
                        procinfo: pbi,
                        name,
                        peb_ptr: pbi.PebBaseAddress,
                        id: sysinfo.UniqueProcessId.0 as u32,
                        base_addr: mi.lpBaseOfDll as usize,
                        base_size: mi.SizeOfImage as usize,
                    });
                }
            }
        }

        let next = sysinfo.NextEntryOffset;
        if next == 0 {
            break;
        }
        count += next;
    }

    if process_list.is_empty() {
        Err(Errors::ProcessNotFound)
    } else {
        Ok(process_list)
    }
}

pub fn read<T: Copy>(handle: HANDLE, addr: usize, buffer: *mut T) {
    let none: Option<*mut usize> = None;
    let size = size_of::<T>();

    unsafe {
        let _ = ReadProcessMemory(handle, addr as *const _, buffer.cast(), size, none);
    }
}

pub fn write<T: Copy>(handle: HANDLE, addr: usize, value: T) {
    let none: Option<*mut usize> = None;
    let size = size_of::<T>();

    unsafe {
        let _ = WriteProcessMemory(
            handle,
            addr as *const _,
            (&raw const value).cast(),
            size,
            none,
        );
    }
}
