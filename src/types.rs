use std::{
    os::raw::c_void,
    ptr::{from_mut, from_ref},
};

use windows::Win32::System::{
    Threading::{PEB, PROCESS_BASIC_INFORMATION},
    WindowsProgramming::SYSTEM_PROCESS_INFORMATION,
};

#[repr(C)]
//SYSTEM_INFORMATION_CLASS enum
pub enum InfoClass {
    ProcessBasicInformation,
    SysProcessList = 5,
}

#[repr(C)]
pub enum Arch {
    X86,
    X64,
}

#[repr(C)]
#[derive(Debug, Clone)]
pub struct ProcessThings {
    pub sysinfo: SYSTEM_PROCESS_INFORMATION,
    pub procinfo: PROCESS_BASIC_INFORMATION,
    pub name: String,
    pub id: u32,
    pub peb_ptr: *mut PEB,
    pub base_addr: usize,
    pub base_size: usize,
}

pub trait CastPointers<U> {
    #[inline]
    #[allow(dead_code)]
    fn as_ptr(&self) -> *const U {
        from_ref(self).cast()
    }

    #[inline]
    fn as_mut_ptr(&mut self) -> *mut U {
        from_mut(self).cast()
    }
}

impl<T> CastPointers<c_void> for T {}

impl CastPointers<usize> for usize {
    #[inline]
    fn as_ptr(&self) -> *const usize {
        *self as *const _
    }

    #[inline]
    fn as_mut_ptr(&mut self) -> *mut usize {
        *self as *mut _
    }
}
