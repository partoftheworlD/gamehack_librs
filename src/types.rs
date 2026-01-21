use std::{
    os::raw::c_void,
    ptr::{from_mut, from_ref},
};

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
    pub id: u32,
    pub module_list: Vec<ModuleList>,
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
