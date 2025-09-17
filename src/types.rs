#![allow(dead_code)]

use std::fmt;

pub unsafe trait Pod: Copy + 'static {
    fn zeroed() -> Self {
        unsafe { std::mem::zeroed() }
    }

    fn as_bytes(&self) -> &[u8] {
        unsafe { std::slice::from_raw_parts(self as *const _ as *const u8, size_of::<Self>()) }
    }

    fn as_bytes_mut(&mut self) -> &mut [u8] {
        unsafe { std::slice::from_raw_parts_mut(self as *mut _ as *mut u8, size_of::<Self>()) }
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
#[repr(transparent)]
pub struct U16(u16);

unsafe impl Pod for U16 {}

impl U16 {
    pub const fn get(self) -> u16 {
        u16::from_le(self.0)
    }

    pub const fn set(x: u16) -> Self {
        Self(x.to_le())
    }
}

impl fmt::Debug for U16 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.get().fmt(f)
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
#[repr(transparent)]
pub struct U32(u32);

unsafe impl Pod for U32 {}

impl U32 {
    pub const fn get(self) -> u32 {
        u32::from_le(self.0)
    }

    pub const fn set(x: u32) -> Self {
        Self(x.to_le())
    }
}

impl fmt::Debug for U32 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.get().fmt(f)
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
#[repr(transparent)]
pub struct U64(u64);

unsafe impl Pod for U64 {}

impl U64 {
    pub const fn get(self) -> u64 {
        u64::from_le(self.0)
    }

    pub const fn set(x: u64) -> Self {
        Self(x.to_le())
    }
}

impl fmt::Debug for U64 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.get().fmt(f)
    }
}

#[derive(Debug, Clone, Copy)]
#[repr(C, packed(2))]
pub struct LocalFileHeader {
    pub signature: U32,
    pub required_version: U16,
    pub flags: U16,
    pub compression_method: U16,
    pub last_modified_time: U16,
    pub last_modified_date: U16,
    pub crc32: U32,
    pub compressed_size: U32,
    pub uncompressed_size: U32,
    pub file_name_length: U16,
    pub extra_fields_length: U16,
}

unsafe impl Pod for LocalFileHeader {}

impl LocalFileHeader {
    pub const SIGNATURE: U32 = U32::set(0x04034b50);
}

#[derive(Debug, Clone, Copy)]
#[repr(C, packed(4))]
pub struct DataDescriptor32 {
    pub crc32: U32,
    pub compressed_size: U32,
    pub uncompressed_size: U32,
}

unsafe impl Pod for DataDescriptor32 {}

#[derive(Debug, Clone, Copy)]
#[repr(C, packed(4))]
pub struct DataDescriptor64 {
    pub crc32: U32,
    pub compressed_size: U64,
    pub uncompressed_size: U64,
}

unsafe impl Pod for DataDescriptor64 {}

#[derive(Debug, Clone, Copy)]
#[repr(C, packed(2))]
pub struct CentralFileHeader {
    pub signature: U32,
    pub made_by: U16,
    pub version_needed: U16,
    pub flags: U16,
    pub compression_method: U16,
    pub last_modified_time: U16,
    pub last_modified_date: U16,
    pub crc32: U32,
    pub compressed_size: U32,
    pub uncompressed_size: U32,
    pub file_name_length: U16,
    pub extra_fields_length: U16,
    pub file_comment_length: U16,
    pub disk_number: U16,
    pub internal_attributes: U16,
    pub external_attributes: U32,
    pub local_header_offset: U32,
}

impl CentralFileHeader {
    pub const SIGNATURE: U32 = U32::set(0x02014b50);
}

unsafe impl Pod for CentralFileHeader {}

#[derive(Debug, Clone, Copy)]
#[repr(C, packed(2))]
pub struct EndOfCentralDirectory64 {
    signature: U32,
    zip64_end_of_central_directory_record_size: U64,
    made_by: U16,
    version_needed: U16,
    disk_number: U32,
    disk_with_central_directory: U32,
    entries_on_this_disk: U64,
    total_entries: U64,
    central_directory_size: U64,
    central_directory_offset: U64,
}

impl EndOfCentralDirectory64 {
    pub const SIGNATURE: U32 = U32::set(0x06064b50);
}

unsafe impl Pod for EndOfCentralDirectory64 {}

#[derive(Debug, Clone, Copy)]
#[repr(C, packed(4))]
pub struct EndOfCentralDirectory64Locator {
    signature: U32,
    disk_with_central_directory: U32,
    central_directory_64_offset: U64,
    total_disks: U32,
}

impl EndOfCentralDirectory64Locator {
    pub const SIGNATURE: U32 = U32::set(0x07064b50);
}

unsafe impl Pod for EndOfCentralDirectory64Locator {}

#[derive(Debug, Clone, Copy)]
#[repr(C, packed(2))]
pub struct EndOfCentralDirectory {
    pub signature: U32,
    pub disk_number: U16,
    pub disk_with_central_directory: U16,
    pub entries_on_this_disk: U16,
    pub total_entries: U16,
    pub central_directory_size: U32,
    pub central_directory_offset: U32,
    pub comment_length: U16,
}

impl EndOfCentralDirectory {
    pub const SIGNATURE: U32 = U32::set(0x06054b50);
}

unsafe impl Pod for EndOfCentralDirectory {}
