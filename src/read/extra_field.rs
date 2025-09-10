//! Extra fields parsing
//!
//! Reference: <https://libzip.org/specifications/extrafld.txt>

use std::fmt;

use crate::utils::Timestamp;

struct DataParser<'a>(&'a [u8]);

impl<'a> DataParser<'a> {
    fn read_u8(&mut self) -> Option<u8> {
        let (x, data) = self.0.split_first()?;
        self.0 = data;
        Some(*x)
    }

    fn read_u16(&mut self) -> Option<u16> {
        let (bytes, data) = self.0.split_first_chunk()?;
        self.0 = data;
        Some(u16::from_le_bytes(*bytes))
    }

    fn read_u32(&mut self) -> Option<u32> {
        let (bytes, data) = self.0.split_first_chunk()?;
        self.0 = data;
        Some(u32::from_le_bytes(*bytes))
    }

    fn read_u64(&mut self) -> Option<u64> {
        let (bytes, data) = self.0.split_first_chunk()?;
        self.0 = data;
        Some(u64::from_le_bytes(*bytes))
    }

    fn read_variable(&mut self, len: usize) -> Option<&'a [u8]> {
        let (bytes, data) = self.0.split_at_checked(len)?;
        self.0 = data;
        Some(bytes)
    }

    fn end(self) -> Option<()> {
        if self.0.is_empty() { Some(()) } else { None }
    }
}

#[derive(Clone)]
pub(crate) struct ExtraFields(pub Box<[u8]>);

impl ExtraFields {
    pub fn iter(&self) -> ExtraFieldIterator<'_> {
        ExtraFieldIterator(DataParser(&self.0))
    }
}

impl fmt::Debug for ExtraFields {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        struct FromFn<F: Fn(&mut fmt::Formatter<'_>) -> fmt::Result>(F);

        impl<F: Fn(&mut fmt::Formatter<'_>) -> fmt::Result> fmt::Debug for FromFn<F> {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                (self.0)(f)
            }
        }

        f.debug_list()
            .entries(self.iter().map(|e| FromFn(move |f| write!(f, "{e:?}"))))
            .finish()
    }
}

pub struct ExtraFieldIterator<'a>(DataParser<'a>);

impl<'a> Iterator for ExtraFieldIterator<'a> {
    type Item = ExtraField<'a>;

    fn next(&mut self) -> Option<Self::Item> {
        let id = self.0.read_u16()?;
        let len = self.0.read_u16()?;

        let data = self.0.read_variable(len as usize)?;

        Some(ExtraField::parse(id, data))
    }
}

#[derive(Debug, Clone)]
pub enum ExtraField<'a> {
    Zip64ExtendedInformation(Zip64ExtendedInformation),
    Ntfs(Ntfs),
    ExtendedTimestamp(ExtendedTimestamp),
    UnicodeComment(UnicodeComment<'a>),
    UnicodeName(UnicodeName<'a>),
    UnixNew(UnixNew<'a>),
    Aes(Aes),

    Invalid(u16, &'a [u8]),
    Unknown(u16, &'a [u8]),
}

impl<'a> ExtraField<'a> {
    fn parse(id: u16, data: &'a [u8]) -> Self {
        let field = (|| {
            let data = DataParser(data);

            Some(match id {
                0x0001 => {
                    ExtraField::Zip64ExtendedInformation(Zip64ExtendedInformation::parse(data)?)
                }
                0x000a => ExtraField::Ntfs(Ntfs::parse(data)?),
                0x5455 => ExtraField::ExtendedTimestamp(ExtendedTimestamp::parse(data)?),
                0x6375 => ExtraField::UnicodeComment(UnicodeComment::parse(data)?),
                0x7075 => ExtraField::UnicodeName(UnicodeName::parse(data)?),
                0x7875 => ExtraField::UnixNew(UnixNew::parse(data)?),
                0x9901 => ExtraField::Aes(Aes::parse(data)?),
                _ => ExtraField::Unknown(id, data.0),
            })
        })();

        field.unwrap_or(ExtraField::Invalid(id, data))
    }
}

#[derive(Debug, Clone)]
pub struct Zip64ExtendedInformation {
    pub original_size: u64,
    pub compressed_size: u64,
    pub local_header_offset: u64,
    pub disk_start_number: u32,
}

impl Zip64ExtendedInformation {
    fn parse(mut data: DataParser<'_>) -> Option<Self> {
        let original_size = data.read_u64()?;
        let compressed_size = data.read_u64()?;
        let local_header_offset = data.read_u64()?;
        let disk_start_number = data.read_u32()?;

        data.end()?;

        Some(Self {
            original_size,
            compressed_size,
            local_header_offset,
            disk_start_number,
        })
    }
}

#[derive(Debug, Clone)]
pub struct NtfsTimes {
    pub mtime: Timestamp,
    pub atime: Timestamp,
    pub ctime: Timestamp,
}

#[derive(Debug, Clone)]
pub struct Ntfs {
    pub times: Option<NtfsTimes>,
}

impl Ntfs {
    fn parse(mut data: DataParser<'_>) -> Option<Self> {
        let _reserved = data.read_u32()?;

        let mut times = None;

        while !data.0.is_empty() {
            let typ = data.read_u16()?;
            let len = data.read_u16()?;
            let mut data = DataParser(data.read_variable(len as _)?);

            match typ {
                0x0001 => {
                    times = Some(NtfsTimes {
                        mtime: Timestamp::from_ntfs(data.read_u64()?),
                        atime: Timestamp::from_ntfs(data.read_u64()?),
                        ctime: Timestamp::from_ntfs(data.read_u64()?),
                    });
                }
                _ => continue, // unsupported
            }
        }

        Some(Ntfs { times })
    }
}

#[derive(Debug, Clone)]
pub struct ExtendedTimestamp {
    pub modification_time: Option<Timestamp>,
    pub access_time: Option<Timestamp>,
    pub creation_time: Option<Timestamp>,
}

impl ExtendedTimestamp {
    fn parse(mut data: DataParser<'_>) -> Option<Self> {
        let flags = data.read_u8()?;

        // There are ZIP out there that don't respect the spec.
        // If there is only one time, and this doesn't match `flags`,
        // assume that this is modification time
        if data.0.len() == 4 && flags.count_ones() != 1 {
            return Some(ExtendedTimestamp {
                modification_time: Some(Timestamp::from_unix(data.read_u32()? as _)),
                access_time: None,
                creation_time: None,
            });
        }

        let modification_time = if flags & 1 != 0 {
            Some(Timestamp::from_unix(data.read_u32()? as _))
        } else {
            None
        };

        let access_time = if flags & 2 != 0 {
            Some(Timestamp::from_unix(data.read_u32()? as _))
        } else {
            None
        };

        let creation_time = if flags & 4 != 0 {
            Some(Timestamp::from_unix(data.read_u32()? as _))
        } else {
            None
        };

        data.end()?;

        Some(ExtendedTimestamp {
            modification_time,
            access_time,
            creation_time,
        })
    }
}

#[derive(Debug, Clone)]
pub struct UnicodeComment<'a> {
    pub version: u8,
    pub header_name_crc32: u32,
    pub comment: &'a str,
}

impl<'a> UnicodeComment<'a> {
    fn parse(mut data: DataParser<'a>) -> Option<Self> {
        let version = data.read_u8()?;
        if version != 1 {
            return None;
        }

        let header_name_crc32 = data.read_u32()?;

        let comment = std::str::from_utf8(data.0).ok()?;

        Some(UnicodeComment {
            version,
            header_name_crc32,
            comment,
        })
    }
}

#[derive(Debug, Clone)]
pub struct UnicodeName<'a> {
    pub version: u8,
    pub header_name_crc32: u32,
    pub name: &'a str,
}

impl<'a> UnicodeName<'a> {
    fn parse(mut data: DataParser<'a>) -> Option<Self> {
        let version = data.read_u8()?;
        if version != 1 {
            return None;
        }

        let header_name_crc32 = data.read_u32()?;

        let name = std::str::from_utf8(data.0).ok()?;

        Some(UnicodeName {
            version,
            header_name_crc32,
            name,
        })
    }
}

#[derive(Debug, Clone)]
pub struct UnixNew<'a> {
    pub version: u8,
    pub uid: &'a [u8],
    pub gid: &'a [u8],
}

impl<'a> UnixNew<'a> {
    fn parse(mut data: DataParser<'a>) -> Option<Self> {
        let version = data.read_u8()?;

        let uid_size = data.read_u8()?;
        let uid = data.read_variable(uid_size as _)?;

        let gid_size = data.read_u8()?;
        let gid = data.read_variable(gid_size as _)?;

        data.end()?;

        Some(UnixNew { version, uid, gid })
    }
}

#[derive(Debug, Clone, Copy)]
pub enum AesVersion {
    Ae1,
    Ae2,
}

#[derive(Debug, Clone, Copy)]
pub enum AesMode {
    Aes128,
    Aes192,
    Aes256,
}

#[derive(Debug, Clone)]
pub struct Aes {
    pub version: AesVersion,
    pub mode: AesMode,
    pub compression: crate::CompressionMethod,
}

impl Aes {
    /// Reference: https://www.winzip.com/en/support/aes-encryption/
    fn parse(mut data: DataParser<'_>) -> Option<Self> {
        let version = match data.read_u16()? {
            1 => AesVersion::Ae1,
            2 => AesVersion::Ae2,
            _ => return None,
        };

        let vendor_id = data.read_u16()?;
        if vendor_id != u16::from_ne_bytes(*b"AE") {
            return None;
        }

        let mode = match data.read_u8()? {
            1 => AesMode::Aes128,
            2 => AesMode::Aes192,
            3 => AesMode::Aes256,
            _ => return None,
        };

        let compression = crate::CompressionMethod(data.read_u16()?);

        data.end()?;

        Some(Aes {
            version,
            mode,
            compression,
        })
    }
}
