use crate::{
    CompressionMethod, FileType, Timestamp,
    types::{self, Pod},
    utils,
};
use std::{
    fmt,
    io::{self, Write},
};

trait WriteExt: Write {
    fn write_pod<T: Pod>(&mut self, data: &T) -> io::Result<()> {
        self.write_all(data.as_bytes())
    }

    #[inline]
    fn write_all_many<const N: usize>(&mut self, data: [&[u8]; N]) -> io::Result<()> {
        self._write_all_many(&mut data.map(io::IoSlice::new))
    }

    fn _write_all_many(&mut self, mut bufs: &mut [io::IoSlice]) -> io::Result<()> {
        #[cold]
        fn write_zero() -> io::Error {
            io::Error::new(io::ErrorKind::WriteZero, "failed to write whole buffer")
        }

        io::IoSlice::advance_slices(&mut bufs, 0);
        while !bufs.is_empty() {
            match self.write_vectored(bufs) {
                Ok(0) => return Err(write_zero()),
                Ok(n) => io::IoSlice::advance_slices(&mut bufs, n),
                Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
                Err(e) => return Err(e),
            }
        }

        Ok(())
    }
}

impl<W: Write> WriteExt for W {}

#[allow(dead_code)]
#[derive(Debug, Clone, Copy)]
#[repr(C, packed(4))]
struct LocalZip64 {
    id: types::U16,
    size: types::U16,
    uncompressed_size: types::U64,
    compressed_size: types::U64,
}

unsafe impl Pod for LocalZip64 {}

#[allow(dead_code)]
#[derive(Debug, Clone, Copy)]
#[repr(C, packed(4))]
struct CentralZip64 {
    id: types::U16,
    size: types::U16,
    uncompressed_size: types::U64,
    compressed_size: types::U64,
    local_header_offset: types::U64,
}

unsafe impl Pod for CentralZip64 {}

#[allow(dead_code)]
#[derive(Debug, Clone, Copy)]
#[repr(C, packed)]
struct ExtendedTimestamp {
    id: types::U16,
    size: types::U16,
    flags: u8,
    timestamp: types::U32,
}

unsafe impl Pod for ExtendedTimestamp {}

impl ExtendedTimestamp {
    fn new(modified: Timestamp) -> Option<Self> {
        match modified.to_unix().try_into() {
            Ok(t) if t != 0 => Some(ExtendedTimestamp {
                id: types::U16::set(0x5455),
                size: types::U16::set(5),
                flags: 1,
                timestamp: types::U32::set(t),
            }),
            _ => None,
        }
    }
}

pub struct Metadata {
    pub compression_method: CompressionMethod,
    pub compressed_size: u64,
    pub uncompressed_size: u64,
    pub crc32: u32,
    pub typ: FileType,
    pub modified_at: Timestamp,
}

#[derive(Debug, Default)]
enum State {
    #[default]
    Default,
    Writing(u64),
}

#[inline]
fn get_name<'a>(central_headers: &'a [u8]) -> impl Fn(&(usize, usize)) -> &'a [u8] {
    |&(start, end)| &central_headers[start..end]
}

#[derive(Default)]
pub struct RawArchiveWriter {
    state: State,
    entries: utils::NameTable<(usize, usize)>,
    central_headers: Vec<u8>,
    position: u64,
}

impl fmt::Debug for RawArchiveWriter {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RawArchiveWriter")
            .field("state", &self.state)
            .field("position", &self.position)
            .finish()
    }
}

impl RawArchiveWriter {
    #[inline]
    fn start_writing(&mut self) -> io::Result<()> {
        #[cold]
        fn error() -> io::Error {
            io::Error::other("A non-recoverable error occurred or a file was not `finish`ed")
        }

        if let State::Writing(_) = self.state {
            return Err(error());
        }
        self.state = State::Writing(self.position);

        Ok(())
    }

    pub fn recover<W: io::Seek>(&mut self, mut writer: W) -> io::Result<()> {
        let State::Writing(pos) = self.state else {
            return Ok(());
        };

        writer.seek(io::SeekFrom::Start(pos))?;
        self.state = State::Default;
        self.position = pos;

        Ok(())
    }

    fn check_name(&self, name: &str, typ: FileType) -> io::Result<Box<str>> {
        #[cold]
        fn invalid_name(msg: &str) -> io::Error {
            io::Error::new(io::ErrorKind::InvalidInput, msg)
        }

        if u16::try_from(name.len()).is_err() {
            return Err(invalid_name("file name too long"));
        }
        match (name.ends_with('/'), typ.is_directory()) {
            (false, true) => return Err(invalid_name("directory name must end with '/'")),
            (true, false) => return Err(invalid_name("file name must not end with '/'")),
            _ => (),
        }

        let name = utils::validate_name(name).ok_or_else(|| invalid_name("invalid file name"))?;
        let stripped_name = name.strip_suffix('/').unwrap_or(&name);

        let duplicated = self
            .entries
            .get(stripped_name.as_bytes(), get_name(&self.central_headers))
            .is_some();
        if duplicated {
            return Err(invalid_name("duplicated file name"));
        }

        Ok(name)
    }

    pub fn write_file_raw<W: Write>(
        &mut self,
        writer: &mut W,
        name: &str,
        content: &[u8],
        meta: &Metadata,
        comment: &str,
    ) -> io::Result<()> {
        let name = self.check_name(name, meta.typ)?;

        self.start_writing()?;
        let mut counter = utils::Counter::new(writer);

        self.write_local_header(&mut counter, &name, meta, false)?;
        counter.write_all(content)?;
        self.push_central_header(name, meta, comment, false, self.position)?;

        self.position += counter.amt;
        self.state = State::Default;

        Ok(())
    }

    pub fn start_stream_raw<W: Write>(
        &mut self,
        writer: W,
        name: &str,
        options: &super::FileOptions,
    ) -> io::Result<RawFileStreamer<'_, W>> {
        let file_name = self.check_name(name, FileType::File)?;

        self.start_writing()?;
        let local_header_offset = self.position;
        let mut writer = utils::Counter::new(writer);

        self.write_local_header(
            &mut writer,
            &file_name,
            &Metadata {
                compression_method: options.compression_method,
                compressed_size: 0,
                uncompressed_size: 0,
                crc32: 0,
                typ: FileType::File,
                modified_at: options.modified_at,
            },
            true,
        )?;

        Ok(RawFileStreamer {
            started_at: writer.amt,
            writer,

            file_name,
            local_header_offset,
            compression_method: options.compression_method,
            modified_at: options.modified_at,

            raw: self,
        })
    }

    fn write_local_header<W: Write>(
        &mut self,
        writer: &mut W,
        name: &str,
        meta: &Metadata,
        is_streaming: bool,
    ) -> io::Result<()> {
        let zip64 = LocalZip64 {
            id: types::U16::set(0x0001),
            size: types::U16::set(16),
            compressed_size: types::U64::set(meta.compressed_size),
            uncompressed_size: types::U64::set(meta.uncompressed_size),
        };

        let time = ExtendedTimestamp::new(meta.modified_at);
        let time = time.as_slice().as_bytes();

        let stream_flag = if is_streaming { 1 << 3 } else { 0 };

        writer.write_all_many([
            types::LocalFileHeader {
                signature: types::LocalFileHeader::SIGNATURE,
                required_version: types::U16::set(45),
                flags: types::U16::set((1 << 11) | stream_flag),
                compression_method: types::U16::set(meta.compression_method.0),
                last_modified_time: types::U16::set(0),
                last_modified_date: types::U16::set(0),
                crc32: types::U32::set(meta.crc32),
                compressed_size: types::U32::set(0xffff_ffff),
                uncompressed_size: types::U32::set(0xffff_ffff),
                file_name_length: types::U16::set(name.len() as u16),
                extra_fields_length: types::U16::set((size_of::<LocalZip64>() + time.len()) as _),
            }
            .as_bytes(),
            name.as_bytes(),
            zip64.as_bytes(),
            time,
        ])?;

        Ok(())
    }

    #[allow(clippy::boxed_local)]
    fn push_central_header(
        &mut self,
        name: Box<str>,
        meta: &Metadata,
        comment: &str,
        is_streaming: bool,
        local_header_offset: u64,
    ) -> io::Result<()> {
        let Ok(comment_len) = comment.len().try_into() else {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "comment too long",
            ));
        };

        self.central_headers.try_reserve(
            size_of::<types::CentralFileHeader>()
                + size_of::<CentralZip64>()
                + size_of::<ExtendedTimestamp>()
                + name.len()
                + comment.len(),
        )?;
        self.entries
            .try_reserve(1, get_name(&self.central_headers))?;

        debug_assert!(name.len() <= u16::MAX as usize);

        let zip64 = CentralZip64 {
            id: types::U16::set(0x0001),
            size: types::U16::set(24),
            compressed_size: types::U64::set(meta.compressed_size),
            uncompressed_size: types::U64::set(meta.uncompressed_size),
            local_header_offset: types::U64::set(local_header_offset),
        };

        let time = ExtendedTimestamp::new(meta.modified_at);
        let time = time.as_slice().as_bytes();

        let stream_flag = if is_streaming { 1 << 3 } else { 0 };

        let attributes = match meta.typ {
            FileType::File => (1 << 5) | (8 << 28),
            FileType::Directory => (1 << 4) | (4 << 28),
            FileType::Symlink => (0o777 << 16) | (10 << 28),
        };

        self.central_headers.extend_from_slice(
            types::CentralFileHeader {
                signature: types::CentralFileHeader::SIGNATURE,
                made_by: types::U16::set(0x0300),    // Unix
                version_needed: types::U16::set(45), // Version 4.5 for Zip64 support
                flags: types::U16::set((1 << 11) | stream_flag),
                compression_method: types::U16::set(meta.compression_method.0),
                last_modified_time: types::U16::set(0),
                last_modified_date: types::U16::set(0),
                crc32: types::U32::set(meta.crc32),
                compressed_size: types::U32::set(0xffff_ffff),
                uncompressed_size: types::U32::set(0xffff_ffff),
                file_name_length: types::U16::set(name.len() as _),
                extra_fields_length: types::U16::set((size_of::<CentralZip64>() + time.len()) as _),
                file_comment_length: types::U16::set(comment_len),
                disk_number: types::U16::set(0),
                internal_attributes: types::U16::set(1), // "Binary Data" flag
                external_attributes: types::U32::set(attributes),
                local_header_offset: types::U32::set(0xffff_ffff),
            }
            .as_bytes(),
        );

        let name_start = self.central_headers.len();
        let name_end = name_start + name.len() - name.ends_with('/') as usize;

        self.central_headers.extend_from_slice(name.as_bytes());
        self.central_headers.extend_from_slice(zip64.as_bytes());
        self.central_headers.extend_from_slice(time);
        self.central_headers.extend_from_slice(comment.as_bytes());

        self.entries
            .insert((name_start, name_end), get_name(&self.central_headers));

        Ok(())
    }

    pub fn finish<W: Write>(mut self, writer: &mut W) -> io::Result<()> {
        self.start_writing()?;

        let central_directory_offset = self.position;

        let central_directory_size = self.central_headers.len() as u64;
        let central_directory_64_offset = central_directory_offset + central_directory_size;

        let total_entries = types::U64::set(self.entries.len() as u64);

        writer.write_all_many([
            &self.central_headers,
            types::EndOfCentralDirectory64 {
                signature: types::EndOfCentralDirectory64::SIGNATURE,
                record_size: types::U64::set(44),
                made_by: types::U16::set(0x0300),    // Unix
                version_needed: types::U16::set(45), // Version 4.5 for Zip64 support
                disk_number: types::U32::set(0),
                disk_with_central_directory: types::U32::set(0),
                entries_on_this_disk: total_entries,
                total_entries,
                central_directory_size: types::U64::set(central_directory_size),
                central_directory_offset: types::U64::set(central_directory_offset),
            }
            .as_bytes(),
            types::EndOfCentralDirectory64Locator {
                signature: types::EndOfCentralDirectory64Locator::SIGNATURE,
                disk_with_central_directory: types::U32::set(0),
                central_directory_64_offset: types::U64::set(central_directory_64_offset),
                total_disks: types::U32::set(1),
            }
            .as_bytes(),
            types::EndOfCentralDirectory {
                signature: types::EndOfCentralDirectory::SIGNATURE,
                disk_number: types::U16::set(0),
                disk_with_central_directory: types::U16::set(0),
                entries_on_this_disk: types::U16::set(0xffff),
                total_entries: types::U16::set(0xffff),
                central_directory_size: types::U32::set(0xffff_ffff),
                central_directory_offset: types::U32::set(0xffff_ffff),
                comment_length: types::U16::set(0),
            }
            .as_bytes(),
        ])?;

        Ok(())
    }
}

pub struct RawFileStreamer<'a, W: Write> {
    started_at: u64,
    writer: utils::Counter<W>,

    file_name: Box<str>,
    local_header_offset: u64,
    compression_method: CompressionMethod,
    modified_at: Timestamp,

    raw: &'a mut RawArchiveWriter,
}

impl<W: Write> Write for RawFileStreamer<'_, W> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.writer.write(buf)
    }

    fn write_vectored(&mut self, bufs: &[io::IoSlice<'_>]) -> io::Result<usize> {
        self.writer.write_vectored(bufs)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.writer.flush()
    }
}

impl<W: Write> RawFileStreamer<'_, W> {
    pub fn finish(mut self, uncompressed_size: u64, crc32: u32, comment: &str) -> io::Result<()> {
        let compressed_size = self.writer.amt - self.started_at;

        self.writer.write_pod(&types::DataDescriptor64 {
            signature: types::DataDescriptor64::SIGNATURE,
            crc32: types::U32::set(crc32),
            compressed_size: types::U64::set(compressed_size),
            uncompressed_size: types::U64::set(uncompressed_size),
        })?;
        self.raw.position += self.writer.amt;

        self.raw.push_central_header(
            self.file_name,
            &Metadata {
                compression_method: self.compression_method,
                compressed_size,
                uncompressed_size,
                crc32,
                typ: FileType::File,
                modified_at: self.modified_at,
            },
            comment,
            true,
            self.local_header_offset,
        )?;

        self.raw.state = State::Default;

        Ok(())
    }
}
