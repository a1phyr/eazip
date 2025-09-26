use crate::{
    CompressionMethod,
    types::{self, Pod},
    utils::Counter,
};
use std::io::{self, Write};

trait WriteExt: Write {
    fn write_pod<T: Pod>(&mut self, data: &T) -> io::Result<()> {
        self.write_all(data.as_bytes())
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

pub struct Metadata {
    pub compression_method: CompressionMethod,
    pub uncompressed_size: u64,
    pub crc32: u32,
    pub attributes: u32,
}

struct RawMetadata {
    is_streaming: bool,
    compressed_size: u64,
    meta: Metadata,
}

#[derive(Default)]
enum State {
    #[default]
    Default,
    Writing(u64),
}

#[derive(Default)]
pub struct RawArchiveWriter {
    state: State,
    n_entries: u64,
    central_headers: Vec<u8>,
    position: u64,
}

impl RawArchiveWriter {
    #[inline]
    fn check_state(&self) -> io::Result<()> {
        #[cold]
        fn error() -> io::Error {
            io::Error::other("A non-recoverable error occurred or a file was not `finish`ed")
        }

        match self.state {
            State::Default => Ok(()),
            State::Writing(_) => Err(error()),
        }
    }

    pub fn recover<W: io::Seek>(&mut self, mut writer: W) -> io::Result<()> {
        let State::Writing(pos) = self.state else {
            return Ok(());
        };

        writer.seek(io::SeekFrom::Start(pos))?;
        self.state = State::Default;

        Ok(())
    }

    pub fn write_file_raw<W: Write>(
        &mut self,
        writer: &mut W,
        name: &str,
        content: &[u8],
        meta: Metadata,
    ) -> io::Result<()> {
        self.check_state()?;
        self.state = State::Writing(self.position);

        let mut counter = Counter::new(writer);

        let meta = RawMetadata {
            is_streaming: false,
            compressed_size: content.len() as u64,
            meta,
        };

        self.write_local_header(&mut counter, name, &meta)?;
        counter.write_all(content)?;
        self.push_central_header(name, &meta, self.position)?;

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
        let local_header_offset = self.position;
        let mut writer = Counter::new(writer);

        self.check_state()?;
        self.state = State::Writing(self.position);

        self.write_local_header(
            &mut writer,
            name,
            &RawMetadata {
                is_streaming: true,
                compressed_size: 0,
                meta: Metadata {
                    compression_method: options.compression_method,
                    uncompressed_size: 0,
                    crc32: 0,
                    attributes: 0,
                },
            },
        )?;

        Ok(RawFileStreamer {
            started_at: writer.amt,
            writer,

            file_name: name.into(),
            local_header_offset,
            compression_method: options.compression_method,

            raw: self,
        })
    }

    fn write_local_header<W: Write>(
        &mut self,
        writer: &mut W,
        name: &str,
        meta: &RawMetadata,
    ) -> io::Result<()> {
        let Ok(name_len) = name.len().try_into() else {
            return Err(io::Error::new(
                io::ErrorKind::InvalidFilename,
                "file name too long",
            ));
        };

        let zip64 = LocalZip64 {
            id: types::U16::set(0x0001),
            size: types::U16::set(16),
            compressed_size: types::U64::set(meta.compressed_size),
            uncompressed_size: types::U64::set(meta.meta.uncompressed_size),
        };

        let stream_flag = if meta.is_streaming { 1 << 3 } else { 0 };

        writer.write_pod(&types::LocalFileHeader {
            signature: types::LocalFileHeader::SIGNATURE,
            required_version: types::U16::set(45),
            flags: types::U16::set((1 << 11) | stream_flag),
            compression_method: types::U16::set(meta.meta.compression_method.0),
            last_modified_time: types::U16::set(0),
            last_modified_date: types::U16::set(0),
            crc32: types::U32::set(meta.meta.crc32),
            compressed_size: types::U32::set(0xffff_ffff),
            uncompressed_size: types::U32::set(0xffff_ffff),
            file_name_length: types::U16::set(name_len),
            extra_fields_length: types::U16::set(size_of::<LocalZip64>() as _),
        })?;

        writer.write_all(name.as_bytes())?;
        writer.write_all(zip64.as_bytes())?;

        Ok(())
    }

    fn push_central_header(
        &mut self,
        name: &str,
        meta: &RawMetadata,
        local_header_offset: u64,
    ) -> io::Result<()> {
        self.central_headers.try_reserve(
            size_of::<types::CentralFileHeader>() + size_of::<CentralZip64>() + name.len(),
        )?;

        self.n_entries += 1;

        debug_assert!(name.len() < u16::MAX as usize);

        let zip64 = CentralZip64 {
            id: types::U16::set(0x0001),
            size: types::U16::set(24),
            compressed_size: types::U64::set(meta.compressed_size),
            uncompressed_size: types::U64::set(meta.meta.uncompressed_size),
            local_header_offset: types::U64::set(local_header_offset),
        };

        let stream_flag = if meta.is_streaming { 1 << 3 } else { 0 };

        self.central_headers.extend_from_slice(
            types::CentralFileHeader {
                signature: types::CentralFileHeader::SIGNATURE,
                made_by: types::U16::set(0x0300),    // Unix
                version_needed: types::U16::set(45), // Version 4.5 for Zip64 support
                flags: types::U16::set((1 << 11) | stream_flag),
                compression_method: types::U16::set(meta.meta.compression_method.0),
                last_modified_time: types::U16::set(0),
                last_modified_date: types::U16::set(0),
                crc32: types::U32::set(meta.meta.crc32),
                compressed_size: types::U32::set(0xffff_ffff),
                uncompressed_size: types::U32::set(0xffff_ffff),
                file_name_length: types::U16::set(name.len() as _),
                extra_fields_length: types::U16::set(size_of::<CentralZip64>() as _),
                file_comment_length: types::U16::set(0),
                disk_number: types::U16::set(0),
                internal_attributes: types::U16::set(1), // "Binary Data" flag
                external_attributes: types::U32::set(meta.meta.attributes),
                local_header_offset: types::U32::set(0xffff_ffff),
            }
            .as_bytes(),
        );

        self.central_headers.extend_from_slice(name.as_bytes());
        self.central_headers.extend_from_slice(zip64.as_bytes());

        Ok(())
    }

    pub fn finish<W: Write>(self, writer: &mut W) -> io::Result<()> {
        self.check_state()?;

        let central_directory_offset = self.position;

        writer.write_all(&self.central_headers)?;

        let central_directory_size = self.central_headers.len() as u64;
        let central_directory_64_offset = central_directory_offset + central_directory_size;

        writer.write_pod(&types::EndOfCentralDirectory64 {
            signature: types::EndOfCentralDirectory64::SIGNATURE,
            record_size: types::U64::set(44),
            made_by: types::U16::set(0x0300),    // Unix
            version_needed: types::U16::set(45), // Version 4.5 for Zip64 support
            disk_number: types::U32::set(0),
            disk_with_central_directory: types::U32::set(0),
            entries_on_this_disk: types::U64::set(self.n_entries),
            total_entries: types::U64::set(self.n_entries),
            central_directory_size: types::U64::set(central_directory_size),
            central_directory_offset: types::U64::set(central_directory_offset),
        })?;

        writer.write_pod(&types::EndOfCentralDirectory64Locator {
            signature: types::EndOfCentralDirectory64Locator::SIGNATURE,
            disk_with_central_directory: types::U32::set(0),
            central_directory_64_offset: types::U64::set(central_directory_64_offset),
            total_disks: types::U32::set(1),
        })?;

        writer.write_pod(&types::EndOfCentralDirectory {
            signature: types::EndOfCentralDirectory::SIGNATURE,
            disk_number: types::U16::set(0),
            disk_with_central_directory: types::U16::set(0),
            entries_on_this_disk: types::U16::set(0xffff),
            total_entries: types::U16::set(0xffff),
            central_directory_size: types::U32::set(0xffff_ffff),
            central_directory_offset: types::U32::set(0xffff_ffff),
            comment_length: types::U16::set(0),
        })?;

        Ok(())
    }
}

pub struct RawFileStreamer<'a, W: Write> {
    started_at: u64,
    writer: Counter<W>,

    file_name: Box<str>,
    local_header_offset: u64,
    compression_method: CompressionMethod,

    raw: &'a mut RawArchiveWriter,
}

impl<W: Write> Write for RawFileStreamer<'_, W> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.writer.write(buf)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.writer.flush()
    }
}

impl<W: Write> RawFileStreamer<'_, W> {
    pub fn finish(mut self, uncompressed_size: u64, crc32: u32) -> io::Result<()> {
        let compressed_size = self.writer.amt - self.started_at;

        self.writer.write_pod(&types::DataDescriptor64 {
            signature: types::DataDescriptor64::SIGNATURE,
            crc32: types::U32::set(crc32),
            compressed_size: types::U64::set(compressed_size),
            uncompressed_size: types::U64::set(uncompressed_size),
        })?;
        self.raw.position += self.writer.amt;

        self.raw.push_central_header(
            &self.file_name,
            &RawMetadata {
                is_streaming: true,
                compressed_size,
                meta: Metadata {
                    compression_method: self.compression_method,
                    uncompressed_size,
                    crc32,
                    attributes: 0,
                },
            },
            self.local_header_offset,
        )?;

        self.raw.state = State::Default;

        Ok(())
    }
}

impl<W: Write + io::Seek> RawFileStreamer<'_, W> {
    pub fn finish_seekable(self, uncompressed_size: u64, crc32: u32) -> io::Result<()> {
        let compressed_size = self.writer.amt - self.started_at;
        self.raw.position += self.writer.amt;

        let mut writer = self.writer.inner;

        let meta = RawMetadata {
            is_streaming: false,
            compressed_size,
            meta: Metadata {
                compression_method: self.compression_method,
                uncompressed_size,
                crc32,
                attributes: 0,
            },
        };

        writer.seek(std::io::SeekFrom::Start(self.local_header_offset))?;
        self.raw
            .write_local_header(&mut writer, &self.file_name, &meta)?;
        writer.seek(std::io::SeekFrom::Start(self.raw.position))?;

        self.raw
            .push_central_header(&self.file_name, &meta, self.local_header_offset)?;

        self.raw.state = State::Default;

        Ok(())
    }
}
