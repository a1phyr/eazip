use crate::{
    CompressionMethod,
    compression::Compressor,
    types::{self, Pod},
    utils::{Counter, Crc32Writer},
};
use std::io::{self, Write};

trait WriteExt: Write {
    fn write_pod<T: Pod>(&mut self, data: &T) -> io::Result<()> {
        self.write_all(data.as_bytes())
    }
}

impl<W: Write> WriteExt for W {}

#[derive(Debug, Default, Clone)]
#[non_exhaustive]
pub struct FileOptions {
    pub compression_method: CompressionMethod,
    pub level: Option<i32>,
}

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

struct Metadata {
    is_streaming: bool,
    compression_method: CompressionMethod,
    compressed_size: u64,
    uncompressed_size: u64,
    crc32: u32,
    attributes: u32,
}

#[derive(Default)]
enum State {
    #[default]
    Default,
    Writing,
}

#[derive(Default)]
struct RawArchiveWriter {
    state: State,
    n_entries: u16,
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
            State::Writing => Err(error()),
        }
    }

    fn write_file_raw<W: Write>(
        &mut self,
        writer: &mut W,
        name: &str,
        content: &[u8],
        meta: &Metadata,
    ) -> io::Result<()> {
        self.check_state()?;

        self.state = State::Writing;

        let mut counter = Counter::new(writer);

        self.write_local_header(&mut counter, name, meta)?;
        counter.write_all(content)?;
        self.push_central_header(name, meta, self.position);

        self.position += counter.amt;
        self.state = State::Default;

        Ok(())
    }

    fn write_local_header<W: Write>(
        &mut self,
        writer: &mut Counter<W>,
        name: &str,
        meta: &Metadata,
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
            uncompressed_size: types::U64::set(meta.uncompressed_size),
        };

        let stream_flag = if meta.is_streaming { 1 << 3 } else { 0 };

        writer.write_pod(&types::LocalFileHeader {
            signature: types::LocalFileHeader::SIGNATURE,
            required_version: types::U16::set(45),
            flags: types::U16::set((1 << 11) | stream_flag),
            compression_method: types::U16::set(meta.compression_method.0),
            last_modified_time: types::U16::set(0),
            last_modified_date: types::U16::set(0),
            crc32: types::U32::set(meta.crc32),
            compressed_size: types::U32::set(0xffff_ffff),
            uncompressed_size: types::U32::set(0xffff_ffff),
            file_name_length: types::U16::set(name_len),
            extra_fields_length: types::U16::set(size_of::<LocalZip64>() as _),
        })?;

        writer.write_all(name.as_bytes())?;
        writer.write_all(zip64.as_bytes())?;

        Ok(())
    }

    fn push_central_header(&mut self, name: &str, meta: &Metadata, local_header_offset: u64) {
        self.n_entries += 1;

        debug_assert!(name.len() < u16::MAX as usize);

        let zip64 = CentralZip64 {
            id: types::U16::set(0x0001),
            size: types::U16::set(24),
            compressed_size: types::U64::set(meta.compressed_size),
            uncompressed_size: types::U64::set(meta.uncompressed_size),
            local_header_offset: types::U64::set(local_header_offset),
        };

        let stream_flag = if meta.is_streaming { 1 << 3 } else { 0 };

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
                extra_fields_length: types::U16::set(size_of::<CentralZip64>() as _),
                file_comment_length: types::U16::set(0),
                disk_number: types::U16::set(0),
                internal_attributes: types::U16::set(1), // "Binary Data" flag
                external_attributes: types::U32::set(meta.attributes),
                local_header_offset: types::U32::set(0xffff_ffff),
            }
            .as_bytes(),
        );

        self.central_headers.extend_from_slice(name.as_bytes());
        self.central_headers.extend_from_slice(zip64.as_bytes());
    }

    fn finish<W: Write>(self, writer: &mut W) -> io::Result<()> {
        self.check_state()?;

        let central_directory_offset = self.position as u32;

        writer.write_all(&self.central_headers)?;

        let central_directory_size =
            self.position as u32 + self.central_headers.len() as u32 - central_directory_offset;

        writer.write_pod(&types::EndOfCentralDirectory {
            signature: types::EndOfCentralDirectory::SIGNATURE,
            disk_number: types::U16::set(0),
            disk_with_central_directory: types::U16::set(0),
            entries_on_this_disk: types::U16::set(self.n_entries),
            total_entries: types::U16::set(self.n_entries),
            central_directory_size: types::U32::set(central_directory_size),
            central_directory_offset: types::U32::set(central_directory_offset),
            comment_length: types::U16::set(0),
        })?;

        Ok(())
    }
}

#[derive(Default)]
pub struct ArchiveWriter<W: Write> {
    writer: W,
    raw: RawArchiveWriter,
}

impl<W: Write> ArchiveWriter<W> {
    pub fn new(writer: W) -> Self {
        ArchiveWriter {
            writer,
            raw: RawArchiveWriter::default(),
        }
    }

    pub fn write_file(
        &mut self,
        name: &str,
        mut content: impl io::Read,
        options: &FileOptions,
    ) -> io::Result<()> {
        let mut w = Crc32Writer::new(Compressor::new(
            Vec::new(),
            options.compression_method,
            options.level,
        )?);
        let uncompressed_size = io::copy(&mut content, &mut w)?;
        let crc32 = w.result();
        let compressed = w.into_inner().finish()?;

        self.raw.write_file_raw(
            &mut self.writer,
            name,
            &compressed,
            &Metadata {
                is_streaming: false,
                compression_method: options.compression_method,
                compressed_size: compressed.len() as u64,
                uncompressed_size,
                crc32,
                attributes: 0,
            },
        )?;

        Ok(())
    }

    pub fn start_stream_file(
        &mut self,
        name: &str,
        options: &FileOptions,
    ) -> io::Result<FileStreamer<'_, W>> {
        self.raw.check_state()?;

        let local_header_offset = self.raw.position;

        self.raw.state = State::Writing;

        let mut writer = Counter::new(&mut self.writer);

        self.raw.write_local_header(
            &mut writer,
            name,
            &Metadata {
                is_streaming: true,
                compression_method: options.compression_method,
                compressed_size: 0,
                uncompressed_size: 0,
                crc32: 0,
                attributes: 0,
            },
        )?;

        Ok(FileStreamer {
            started_at: writer.amt,
            writer: Counter::new(Crc32Writer::new(Compressor::new(
                writer,
                options.compression_method,
                options.level,
            )?)),

            file_name: name.into(),
            local_header_offset,

            raw: &mut self.raw,
        })
    }

    pub fn write_directory(&mut self, name: &str) -> io::Result<()> {
        if !name.ends_with('/') {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "directory name must end with '/'",
            ));
        }

        self.raw.write_file_raw(
            &mut self.writer,
            name,
            &[],
            &Metadata {
                is_streaming: false,
                compression_method: CompressionMethod::STORE,
                compressed_size: 0,
                uncompressed_size: 0,
                crc32: 0,
                attributes: (1 << 4) | (4 << 28),
            },
        )
    }

    pub fn flush(&mut self) -> io::Result<()> {
        self.writer.flush()
    }

    pub fn finish(mut self) -> io::Result<W> {
        self.raw.finish(&mut self.writer)?;
        Ok(self.writer)
    }
}

pub struct FileStreamer<'a, W: Write> {
    started_at: u64,
    writer: Counter<Crc32Writer<Compressor<Counter<&'a mut W>>>>,

    file_name: Box<str>,
    local_header_offset: u64,

    raw: &'a mut RawArchiveWriter,
}

impl<W: Write> Write for FileStreamer<'_, W> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.writer.write(buf)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.writer.flush()
    }
}

impl<W: Write> FileStreamer<'_, W> {
    pub fn finish(self) -> io::Result<()> {
        let crc32 = self.writer.inner.result();

        let writer = self.writer.inner.into_inner();
        let compression_method = writer.compression_method();
        let mut writer = writer.finish()?;

        let compressed_size = writer.amt - self.started_at;
        let uncompressed_size = self.writer.amt;

        writer.write_pod(&types::DataDescriptor64 {
            signature: types::DataDescriptor64::SIGNATURE,
            crc32: types::U32::set(crc32),
            compressed_size: types::U64::set(compressed_size),
            uncompressed_size: types::U64::set(uncompressed_size),
        })?;
        self.raw.position += writer.amt;

        self.raw.push_central_header(
            &self.file_name,
            &Metadata {
                is_streaming: true,
                compression_method,
                compressed_size,
                uncompressed_size,
                crc32,
                attributes: 0,
            },
            self.local_header_offset,
        );

        self.raw.state = State::Default;

        Ok(())
    }
}
