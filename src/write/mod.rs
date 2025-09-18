use crate::{
    CompressionMethod,
    compression::Compressor,
    crc32::Crc32Writer,
    types::{self, Pod},
};
use std::io::{self, Write};

#[derive(Default)]
struct Counter<W> {
    amt: u64,
    writer: W,
}

impl<W> Counter<W> {
    pub const fn new(writer: W) -> Self {
        Self { amt: 0, writer }
    }
}

impl<W: Write> Write for Counter<W> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        let n = self.writer.write(buf)?;
        self.amt += n as u64;
        Ok(n)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.writer.flush()
    }
}

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
    pub force_zip_64: bool,
}

#[allow(dead_code)]
#[derive(Debug, Clone, Copy)]
#[repr(C, packed(4))]
struct Zip64 {
    id: types::U16,
    size: types::U16,
    uncompressed_size: types::U64,
    compressed_size: types::U64,
    local_header_offset: types::U64,
}

unsafe impl Pod for Zip64 {}

fn convert_sizes(
    force_zip64: bool,
    compressed: u64,
    uncompressed: u64,
    local_header: u64,
) -> (types::U32, types::U32, types::U32, Option<Zip64>) {
    if let (Ok(compressed), Ok(uncompressed), Ok(local_header_offset), false) = (
        compressed.try_into(),
        uncompressed.try_into(),
        local_header.try_into(),
        force_zip64,
    ) {
        (
            types::U32::set(compressed),
            types::U32::set(uncompressed),
            types::U32::set(local_header_offset),
            None,
        )
    } else {
        (
            types::U32::set(0xffff_ffff),
            types::U32::set(0xffff_ffff),
            types::U32::set(0xffff_ffff),
            Some(Zip64 {
                id: types::U16::set(0x0001),
                size: types::U16::set(24),
                compressed_size: types::U64::set(compressed),
                uncompressed_size: types::U64::set(uncompressed),
                local_header_offset: types::U64::set(local_header),
            }),
        )
    }
}

#[derive(Default)]
struct RawArchiveWriter {
    error: bool,
    n_entries: u16,
    central_headers: Vec<u8>,
}

impl RawArchiveWriter {
    #[inline]
    fn check_state(&self) -> io::Result<()> {
        #[cold]
        fn error() -> io::Error {
            io::Error::other("A non-recoverable error occurred or a file was not `finish`ed")
        }

        if self.error { Err(error()) } else { Ok(()) }
    }

    fn write_local_header<W: Write>(
        &mut self,
        writer: &mut Counter<W>,
        name: &str,
        compression_method: CompressionMethod,
        flags: u16,
        compressed_size: types::U32,
        uncompressed_size: types::U32,
        crc32: types::U32,
        extra: &[u8],
    ) -> io::Result<()> {
        let Ok(name_len) = name.len().try_into() else {
            return Err(io::Error::new(
                io::ErrorKind::InvalidFilename,
                "file name too long",
            ));
        };

        writer.write_pod(&types::LocalFileHeader {
            signature: types::LocalFileHeader::SIGNATURE,
            required_version: types::U16::set(45),
            flags: types::U16::set((1 << 11) | flags),
            compression_method: types::U16::set(compression_method.0),
            last_modified_time: types::U16::set(0),
            last_modified_date: types::U16::set(0),
            crc32,
            compressed_size,
            uncompressed_size,
            file_name_length: types::U16::set(name_len),
            extra_fields_length: types::U16::set(extra.len() as _),
        })?;

        writer.write_all(name.as_bytes())?;
        writer.write_all(extra)?;

        Ok(())
    }

    fn push_central_header(
        &mut self,
        name: &str,
        compression_method: CompressionMethod,
        flags: u16,
        compressed_size: types::U32,
        uncompressed_size: types::U32,
        local_header_offset: types::U32,
        crc32: types::U32,
        extra: &[u8],
    ) {
        self.n_entries += 1;

        debug_assert!(name.len() < u16::MAX as usize);

        self.central_headers.extend_from_slice(
            types::CentralFileHeader {
                signature: types::CentralFileHeader::SIGNATURE,
                made_by: types::U16::set(0x0300), // Unix
                version_needed: types::U16::set(45),
                flags: types::U16::set((1 << 11) | flags),
                compression_method: types::U16::set(compression_method.0),
                last_modified_time: types::U16::set(0),
                last_modified_date: types::U16::set(0),
                crc32,
                compressed_size,
                uncompressed_size,
                file_name_length: types::U16::set(name.len() as _),
                extra_fields_length: types::U16::set(extra.len() as _),
                file_comment_length: types::U16::set(0),
                disk_number: types::U16::set(0),
                internal_attributes: types::U16::set(1), // "Binary Data" flag
                external_attributes: types::U32::set(0),
                local_header_offset,
            }
            .as_bytes(),
        );

        self.central_headers.extend_from_slice(name.as_bytes());
        self.central_headers.extend_from_slice(extra);
    }

    fn finish<W: Write>(self, writer: &mut Counter<W>) -> io::Result<()> {
        self.check_state()?;

        let central_directory_offset = types::U32::set(writer.amt as _);

        writer.write_all(&self.central_headers)?;

        let central_directory_size =
            types::U32::set(writer.amt as u32 - central_directory_offset.get());

        writer.write_pod(&types::EndOfCentralDirectory {
            signature: types::EndOfCentralDirectory::SIGNATURE,
            disk_number: types::U16::set(0),
            disk_with_central_directory: types::U16::set(0),
            entries_on_this_disk: types::U16::set(self.n_entries),
            total_entries: types::U16::set(self.n_entries),
            central_directory_size,
            central_directory_offset,
            comment_length: types::U16::set(0),
        })?;

        Ok(())
    }
}

#[derive(Default)]
pub struct ArchiveWriter<W: Write> {
    writer: Counter<W>,
    raw: RawArchiveWriter,
}

impl<W: Write> ArchiveWriter<W> {
    pub fn new(writer: W) -> Self {
        ArchiveWriter {
            writer: Counter::new(writer),
            raw: RawArchiveWriter::default(),
        }
    }

    pub fn write_file(
        &mut self,
        name: &str,
        mut content: impl io::Read,
        options: &FileOptions,
    ) -> io::Result<()> {
        self.raw.check_state()?;

        let mut w = Crc32Writer::new(Compressor::new(
            Vec::new(),
            options.compression_method,
            options.level,
        )?);
        let uncompressed_size = io::copy(&mut content, &mut w)?;
        let crc32 = types::U32::set(w.result());
        let compressed = w.into_inner().finish()?;

        let (compressed_size, uncompressed_size, local_header_offset, zip64) = convert_sizes(
            options.force_zip_64,
            compressed.len() as u64,
            uncompressed_size,
            self.writer.amt,
        );

        self.raw.error = true;

        self.raw.write_local_header(
            &mut self.writer,
            name,
            options.compression_method,
            0,
            compressed_size,
            uncompressed_size,
            crc32,
            zip64.as_slice().as_bytes(),
        )?;

        self.writer.write_all(&compressed)?;

        self.raw.push_central_header(
            name,
            options.compression_method,
            0,
            compressed_size,
            uncompressed_size,
            local_header_offset,
            crc32,
            zip64.as_slice().as_bytes(),
        );

        self.raw.error = false;

        Ok(())
    }

    pub fn start_stream_file(
        &mut self,
        name: &str,
        options: &FileOptions,
    ) -> io::Result<FileStreamer<'_, W>> {
        self.raw.check_state()?;

        let local_header_offset = self.writer.amt;

        self.raw.error = true;

        self.raw.write_local_header(
            &mut self.writer,
            name,
            options.compression_method,
            1 << 3,
            types::U32::set(0),
            types::U32::set(0),
            types::U32::set(0),
            [types::U16::set(0x0001), types::U16::set(0)].as_bytes(),
        )?;

        Ok(FileStreamer {
            started_at: self.writer.amt,
            writer: Counter::new(Crc32Writer::new(Compressor::new(
                &mut self.writer,
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
                "directory name does not end with '/'",
            ));
        }

        self.write_file(
            name,
            io::empty(),
            &FileOptions {
                compression_method: CompressionMethod::STORE,
                level: None,
                force_zip_64: false,
            },
        )?;

        Ok(())
    }

    pub fn flush(&mut self) -> io::Result<()> {
        self.writer.flush()
    }

    pub fn finish(mut self) -> io::Result<W> {
        self.raw.finish(&mut self.writer)?;
        Ok(self.writer.writer)
    }
}

pub struct FileStreamer<'a, W: Write> {
    started_at: u64,
    writer: Counter<Crc32Writer<Compressor<&'a mut Counter<W>>>>,

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
        let crc32 = types::U32::set(self.writer.writer.result());

        let writer = self.writer.writer.into_inner();
        let compression_method = writer.compression_method();
        let writer = writer.finish()?;

        let (compressed_size, uncompressed_size, local_header_offset, zip64) = convert_sizes(
            true,
            writer.amt - self.started_at,
            self.writer.amt,
            self.local_header_offset,
        );
        let zip64 = zip64.unwrap();

        writer.write_pod(&types::DataDescriptor64 {
            signature: types::DataDescriptor64::SIGNATURE,
            crc32,
            compressed_size: zip64.compressed_size,
            uncompressed_size: zip64.uncompressed_size,
        })?;

        self.raw.push_central_header(
            &self.file_name,
            compression_method,
            1 << 3,
            compressed_size,
            uncompressed_size,
            local_header_offset,
            crc32,
            zip64.as_bytes(),
        );

        self.raw.error = false;

        Ok(())
    }
}
