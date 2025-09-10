use crate::{CompressionMethod, compression::Compressor, crc32::Crc32Writer, types};
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
    fn write_pod<T: types::Pod>(&mut self, data: &T) -> io::Result<()> {
        self.write_all(data.as_bytes())
    }
}

impl<W: Write> WriteExt for W {}

pub struct FileOptions {
    pub compression_method: CompressionMethod,
    pub level: Option<i32>,
}

#[derive(Default)]
pub struct ArchiveWriter<W: Write> {
    writer: Counter<W>,
    entries: Vec<types::CentralFileHeader>,
    names: String,
    error: bool,
}

impl<W: Write> ArchiveWriter<W> {
    pub fn new(writer: W) -> Self {
        ArchiveWriter {
            entries: Vec::new(),
            writer: Counter::new(writer),
            names: String::new(),
            error: false,
        }
    }

    #[inline]
    fn check_state(&self) -> io::Result<()> {
        #[cold]
        fn error() -> io::Error {
            io::Error::other("A non-recoverable error occurred or a file was not `finish`ed")
        }

        if self.error { Err(error()) } else { Ok(()) }
    }

    pub fn finish(mut self) -> io::Result<W> {
        self.check_state()?;

        let central_directory_offset = types::U32::set(self.writer.amt as _);

        let mut names_len = 0;
        for entry in &self.entries {
            let name_end = names_len + entry.file_name_length.get() as usize;
            let name = &self.names.as_bytes()[names_len..name_end];
            names_len = name_end;

            debug_assert!(std::str::from_utf8(name).is_ok());

            self.writer.write_pod(entry)?;
            self.writer.write_all(name)?;
        }
        debug_assert_eq!(names_len, self.names.len());

        let central_directory_size =
            types::U32::set(self.writer.amt as u32 - central_directory_offset.get());

        self.writer.write_pod(&types::EndOfCentralDirectory {
            signature: types::EndOfCentralDirectory::SIGNATURE,
            disk_number: types::U16::set(0),
            disk_with_central_directory: types::U16::set(0),
            entries_on_this_disk: types::U16::set(self.entries.len() as _),
            total_entries: types::U16::set(self.entries.len() as _),
            central_directory_size,
            central_directory_offset,
            comment_length: types::U16::set(0),
        })?;

        Ok(self.writer.writer)
    }

    pub fn write_file(
        &mut self,
        name: &str,
        compression_method: CompressionMethod,
        level: Option<i32>,
        mut content: impl io::Read,
    ) -> io::Result<()> {
        self.check_state()?;

        let Ok(name_len) = name.len().try_into() else {
            return Err(io::Error::new(
                io::ErrorKind::InvalidFilename,
                "file name too long",
            ));
        };
        let file_name_length = types::U16::set(name_len);

        let mut w = Crc32Writer::new(Compressor::new(Vec::new(), compression_method, level)?);
        let size = io::copy(&mut content, &mut w)?;
        let crc32 = types::U32::set(w.result());
        let compressed = w.into_inner().finish()?;

        let local_header_offset = types::U32::set(self.writer.amt as _);

        self.error = true;

        self.writer.write_pod(&types::LocalFileHeader {
            signature: types::LocalFileHeader::SIGNATURE,
            required_version: types::U16::set(40),
            flags: types::U16::set(1 << 11),
            compression_method: types::U16::set(compression_method.0),
            last_modified_time: types::U16::set(0),
            last_modified_date: types::U16::set(0),
            crc32,
            compressed_size: types::U32::set(compressed.len() as _),
            uncompressed_size: types::U32::set(size as _),
            file_name_length,
            extra_fields_length: types::U16::set(0),
        })?;

        self.writer.write_all(name.as_bytes())?;
        self.writer.write_all(&compressed)?;

        self.entries.push(types::CentralFileHeader {
            signature: types::CentralFileHeader::SIGNATURE,
            made_by: types::U16::set(0),
            version_needed: types::U16::set(40),
            flags: types::U16::set(1 << 11),
            compression_method: types::U16::set(compression_method.0),
            last_modified_time: types::U16::set(0),
            last_modified_date: types::U16::set(0),
            crc32,
            compressed_size: types::U32::set(compressed.len() as _),
            uncompressed_size: types::U32::set(size as _),
            file_name_length,
            extra_fields_length: types::U16::set(0),
            file_comment_length: types::U16::set(0),
            disk_number: types::U16::set(0),
            internal_attributes: types::U16::set(0),
            external_attributes: types::U32::set(0),
            local_header_offset,
        });
        self.names.push_str(name);

        self.error = false;

        Ok(())
    }

    pub fn start_stream_file(
        &mut self,
        name: &str,
        compression_method: CompressionMethod,
        level: Option<i32>,
    ) -> io::Result<FileStreamer<'_, W>> {
        self.check_state()?;

        let local_header_offset = types::U32::set(self.writer.amt as _);

        let Ok(name_len) = name.len().try_into() else {
            return Err(io::Error::new(
                io::ErrorKind::InvalidFilename,
                "file name too long",
            ));
        };
        let file_name_length = types::U16::set(name_len);

        self.error = true;

        self.writer.write_pod(&types::LocalFileHeader {
            signature: types::LocalFileHeader::SIGNATURE,
            required_version: types::U16::set(40),
            flags: types::U16::set((1 << 3) | (1 << 11)),
            compression_method: types::U16::set(compression_method.0),
            last_modified_time: types::U16::set(0),
            last_modified_date: types::U16::set(0),
            crc32: types::U32::set(0),
            compressed_size: types::U32::set(0),
            uncompressed_size: types::U32::set(0),
            file_name_length,
            extra_fields_length: types::U16::set(0),
        })?;
        self.writer.write_all(name.as_bytes())?;

        self.entries.push(types::CentralFileHeader {
            signature: types::CentralFileHeader::SIGNATURE,
            made_by: types::U16::set(0),
            version_needed: types::U16::set(40),
            flags: types::U16::set((1 << 3) | (1 << 11)),
            compression_method: types::U16::set(compression_method.0),
            last_modified_time: types::U16::set(0),
            last_modified_date: types::U16::set(0),
            crc32: types::U32::set(0),
            compressed_size: types::U32::set(0),
            uncompressed_size: types::U32::set(0),
            file_name_length,
            extra_fields_length: types::U16::set(0),
            file_comment_length: types::U16::set(0),
            disk_number: types::U16::set(0),
            internal_attributes: types::U16::set(0),
            external_attributes: types::U32::set(0),
            local_header_offset,
        });
        self.names.push_str(name);

        Ok(FileStreamer {
            started_at: self.writer.amt,
            writer: Counter::new(Crc32Writer::new(Compressor::new(
                &mut self.writer,
                compression_method,
                level,
            )?)),
            entry: self.entries.last_mut().unwrap(),
            error: &mut self.error,
        })
    }

    pub fn write_directory(&mut self, name: &str) -> io::Result<()> {
        if !name.ends_with('/') {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "directory name does not end with '/'",
            ));
        }

        self.write_file(name, CompressionMethod::STORE, None, io::empty())?;
        let entry = &mut self.entries.last_mut().unwrap();
        entry.external_attributes = types::U32::set(entry.external_attributes.get() | 0x10);
        Ok(())
    }

    pub fn flush(&mut self) -> io::Result<()> {
        self.writer.flush()
    }
}

pub struct FileStreamer<'a, W: Write> {
    started_at: u64,
    writer: Counter<Crc32Writer<Compressor<&'a mut Counter<W>>>>,
    entry: &'a mut types::CentralFileHeader,
    error: &'a mut bool,
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
        let uncompressed_size = self.writer.amt.try_into().unwrap();

        let writer = self.writer.writer;
        let crc32 = types::U32::set(writer.result());

        let writer = writer.into_inner().finish()?;

        let compressed_size = (writer.amt - self.started_at).try_into().unwrap();

        writer.write_pod(&types::U32::set(0x08074B50))?;
        writer.write_pod(&types::DataDescriptor32 {
            crc32,
            compressed_size: types::U32::set(compressed_size),
            uncompressed_size: types::U32::set(uncompressed_size),
        })?;

        self.entry.crc32 = crc32;
        self.entry.compressed_size = types::U32::set(compressed_size);
        self.entry.uncompressed_size = types::U32::set(uncompressed_size);

        *self.error = false;

        Ok(())
    }
}
