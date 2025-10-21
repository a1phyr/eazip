use crate::{
    CompressionMethod,
    compression::Compressor,
    utils::{Counter, Crc32Writer},
};
use std::io;

mod raw;

#[derive(Debug, Default, Clone)]
#[non_exhaustive]
pub struct FileOptions {
    pub compression_method: CompressionMethod,
    pub level: Option<i32>,
}

#[derive(Default)]
pub struct ArchiveWriter<W: io::Write> {
    writer: W,
    raw: raw::RawArchiveWriter,
}

impl<W: io::Write> ArchiveWriter<W> {
    pub fn new(writer: W) -> Self {
        ArchiveWriter {
            writer,
            raw: raw::RawArchiveWriter::default(),
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
            raw::Metadata {
                compression_method: options.compression_method,
                uncompressed_size,
                crc32,
                typ: crate::FileType::File,
            },
        )?;

        Ok(())
    }

    pub fn start_stream_file(
        &mut self,
        name: &str,
        options: &FileOptions,
    ) -> io::Result<FileStreamer<'_, W>> {
        let writer = self.raw.start_stream_raw(&mut self.writer, name, options)?;

        Ok(FileStreamer {
            writer: Counter::new(Crc32Writer::new(Compressor::new(
                writer,
                options.compression_method,
                options.level,
            )?)),
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
            raw::Metadata {
                compression_method: CompressionMethod::STORE,
                uncompressed_size: 0,
                crc32: 0,
                typ: crate::FileType::Directory,
            },
        )
    }

    pub fn write_symlink(&mut self, name: &str, target: &str) -> io::Result<()> {
        self.raw.write_file_raw(
            &mut self.writer,
            name,
            target.as_bytes(),
            raw::Metadata {
                compression_method: CompressionMethod::STORE,
                uncompressed_size: target.len() as _,
                crc32: crc32fast::hash(target.as_bytes()),
                typ: crate::FileType::Symlink,
            },
        )
    }

    pub fn recover(&mut self) -> io::Result<()>
    where
        W: io::Seek,
    {
        self.raw.recover(&mut self.writer)
    }

    pub fn flush(&mut self) -> io::Result<()> {
        self.writer.flush()
    }

    pub fn finish(mut self) -> io::Result<W> {
        self.raw.finish(&mut self.writer)?;
        Ok(self.writer)
    }
}

pub struct FileStreamer<'a, W: io::Write> {
    writer: Counter<Crc32Writer<Compressor<raw::RawFileStreamer<'a, &'a mut W>>>>,
}

impl<W: io::Write> io::Write for FileStreamer<'_, W> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.writer.write(buf)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.writer.flush()
    }
}

impl<W: io::Write> FileStreamer<'_, W> {
    pub fn finish(self) -> io::Result<()> {
        let uncompressed_size = self.writer.amt;
        let crc32 = self.writer.inner.result();

        let raw_writer = self.writer.inner.into_inner().finish()?;

        raw_writer.finish(uncompressed_size, crc32)
    }
}

impl<W: io::Write + io::Seek> FileStreamer<'_, W> {
    pub fn finish_seekable(self) -> io::Result<()> {
        let uncompressed_size = self.writer.amt;
        let crc32 = self.writer.inner.result();

        let raw_writer = self.writer.inner.into_inner().finish()?;

        raw_writer.finish_seekable(uncompressed_size, crc32)
    }
}
