//! Utilities to write an archive.

use crate::{
    CompressionMethod, Timestamp,
    compression::Compressor,
    utils::{Counter, Crc32Writer},
};
use std::{fmt, io};

mod raw;

/// The options used when adding a file to an archive.
///
/// Setting the timestamp is not implemented yet.
#[derive(Debug, Default, Clone)]
#[non_exhaustive]
pub struct FileOptions {
    /// The compression method.
    pub compression_method: CompressionMethod,
    /// The compression level.
    pub level: Option<i32>,
    /// The modification time of the entry.
    ///
    /// Default value is `Timestamp::UNIX_EPOCH`, which means that this field is
    /// ignored.
    pub modified_at: Timestamp,
}

/// Wraps a writer to create a ZIP archive.
///
/// You need to call `self.finish()` when done.
///
/// When adding a file to the archive, some checks are made to ensure its name
/// is valid (it is not absolute, does not contain the '\\' character, etc).
/// Such validation checks may be added in a semver-compatible version if they
/// may prevent invalid or dangerous archives.
///
/// # Example
///
/// ```no_run
/// use std::io::prelude::*;
///
/// let mut archive = eazip::ArchiveWriter::create("example.zip")?;
/// let options = eazip::write::FileOptions::default();
///
/// // Add a file
/// archive.add_file("hello.txt", b"hello\n".as_slice(), &options)?;
///
/// // Add a directory
/// archive.add_directory("dir/")?;
///
/// // Stream a file
/// let mut writer = archive.stream_file("dir/streaming.txt", &options)?;
/// writer.write_all(b"some data\n")?;
/// writer.finish()?;
///
/// // Finish writing the archive
/// archive.finish()?;
/// # Ok::<(), std::io::Error>(())
/// ```
#[derive(Debug, Default)]
pub struct ArchiveWriter<W: io::Write> {
    writer: W,
    raw: raw::RawArchiveWriter,
}

impl ArchiveWriter<std::fs::File> {
    /// Creates a new `ArchiveWriter` that writes to the given file.
    ///
    /// The file will be created if it does not exist, and will be truncated if
    /// it does.
    pub fn create(path: impl AsRef<std::path::Path>) -> io::Result<Self> {
        std::fs::File::create(path).map(Self::new)
    }

    /// Creates a new `ArchiveWriter` that writes to the given file; error if
    /// the file exists.
    pub fn create_new(path: impl AsRef<std::path::Path>) -> io::Result<Self> {
        std::fs::File::create_new(path).map(Self::new)
    }
}

impl<W: io::Write> ArchiveWriter<W> {
    /// Creates a new `ArchiveWriter` that writes to the given writer.
    #[inline]
    pub fn new(writer: W) -> Self {
        ArchiveWriter {
            writer,
            raw: raw::RawArchiveWriter::default(),
        }
    }

    /// Writes a file to the archive.
    ///
    /// The entire compressed content of the file must fit in memory.
    pub fn add_file<R: io::Read>(
        &mut self,
        name: &str,
        mut content: R,
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
            &raw::Metadata {
                compression_method: options.compression_method,
                compressed_size: compressed.len() as _,
                uncompressed_size,
                crc32,
                typ: crate::FileType::File,
                modified_at: options.modified_at,
            },
            "",
        )?;

        Ok(())
    }

    /// Starts streaming a file to the archive.
    ///
    /// This is useful for (but not limited to) very large files that may not
    /// fit in memory.
    ///
    /// This method returns a `FileStreamer` that can be written to.
    pub fn stream_file(
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

    /// Adds a directory to the archive.
    pub fn add_directory(&mut self, name: &str) -> io::Result<()> {
        self.raw.write_file_raw(
            &mut self.writer,
            name,
            &[],
            &raw::Metadata {
                compression_method: CompressionMethod::STORE,
                compressed_size: 0,
                uncompressed_size: 0,
                crc32: 0,
                typ: crate::FileType::Directory,
                modified_at: Timestamp::UNIX_EPOCH,
            },
            "",
        )
    }

    /// Adds a symlink to the archive.
    ///
    /// The target of the symlink is not validated yet, which may be used to
    /// create dangerous archives if used with untrusted input. This will be
    /// fixed in a future version so this behaviour should not be relied on.
    pub fn add_symlink(&mut self, name: &str, target: &str) -> io::Result<()> {
        self.raw.write_file_raw(
            &mut self.writer,
            name,
            target.as_bytes(),
            &raw::Metadata {
                compression_method: CompressionMethod::STORE,
                compressed_size: target.len() as _,
                uncompressed_size: target.len() as _,
                crc32: crc32fast::hash(target.as_bytes()),
                typ: crate::FileType::Symlink,
                modified_at: Timestamp::UNIX_EPOCH,
            },
            "",
        )
    }

    /// Tries to recover from an error by erasing the last entry.
    ///
    /// Note that this requires a seeking writer. Calling this when no error
    /// needs recovery does nothing.
    ///
    /// **Footgun**: this requires the user to properly truncate the writer after
    /// using this method.
    #[inline]
    pub fn recover(&mut self) -> io::Result<()>
    where
        W: io::Seek,
    {
        self.raw.recover(&mut self.writer)
    }

    /// Gets a shared reference to the underlying writer.
    #[inline]
    pub fn get_ref(&self) -> &W {
        &self.writer
    }

    /// Gets a mutable reference to the underlying writer.
    ///
    /// It is inadvisable to directly write to the underlying writer.
    #[inline]
    pub fn get_mut(&mut self) -> &mut W {
        &mut self.writer
    }

    /// Flushes the underlying stream.
    #[inline]
    pub fn flush(&mut self) -> io::Result<()> {
        self.writer.flush()
    }

    /// Finishes writing the archive and get the writer back.
    ///
    /// It is necessary to call this method or the resulting archive will not
    /// be readable.
    #[inline]
    pub fn finish(mut self) -> io::Result<W> {
        self.raw.finish(&mut self.writer)?;
        Ok(self.writer)
    }
}

/// An adapter to stream a ZIP file.
///
/// Writing to this value will write to a file in an archive.
///
/// It is necessary to call `finish` when done.
pub struct FileStreamer<'a, W: io::Write> {
    writer: Counter<Crc32Writer<Compressor<raw::RawFileStreamer<'a, &'a mut W>>>>,
}

impl<W: io::Write> io::Write for FileStreamer<'_, W> {
    #[inline]
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.writer.write(buf)
    }

    #[inline]
    fn write_vectored(&mut self, bufs: &[io::IoSlice<'_>]) -> io::Result<usize> {
        self.writer.write_vectored(bufs)
    }

    #[inline]
    fn flush(&mut self) -> io::Result<()> {
        self.writer.flush()
    }
}

impl<W: io::Write> FileStreamer<'_, W> {
    /// Finishes writing the current file.
    pub fn finish(self) -> io::Result<()> {
        self.finish_with_comment("")
    }

    /// Finishes writing the current file.
    pub fn finish_with_comment(self, comment: &str) -> io::Result<()> {
        let uncompressed_size = self.writer.amt;
        let crc32 = self.writer.inner.result();

        let raw_writer = self.writer.inner.into_inner().finish()?;

        raw_writer.finish(uncompressed_size, crc32, comment)
    }
}

impl<'a, W: io::Write + fmt::Debug> fmt::Debug for FileStreamer<'a, W> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("FileStreamer { .. }")
    }
}
