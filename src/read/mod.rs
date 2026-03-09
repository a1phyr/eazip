//! Utilities to read an archive.

use std::{
    borrow::Cow,
    collections::HashMap,
    io::{self, BufRead, Read, Seek},
};

use crate::{CompressionMethod, Decompressor, FileType, Timestamp, types, utils};

mod extra_field;
mod raw;

use extra_field::{ExtraField, ExtraFields};

#[cold]
fn invalid(msg: &str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, msg)
}

#[cold]
fn encrypted_file() -> io::Error {
    io::Error::new(io::ErrorKind::Unsupported, "encrypted file")
}

#[cold]
fn compressed() -> io::Error {
    io::Error::new(io::ErrorKind::Unsupported, "compressed file")
}

trait ReadSeek: Read + Seek {}
impl<R: Read + Seek> ReadSeek for R {}

trait BufReadSeek: BufRead + Seek {}
impl<R: BufRead + Seek> BufReadSeek for R {}

/// The method used to encrypt a file.
///
/// `eazip` does not provide the tools to decrypt these files, but provides the
/// required metadata if you really need to.
///
/// This is only provided for completeness, please don't use this in scenarios
/// where security actually matters and use proper tools (eg `age`).
#[derive(Debug, Clone, Copy)]
#[non_exhaustive]
pub enum EncryptionMethod {
    /// Legacy ZipCrypto encryption.
    ZipCrypto,
    /// The file is encrypted using AES in CTR mode.
    ///
    /// See [the specification](https://www.winzip.com/en/support/aes-encryption/#file-format1)
    /// for the format of the encrypted files.
    Aes {
        /// The size of the AES key. This may be 128, 192 or 256 bytes.
        key_size: u16,
        /// Whether to check the CRC32 of the decypted content.
        ///
        /// If `true`, this will lead to data leak.
        check_crc32: bool,
    },
}

/// An open ZIP archive without a reader
#[derive(Debug)]
pub struct RawArchive {
    entries: Vec<Metadata>,
    comment: Box<[u8]>,
}

impl RawArchive {
    /// Creates a `RawArchive` from a reader.
    ///
    /// The same reader should be used for other methods.
    #[inline]
    pub fn new<R: Read + Seek>(reader: &mut R) -> io::Result<Self> {
        let (entries, comment) = raw::read_archive(reader)?;
        Ok(Self { entries, comment })
    }

    /// Gets the list of entries in this archive.
    #[inline]
    pub fn entries(&self) -> &[Metadata] {
        &self.entries
    }

    /// Gets the comment of the archive.
    #[inline]
    pub fn comment(&self) -> &[u8] {
        &self.comment
    }

    /// Extracts the archive to the given directory.
    ///
    /// The directory will be created if needed, but *not* its parent.
    pub fn extract<R: BufRead + Seek>(
        &self,
        reader: &mut R,
        at: &std::path::Path,
    ) -> io::Result<()> {
        match std::fs::create_dir(at) {
            Ok(()) => (),
            Err(err) if err.kind() == io::ErrorKind::AlreadyExists => (),
            Err(err) => return Err(err),
        };

        for entry in &self.entries {
            entry.extract(reader, at)?;
        }

        Ok(())
    }

    /// Extracts the archive to the given directory in parallel.
    ///
    /// The directory will be created if needed, but *not* its parent.
    ///
    /// The reader should implement [`sync_file::ReadAt`], like [`io::Cursor`]
    /// or [`sync_file::RandomAccessFile`].
    #[cfg(feature = "parallel")]
    pub fn parallel_extract<R: sync_file::ReadAt + sync_file::Size + Sync>(
        &self,
        reader: &R,
        at: &std::path::Path,
    ) -> io::Result<()> {
        use rayon::prelude::*;

        match std::fs::create_dir(at) {
            Ok(()) => (),
            Err(err) if err.kind() == io::ErrorKind::AlreadyExists => (),
            Err(err) => return Err(err),
        };

        self.entries.par_iter().try_for_each_init(
            || io::BufReader::new(sync_file::Adapter::new(reader)),
            |reader, entry| entry.extract(reader, at),
        )?;

        Ok(())
    }
}

impl FileType {
    fn test(attr: u32, name: &str) -> Option<Self> {
        let dos_attr = attr as u16;
        let unix_mode = (attr >> 16) as u16;
        let unix_kind = unix_mode >> 12;

        let is_file = (dos_attr & (1 << 5)) != 0 || unix_kind == 8;
        let is_dir = (dos_attr & (1 << 4)) != 0 || unix_kind == 4;
        let is_symlink = unix_kind == 10;
        let trailing_slash = name.ends_with('/');

        match (is_file, is_dir, trailing_slash, is_symlink) {
            (_, false, false, false) => Some(FileType::File),
            (false, _, true, false) => Some(FileType::Directory),
            (false, false, false, true) => Some(FileType::Symlink),
            _ => None,
        }
    }
}

fn convert_string(raw: &[u8], force_unicode: bool) -> Option<(Cow<'_, str>, Option<u32>)> {
    // MacOS stores the file name as UTF8, but does not use the unicode flag,
    // and everyone seems fine with that, so if we meet UTF8 we'll just pretend
    // that everything is fine.
    if let Ok(name) = str::from_utf8(raw) {
        return Some((Cow::Borrowed(name), None));
    }

    // If we didn't find UTF8 and it wasn't expected, handle it as CP437.
    if force_unicode {
        None
    } else {
        let name = utils::cp437::convert(raw);
        Some((Cow::Owned(name), Some(crc32fast::hash(raw))))
    }
}

/// The metadata of a ZIP entry.
#[derive(Debug)]
pub struct Metadata {
    header_offset: u64,
    pub data_offset: u64,

    pub compressed_size: u64,
    pub uncompressed_size: u64,
    pub compression_method: CompressionMethod,
    pub crc32: u32,
    pub file_type: FileType,

    pub modification_time: Option<Timestamp>,
    pub access_time: Option<Timestamp>,
    pub creation_time: Option<Timestamp>,

    pub encryption: Option<EncryptionMethod>,

    name: Box<str>,
    comment: Box<str>,

    is_streaming: bool,
    is_zip64: bool,
    flags: u16,
}

impl Metadata {
    fn from_local_header(
        header: types::LocalFileHeader,
        file_name: &[u8],
        extra_fields: &[u8],
    ) -> Option<Self> {
        let flags = header.flags.get();
        let is_encrypted = flags & (1 << 0) != 0;
        let is_streaming = flags & (1 << 3) != 0;
        let is_unicode = flags & (1 << 11) != 0;

        if { header.signature } != types::LocalFileHeader::SIGNATURE {
            return None;
        }

        let (name, name_crc) = convert_string(file_name, is_unicode)?;
        let name = utils::validate_name(&name)?;

        let mut meta = Self {
            crc32: header.crc32.get(),
            encryption: is_encrypted.then_some(EncryptionMethod::ZipCrypto),
            header_offset: 0,
            data_offset: 0,

            compressed_size: header.compressed_size.get() as u64,
            uncompressed_size: header.uncompressed_size.get() as u64,
            compression_method: CompressionMethod(header.compression_method.get()),
            file_type: FileType::File,

            modification_time: None,
            access_time: None,
            creation_time: None,

            name,
            comment: Box::default(),

            is_streaming,
            is_zip64: false,
            flags,
        };

        meta.parse_extra_fields(ExtraFields(extra_fields), name_crc, None)?;

        Some(meta)
    }

    fn from_central_header(
        header: types::CentralFileHeader,
        file_name: &[u8],
        extra_fields: &[u8],
        comment: &[u8],
    ) -> Option<Self> {
        let flags = header.flags.get();
        let is_encrypted = flags & (1 << 0) != 0;
        let is_streaming = flags & (1 << 3) != 0;
        let is_unicode = flags & (1 << 11) != 0;

        if { header.signature } != types::CentralFileHeader::SIGNATURE
            || header.disk_number.get() != 0
        {
            return None;
        }

        let (comment, comment_crc) = convert_string(comment, is_unicode)?;
        let comment = comment.into_owned().into_boxed_str();
        let (name, name_crc) = convert_string(file_name, is_unicode)?;
        let name = utils::validate_name(&name)?;
        let file_type = FileType::test(header.external_attributes.get(), &name)?;

        let mut meta = Self {
            crc32: header.crc32.get(),
            encryption: is_encrypted.then_some(EncryptionMethod::ZipCrypto),
            header_offset: header.local_header_offset.get() as u64,
            data_offset: 0,

            compressed_size: header.compressed_size.get() as u64,
            uncompressed_size: header.uncompressed_size.get() as u64,
            compression_method: CompressionMethod(header.compression_method.get()),
            file_type,

            modification_time: None,
            access_time: None,
            creation_time: None,

            name,
            comment,

            is_streaming,
            is_zip64: false,
            flags,
        };

        meta.parse_extra_fields(ExtraFields(extra_fields), name_crc, comment_crc)?;

        Some(meta)
    }

    fn parse_extra_fields(
        &mut self,
        extra_fields: ExtraFields,
        name_crc: Option<u32>,
        comment_crc: Option<u32>,
    ) -> Option<()> {
        for field in extra_fields.iter() {
            match field {
                ExtraField::Zip64ExtendedInformation(mut info) => {
                    if self.uncompressed_size == 0xffff_ffff {
                        self.uncompressed_size = info.next()?;
                    }
                    if self.compressed_size == 0xffff_ffff {
                        self.compressed_size = info.next()?;
                    }
                    if self.header_offset == 0xffff_ffff {
                        self.header_offset = info.next()?;
                    }
                    // Disk number must be 0
                    info.end()?;
                    self.is_zip64 = true;
                }
                ExtraField::UnicodeComment(unicode) => {
                    if Some(unicode.header_comment_crc32) != comment_crc {
                        return None;
                    }
                    self.comment = unicode.comment.into();
                }

                ExtraField::UnicodeName(unicode) => {
                    if Some(unicode.header_name_crc32) != name_crc {
                        return None;
                    }
                    self.name = utils::validate_name(unicode.name)?;
                }

                ExtraField::Ntfs(ntfs) => {
                    self.modification_time = ntfs.times.mtime;
                    self.access_time = ntfs.times.atime;
                    self.creation_time = ntfs.times.ctime;
                }

                ExtraField::ExtendedTimestamp(ts) => {
                    self.modification_time = ts.modification_time;
                    self.access_time = ts.access_time;
                    self.creation_time = ts.creation_time;
                }

                ExtraField::Aes(aes) => {
                    if self.compression_method != CompressionMethod::AES
                        || (!aes.check_crc32 && self.crc32 != 0)
                    {
                        return None;
                    }
                    let Some(enc @ EncryptionMethod::ZipCrypto) = &mut self.encryption else {
                        return None;
                    };

                    *enc = EncryptionMethod::Aes {
                        key_size: aes.key_size,
                        check_crc32: aes.check_crc32,
                    };
                    self.compression_method = aes.compression;
                }

                ExtraField::Invalid => return None,

                _ => (),
            }
        }

        if self.compression_method == CompressionMethod::AES {
            return None;
        }

        Some(())
    }

    /// Returns `true` if this file is encrypted.
    #[inline]
    pub fn is_encrypted(&self) -> bool {
        self.encryption.is_some()
    }

    /// Gets the name of this entry.
    #[inline]
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Gets the comment of this entry.
    #[inline]
    pub fn comment(&self) -> &str {
        &self.comment
    }

    /// Returns a reader with the content of the file.
    ///
    /// Unsupported compression methods and encrypted files will return an error.
    pub fn read<R: BufRead + Seek>(&self, reader: R) -> io::Result<impl Read + use<R>> {
        if self.encryption.is_some() {
            return Err(encrypted_file());
        }

        let reader = Decompressor::new(self.read_raw(reader)?, self.compression_method)?;
        Ok(self.content_checker(reader))
    }

    /// Returns a reader with the content of the file.
    ///
    /// Errors if the file is compressed, encrypted or corrupted. Is is not
    /// necessary to use `Metadata::content_checker` on the result.
    ///
    /// It is useful if you know that the file is stored as-is and you want to
    /// take advantage of the `BufReader` or the `Seek` implementation.
    pub fn read_stored<R: Read + Seek>(&self, mut reader: R) -> io::Result<io::Take<R>> {
        if self.encryption.is_some() {
            return Err(encrypted_file());
        }
        if self.compression_method != CompressionMethod::STORE {
            return Err(compressed());
        }

        // Check CRC beforehand. Length has already been checked.
        let mut checker = utils::Crc32Checker::new(self.read_raw(&mut reader)?, self.crc32);
        std::io::copy(&mut checker, &mut io::sink())?;

        self.read_raw(reader)
    }

    /// Returns a reader with the raw, uncompressed, content of the file.
    ///
    /// The uncompressed content should be checked with `content_checker`.
    pub fn read_raw<R: Read + Seek>(&self, mut reader: R) -> io::Result<io::Take<R>> {
        reader.seek(io::SeekFrom::Start(self.data_offset))?;
        Ok(reader.take(self.compressed_size))
    }

    /// Wraps a reader to check that its content matches this metadata.
    ///
    /// It is particularly  useful in combinaison of `read_raw`.
    #[inline]
    pub fn content_checker<R: Read>(&self, reader: R) -> impl Read + use<R> {
        utils::Crc32Checker::new(
            utils::LengthChecker::new(reader, self.uncompressed_size),
            self.crc32,
        )
    }

    /// Extracts this entry as if the root of the archive was at `root`.
    #[inline]
    pub fn extract<R: BufRead + Seek>(
        &self,
        reader: &mut R,
        root: impl AsRef<std::path::Path>,
    ) -> io::Result<()> {
        self._extract(reader, root.as_ref())
    }

    fn _extract(&self, reader: &mut dyn BufReadSeek, at: &std::path::Path) -> io::Result<()> {
        if !std::fs::metadata(at)?.is_dir() {
            return Err(io::Error::from(io::ErrorKind::NotFound));
        }

        let path = at.join(&*self.name);
        std::fs::create_dir_all(path.parent().unwrap())?;

        match self.file_type {
            FileType::File => {
                let mut f = std::fs::File::create_new(&path)?;
                io::copy(&mut self.read(reader)?, &mut f)?;

                if let Some(mod_time) = self.modification_time {
                    f.set_times(std::fs::FileTimes::new().set_modified(mod_time.to_std()))?;
                }
            }
            FileType::Directory => {
                std::fs::create_dir(path)?;
            }
            FileType::Symlink => {
                let target = io::read_to_string(self.read(reader)?)?;
                if !utils::validate_symlink(&self.name, &target) {
                    return Err(invalid("invalid symlink target"));
                }

                #[cfg(unix)]
                std::os::unix::fs::symlink(target, path)?;

                #[cfg(windows)]
                if target.ends_with('/') {
                    std::os::windows::fs::symlink_dir(target, path)?;
                } else {
                    std::os::windows::fs::symlink_file(target, path)?;
                }

                #[cfg(not(any(unix, windows)))]
                std::fs::write(path, target.as_bytes())?;
            }
        }

        Ok(())
    }
}

/// An open ZIP archive.
///
/// This type owns the reader. If you need something more flexible, use
/// [`RawArchive`] instead.
///
/// # Example
///
/// Print the name and content of each file in the archive:
///
/// ```no_run
/// let mut archive = eazip::Archive::open("example.zip")?;
///
/// for i in 0..archive.entries().len() {
///     let mut entry = archive.get_by_index(i).unwrap();
///     let name = entry.metadata().name();
///     let content = std::io::read_to_string(entry.read()?)?;
///
///     println!("{name}: {content}");
/// }
///
/// # Ok::<(), std::io::Error>(())
/// ```
#[derive(Debug)]
pub struct Archive<R> {
    inner: RawArchive,
    names: HashMap<Box<str>, usize>,
    reader: R,
}

impl Archive<io::BufReader<std::fs::File>> {
    /// Opens the given file as a ZIP archive.
    #[inline]
    pub fn open(path: impl AsRef<std::path::Path>) -> io::Result<Self> {
        Self::_open(path.as_ref())
    }

    fn _open(path: &std::path::Path) -> io::Result<Self> {
        Self::new(io::BufReader::new(std::fs::File::open(path)?))
    }
}

#[cfg(feature = "parallel")]
impl Archive<io::BufReader<sync_file::SyncFile>> {
    /// Opens the given file as a ZIP archive ready for parallel extract.
    #[inline]
    pub fn open_parallel(path: impl AsRef<std::path::Path>) -> io::Result<Self> {
        Self::_open(path.as_ref())
    }

    fn _open(path: &std::path::Path) -> io::Result<Self> {
        Self::new(io::BufReader::new(sync_file::SyncFile::open(path)?))
    }
}

impl<R: BufRead + Seek> Archive<R> {
    /// Opens a ZIP archive from a reader.
    ///
    /// This also perform many validation checks on the archive to make sure
    /// that is it well-formed and does not have dangerous or duplicated paths.
    /// The validity of file contents is checked lazily when reading them.
    ///
    /// The exact rules around validation are not part of semver guaranties and
    /// may change at every release.
    ///
    /// **The targets of symlinks are not checked yet here**, though they are
    /// through `extract` and `extract_parallel`.
    pub fn new(mut reader: R) -> io::Result<Self> {
        let inner = RawArchive::new(&mut reader)?;

        let names = inner
            .entries()
            .iter()
            .enumerate()
            .map(|(i, meta)| (meta.name().into(), i))
            .collect();

        Ok(Self {
            inner,
            names,
            reader,
        })
    }

    /// Gets the list of entries in the archive.
    #[inline]
    pub fn entries(&self) -> &[Metadata] {
        &self.inner.entries
    }

    /// Gets a file by its index.
    #[inline]
    pub fn get_by_index(&mut self, index: usize) -> Option<File<'_, R>> {
        let metadata = self.inner.entries().get(index)?;
        Some(File {
            metadata,
            reader: &mut self.reader,
        })
    }

    /// Gets a file by its name.
    pub fn get_by_name(&mut self, name: &str) -> Option<File<'_, R>> {
        let index = *self.names.get(name)?;
        self.get_by_index(index)
    }

    /// Gets the index of a file in [`Self::entries`] by its name.
    pub fn index_of(&self, name: &str) -> Option<usize> {
        self.names.get(name).copied()
    }

    /// Gets the comment of the archive.
    #[inline]
    pub fn commment(&self) -> &[u8] {
        &self.inner.comment
    }

    /// Extracts the archive to the given directory.
    ///
    /// The directory will be created if needed, but *not* its parent.
    #[inline]
    pub fn extract(&mut self, at: impl AsRef<std::path::Path>) -> io::Result<()> {
        self.inner.extract(&mut self.reader, at.as_ref())
    }

    /// Extracts the archive to the given directory in parallel.
    ///
    /// The directory will be created if needed, but *not* its parent.
    ///
    /// The reader should implement [`sync_file::ReadAt`], like [`io::Cursor`]
    /// or [`sync_file::SyncFile`].
    #[cfg(feature = "parallel")]
    #[inline]
    pub fn parallel_extract(&self, at: impl AsRef<std::path::Path>) -> io::Result<()>
    where
        R: sync_file::ReadAt + sync_file::Size + Sync,
    {
        self.inner.parallel_extract(&self.reader, at.as_ref())
    }

    /// Gets a shared reference to the underlying reader.
    #[inline]
    pub fn get_ref(&self) -> &R {
        &self.reader
    }

    /// Gets a mutable reference to the underlying reader.
    #[inline]
    pub fn get_mut(&mut self) -> &mut R {
        &mut self.reader
    }
}

/// A file in a ZIP archive.
#[derive(Debug)]
pub struct File<'a, R> {
    metadata: &'a Metadata,
    reader: &'a mut R,
}

impl<'a, R: BufRead + Seek> File<'a, R> {
    /// Gets the metadata of the file.
    ///
    /// The lifetime of the returned reference is bound to the `Archive`, so it
    /// can outlive `self`.
    #[inline]
    pub fn metadata(&self) -> &'a Metadata {
        self.metadata
    }

    /// Returns a reader with the content of the file.
    ///
    /// Unsupported compression methods will return an error.
    #[inline]
    pub fn read(&mut self) -> io::Result<impl Read + '_> {
        self.metadata.read(&mut *self.reader)
    }

    /// Returns a reader with the content of the file.
    ///
    /// Errors if the file is compressed, encrypted or corrupted. Is is not
    /// necessary to use `Metadata::content_checker` on the result.
    ///
    /// It is useful if you know that the file is stored as-is and you want to
    /// take advantage of the `BufReader` or the `Seek` implementation.
    pub fn read_stored(self) -> io::Result<io::Take<&'a mut R>> {
        self.metadata.read_stored(self.reader)
    }

    /// Returns a reader with the raw, compressed, content of the file.
    ///
    /// The uncompressed content should be checked with [`Metadata::content_checker`].
    #[inline]
    pub fn read_raw(&mut self) -> io::Result<io::Take<&mut R>> {
        self.metadata.read_raw(self.reader)
    }

    /// Consumes self, returning the underlying reader.
    ///
    /// This reader can be used with [`Metadata::read_raw`] to read the raw,
    /// compressed content of the file. The uncompressed content should then be
    /// checked with [`Metadata::content_checker`].
    pub fn into_reader(self) -> &'a mut R {
        self.reader
    }
}
