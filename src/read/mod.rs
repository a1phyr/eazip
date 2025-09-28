use std::{
    collections::HashMap,
    fmt,
    io::{self, BufRead, Read, Seek},
    sync::atomic,
};

use crate::{
    CompressionMethod, Decompressor,
    types::{self, Pod},
    utils::{Crc32Checker, Timestamp, cp437},
};

mod extra_field;
pub mod stream;

use extra_field::{ExtraField, ExtraFields};

trait ReadExt: Read {
    fn read_variable(&mut self, size: usize) -> io::Result<Box<[u8]>> {
        let mut buf = vec![0; size].into_boxed_slice();
        self.read_exact(&mut buf)?;
        Ok(buf)
    }

    fn read_pod<T: types::Pod>(&mut self) -> io::Result<T> {
        let mut buf = T::zeroed();
        self.read_exact(buf.as_bytes_mut())?;
        Ok(buf)
    }
}

impl<R: Read + ?Sized> ReadExt for R {}

#[inline]
fn not_a_zip() -> io::Error {
    invalid("not a zip archive")
}

#[inline]
fn invalid_entry() -> io::Error {
    invalid("invalid entry")
}

fn invalid_zip() -> io::Error {
    invalid("invalid zip archive")
}

#[cold]
fn invalid(msg: &str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, msg)
}

#[cold]
fn multi_disk() -> io::Error {
    io::Error::new(
        io::ErrorKind::Unsupported,
        "multi-disk archives are not supported",
    )
}

fn validate_symlink(name: &str, target: &str) -> bool {
    if target.starts_with('/') || target.contains('\\') || (cfg!(windows) && target.contains(':')) {
        return false;
    }

    let mut depth = name.split('/').filter(|p| *p != ".").count() - 1;
    for part in target.split('/') {
        match part {
            "." => (),
            ".." => match depth.checked_sub(1) {
                Some(d) => depth = d,
                None => return false,
            },
            _ => depth += 1,
        }
    }

    true
}

trait ReadSeek: Read + Seek {}
impl<R: Read + Seek> ReadSeek for R {}

fn parse_central_directory_header(reader: &mut dyn ReadSeek) -> io::Result<Metadata> {
    let header = reader.read_pod::<types::CentralFileHeader>()?;

    let file_name = reader.read_variable(header.file_name_length.get() as _)?;
    let extra_fields = reader.read_variable(header.extra_fields_length.get() as _)?;
    let comment = reader.read_variable(header.file_comment_length.get() as _)?;

    Metadata::from_central_header(header, file_name, extra_fields, comment)
}

struct CentralDirectoryEnd {
    offset: u64,
    entries: u64,
    comment: Box<[u8]>,
}

impl CentralDirectoryEnd {
    fn find_in_buffer(
        buffer_offset: u64,
        buffer: &[u8],
    ) -> io::Result<Option<(u64, types::EndOfCentralDirectory, Box<[u8]>)>> {
        let signature = types::EndOfCentralDirectory::SIGNATURE.as_bytes();

        for i in memchr::memmem::rfind_iter(buffer, signature) {
            let mut buffer = &buffer[i..];
            let record: types::EndOfCentralDirectory = buffer.read_pod()?;

            if record.comment_length.get() as usize != buffer.len() {
                continue;
            }

            let offset = buffer_offset + i as u64;
            return Ok(Some((offset, record, Box::from(buffer))));
        }

        Ok(None)
    }

    fn find(
        reader: &mut dyn ReadSeek,
    ) -> io::Result<(u64, types::EndOfCentralDirectory, Box<[u8]>)> {
        let size = reader.seek(io::SeekFrom::End(0))?;

        if size < 22 {
            return Err(not_a_zip());
        }

        // Most zip files don't have a comment
        let pos = reader.seek(io::SeekFrom::End(-22))?;

        let record = reader.read_pod::<types::EndOfCentralDirectory>()?;

        if let Some(eocd) = Self::find_in_buffer(pos, record.as_bytes())? {
            return Ok(eocd);
        }

        // This one does
        let read_size = std::cmp::min(size, 22 + u16::MAX as u64);
        let pos = reader.seek(io::SeekFrom::Start(size - read_size))?;

        let mut buffer = vec![0; read_size as usize];
        reader.read_exact(&mut buffer)?;

        if let Some(eocd) = Self::find_in_buffer(pos, &buffer)? {
            return Ok(eocd);
        }

        Err(not_a_zip())
    }

    fn read64(reader: &mut dyn ReadSeek, offset: u64, comment: Box<[u8]>) -> io::Result<Self> {
        reader.seek(io::SeekFrom::Start(
            offset - size_of::<types::EndOfCentralDirectory64Locator>() as u64,
        ))?;
        let locator: types::EndOfCentralDirectory64Locator = reader.read_pod()?;

        if locator.signature != types::EndOfCentralDirectory64Locator::SIGNATURE {
            return Err(invalid_zip());
        }

        if locator.disk_with_central_directory.get() != 0 || locator.total_disks.get() > 1 {
            return Err(multi_disk());
        }

        reader.seek(io::SeekFrom::Start(
            locator.central_directory_64_offset.get(),
        ))?;
        let end_dir: types::EndOfCentralDirectory64 = reader.read_pod()?;

        // Yes, this is the third time that we do that stupid check
        if end_dir.disk_with_central_directory.get() != 0 || end_dir.disk_number.get() != 0 {
            return Err(multi_disk());
        }

        if { end_dir.total_entries } != { end_dir.entries_on_this_disk } {
            return Err(invalid_zip());
        }

        Ok(Self {
            offset: end_dir.central_directory_offset.get(),
            entries: end_dir.total_entries.get(),
            comment,
        })
    }

    fn read(reader: &mut dyn ReadSeek) -> io::Result<Self> {
        let (offset, dir_end, comment) = Self::find(reader)?;

        if dir_end.disk_number.get() != 0 || dir_end.disk_with_central_directory.get() != 0 {
            return Err(multi_disk());
        }

        if dir_end.total_entries != dir_end.entries_on_this_disk {
            return Err(invalid_zip());
        }

        if dir_end.total_entries.get() == u16::MAX
            || dir_end.central_directory_offset.get() == u32::MAX
        {
            // This is a Zip64
            return Self::read64(reader, offset, comment);
        }

        Ok(CentralDirectoryEnd {
            offset: dir_end.central_directory_offset.get() as _,
            entries: dir_end.total_entries.get() as _,
            comment,
        })
    }
}

pub struct RawArchive {
    entries: Vec<Metadata>,
    comment: Box<[u8]>,
}

impl RawArchive {
    pub fn new<R: Read + Seek>(reader: &mut R) -> io::Result<Self> {
        Self::_new(reader)
    }

    fn _new(reader: &mut dyn ReadSeek) -> io::Result<Self> {
        let central_dir = CentralDirectoryEnd::read(reader)?;

        reader.seek(io::SeekFrom::Start(central_dir.offset))?;

        let len = central_dir.entries as usize;
        let mut entries = Vec::with_capacity(len);

        for _ in 0..len {
            entries.push(parse_central_directory_header(reader)?);
        }

        Ok(Self {
            entries,
            comment: central_dir.comment,
        })
    }

    pub fn entries(&self) -> &[Metadata] {
        &self.entries
    }

    pub fn comment(&self) -> &[u8] {
        &self.comment
    }

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
            entry.extract(&mut *reader, at)?;
        }

        Ok(())
    }

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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum FileType {
    File,
    Directory,
    Symlink,
}

impl FileType {
    fn test(attr: Option<u32>, name: &str) -> Option<Self> {
        let has_attr = |flag| match attr {
            Some(attr) => attr & flag == flag,
            None => false,
        };

        let is_file = has_attr(10 << 28);
        let is_dir = has_attr(1 << 4) || has_attr(4 << 28) || name.ends_with('/');
        let is_symlink = has_attr(10 << 28);

        match (is_file, is_dir, is_symlink) {
            (_, false, false) => Some(FileType::File),
            (false, true, false) => Some(FileType::Directory),
            (false, false, true) => Some(FileType::Symlink),
            _ => None,
        }
    }
}

pub struct Metadata {
    flags: u16,
    header_offset: u64,
    data_offset: atomic::AtomicU64,

    pub compressed_size: u64,
    pub uncompressed_size: u64,
    pub compression_method: CompressionMethod,
    pub crc32: u32,
    external_attributes: Option<u32>,
    file_type: FileType,

    pub modification_time: Option<Timestamp>,
    pub access_time: Option<Timestamp>,
    pub creation_time: Option<Timestamp>,

    raw_name: Box<[u8]>,
    name: Box<str>,

    raw_comment: Option<Box<[u8]>>,
    comment: Option<Box<str>>,
}

impl Metadata {
    pub(crate) fn from_local_header(
        header: types::LocalFileHeader,
        header_offset: u64,
        file_name: Box<[u8]>,
        extra_fields: Box<[u8]>,
    ) -> io::Result<Self> {
        let flags = header.flags.get();
        let is_unicode = flags & (1 << 11) != 0;

        if { header.signature } != types::LocalFileHeader::SIGNATURE {
            return Err(invalid_entry());
        }

        let name = if is_unicode {
            String::from_utf8_lossy(&file_name)
        } else {
            cp437::convert(&file_name)
        };

        let file_type = FileType::test(None, &name).ok_or_else(invalid_entry)?;

        let mut meta = Self {
            crc32: header.crc32.get(),
            flags,
            header_offset,
            data_offset: atomic::AtomicU64::new(header_offset + header.total_size()),

            compressed_size: header.compressed_size.get() as u64,
            uncompressed_size: header.uncompressed_size.get() as u64,
            compression_method: CompressionMethod(header.compression_method.get()),
            external_attributes: None,
            file_type,

            modification_time: None,
            access_time: None,
            creation_time: None,

            name: name.into(),
            raw_name: file_name,

            comment: None,
            raw_comment: None,
        };

        meta.parse_extra_fields(ExtraFields(extra_fields))
            .ok_or_else(invalid_entry)?;

        Ok(meta)
    }

    pub(crate) fn from_central_header(
        header: types::CentralFileHeader,
        raw_name: Box<[u8]>,
        extra_fields: Box<[u8]>,
        raw_comment: Box<[u8]>,
    ) -> io::Result<Self> {
        let flags = header.flags.get();
        let is_unicode = flags & (1 << 11) != 0;

        if { header.signature } != types::CentralFileHeader::SIGNATURE
            || header.disk_number.get() != 0
        {
            return Err(invalid_entry());
        }

        let (name, comment) = if is_unicode {
            (
                String::from_utf8_lossy(&raw_name),
                String::from_utf8_lossy(&raw_comment),
            )
        } else {
            (cp437::convert(&raw_name), cp437::convert(&raw_comment))
        };

        let external_attributes = Some(header.external_attributes.get());
        let file_type = FileType::test(external_attributes, &name).ok_or_else(invalid_entry)?;

        let mut meta = Self {
            crc32: header.crc32.get(),
            flags,
            header_offset: header.local_header_offset.get() as u64,
            data_offset: atomic::AtomicU64::new(0),

            compressed_size: header.compressed_size.get() as u64,
            uncompressed_size: header.uncompressed_size.get() as u64,
            compression_method: CompressionMethod(header.compression_method.get()),
            external_attributes,
            file_type,

            modification_time: None,
            access_time: None,
            creation_time: None,

            name: name.into(),
            raw_name,

            comment: Some(comment.into()),
            raw_comment: Some(raw_comment),
        };

        meta.parse_extra_fields(ExtraFields(extra_fields))
            .ok_or_else(invalid_entry)?;

        Ok(meta)
    }

    fn parse_extra_fields(&mut self, extra_fields: ExtraFields) -> Option<()> {
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
                }
                ExtraField::UnicodeComment(comment) => {
                    let raw_comment = self.raw_comment.as_deref()?;
                    if comment.header_name_crc32 == crc32fast::hash(raw_comment) {
                        self.comment = Some(comment.comment.into());
                        self.raw_comment = Some(comment.comment.as_bytes().into());
                    }
                }

                ExtraField::UnicodeName(name) => {
                    if name.header_name_crc32 == crc32fast::hash(&self.raw_name) {
                        self.name = name.name.into();
                        self.raw_name = name.name.as_bytes().into();
                    }
                }

                ExtraField::Ntfs(ntfs) => {
                    if let Some(times) = ntfs.times {
                        self.modification_time = Some(times.mtime);
                        self.access_time = Some(times.atime);
                        self.creation_time = Some(times.ctime);
                    }
                }

                ExtraField::ExtendedTimestamp(ts) => {
                    self.modification_time = ts.modification_time;
                    self.access_time = ts.access_time;
                    self.creation_time = ts.creation_time;
                }

                _ => (),
            }
        }

        Some(())
    }

    pub fn is_encrypted(&self) -> bool {
        self.flags & (1 << 0) != 0
    }

    #[inline]
    pub fn is_dir(&self) -> bool {
        matches!(self.file_type, FileType::Directory)
    }

    #[inline]
    pub fn is_symlink(&self) -> bool {
        matches!(self.file_type, FileType::Symlink)
    }

    pub fn display_name(&self) -> &str {
        &self.name
    }

    pub fn safe_name(&self) -> Option<&str> {
        if self.name.starts_with('/')
            || self.name.contains('\\')
            || (cfg!(windows) && self.name.contains(':'))
        {
            return None;
        }

        if self.name.split('/').any(|part| part.contains("..")) {
            return None;
        }

        Some(&self.name)
    }

    pub fn raw_name(&self) -> &[u8] {
        &self.raw_name
    }

    pub fn comment(&self) -> Option<&str> {
        self.comment.as_deref()
    }

    pub fn raw_comment(&self) -> Option<&[u8]> {
        self.raw_comment.as_deref()
    }

    #[cold]
    fn set_data_offset(&self, reader: &mut dyn ReadSeek) -> io::Result<()> {
        reader.seek(io::SeekFrom::Start(self.header_offset))?;
        let header = reader.read_pod::<types::LocalFileHeader>()?;

        if { header.signature } != types::LocalFileHeader::SIGNATURE
            || header.compression_method.get() != self.compression_method.0
        {
            return Err(invalid_entry());
        }

        let extra_data = (header.file_name_length.get() + header.extra_fields_length.get()) as i64;
        reader.seek_relative(extra_data)?;

        self.data_offset.store(
            self.header_offset + header.total_size(),
            atomic::Ordering::Relaxed,
        );

        Ok(())
    }

    pub fn read_raw<R: Read + Seek>(&self, mut reader: R) -> io::Result<io::Take<R>> {
        // This check is racy but that's fine
        match self.data_offset.load(atomic::Ordering::Relaxed) {
            0 => self.set_data_offset(&mut reader)?,
            n => {
                reader.seek(io::SeekFrom::Start(n))?;
            }
        }

        Ok(reader.take(self.compressed_size))
    }

    pub fn read<R: BufRead + Seek>(&self, reader: R) -> io::Result<impl Read + use<R>> {
        let reader = Decompressor::new(self.read_raw(reader)?, self.compression_method)?;
        Ok(self.read_with_decompressor(reader))
    }

    fn read_from_raw<R: BufRead>(&self, reader: R) -> io::Result<impl Read + use<R>> {
        Ok(self.read_with_decompressor(Decompressor::new(reader, self.compression_method)?))
    }

    pub fn read_with_decompressor<R: Read>(&self, reader: R) -> impl Read + use<R> {
        Crc32Checker::new(
            LengthChecker {
                reader,
                expected: self.uncompressed_size,
            },
            self.crc32,
        )
    }

    pub fn extract<R: BufRead + Seek>(&self, reader: R, at: &std::path::Path) -> io::Result<()> {
        let name = self.safe_name().ok_or_else(|| invalid("invalid path"))?;
        let path = at.join(name);
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
                if !validate_symlink(name, &target) {
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

impl fmt::Debug for Metadata {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Metadata")
            .field("crc32", &self.crc32)
            .field("flags", &self.flags)
            .field("compressed_size", &self.compressed_size)
            .field("uncompressed_size", &self.uncompressed_size)
            .field("compression_method", &self.compression_method)
            .field("file_type", &self.file_type)
            .field("external_attributes", &self.external_attributes)
            .field("modification_time", &self.modification_time)
            .field("access_time", &self.access_time)
            .field("creation_time", &self.creation_time)
            .field("name", &self.name)
            .field("comment", &self.comment)
            .finish()
    }
}

pub struct ZipArchive<R> {
    inner: RawArchive,
    names: HashMap<Box<str>, usize>,
    reader: R,
}

impl ZipArchive<io::BufReader<std::fs::File>> {
    #[inline]
    pub fn open(path: impl AsRef<std::path::Path>) -> io::Result<Self> {
        Self::_open(path.as_ref())
    }

    fn _open(path: &std::path::Path) -> io::Result<Self> {
        Self::new(io::BufReader::new(std::fs::File::open(path)?))
    }
}

impl<R: BufRead + Seek> ZipArchive<R> {
    pub fn new(mut reader: R) -> io::Result<Self> {
        let inner = RawArchive::new(&mut reader)?;

        let names = inner
            .entries()
            .iter()
            .enumerate()
            .map(|(i, meta)| (meta.display_name().into(), i))
            .collect();

        Ok(Self {
            inner,
            names,
            reader,
        })
    }

    pub fn entries(&self) -> &[Metadata] {
        &self.inner.entries
    }

    pub fn get_by_index(&mut self, index: usize) -> Option<ZipFile<'_, R>> {
        let metadata = self.inner.entries().get(index)?;
        Some(ZipFile {
            metadata,
            reader: &mut self.reader,
        })
    }

    pub fn get_by_name(&mut self, name: &str) -> Option<ZipFile<'_, R>> {
        let index = *self.names.get(name)?;
        self.get_by_index(index)
    }

    pub fn commment(&self) -> &[u8] {
        &self.inner.comment
    }

    pub fn extract(&mut self, at: impl AsRef<std::path::Path>) -> io::Result<()> {
        self.inner.extract(&mut self.reader, at.as_ref())
    }

    #[cfg(feature = "parallel")]
    pub fn parallel_extract(&self, at: impl AsRef<std::path::Path>) -> io::Result<()>
    where
        R: sync_file::ReadAt + sync_file::Size + Sync,
    {
        self.inner.parallel_extract(&self.reader, at.as_ref())
    }
}

pub struct ZipFile<'a, R> {
    metadata: &'a Metadata,
    reader: &'a mut R,
}

impl<R: BufRead + Seek> ZipFile<'_, R> {
    pub fn metadata(&self) -> &Metadata {
        self.metadata
    }

    pub fn read_raw(&mut self) -> io::Result<io::Take<&mut R>> {
        self.metadata.read_raw(self.reader)
    }

    pub fn read(&mut self) -> io::Result<impl Read + '_> {
        self.metadata.read(&mut *self.reader)
    }
}

#[cold]
fn too_large() -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, "file is larger than expected")
}

pub struct LengthChecker<R> {
    expected: u64,
    reader: R,
}

impl<R: Read> Read for LengthChecker<R> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let n = self.reader.read(buf)?;
        self.expected = self.expected.checked_sub(n as u64).ok_or_else(too_large)?;
        Ok(n)
    }

    fn read_to_end(&mut self, buf: &mut Vec<u8>) -> io::Result<usize> {
        let size = self
            .expected
            .try_into()
            .map_err(|_| io::ErrorKind::OutOfMemory)?;
        buf.try_reserve(size)?;

        let initial_len = buf.len();
        buf.extend((0..size).map(|_| 0));
        self.read_exact(&mut buf[initial_len..])?;

        // Check that we really are at EOF
        self.read(&mut [0])?;

        Ok(size)
    }

    fn read_to_string(&mut self, buf: &mut String) -> io::Result<usize> {
        let size = self
            .expected
            .try_into()
            .map_err(|_| io::ErrorKind::OutOfMemory)?;
        buf.try_reserve(size)?;

        // Forward to the default implementation of `read_to_string`

        struct Reader<R>(R);
        impl<R: Read> Read for Reader<R> {
            fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
                self.0.read(buf)
            }
            fn read_to_end(&mut self, buf: &mut Vec<u8>) -> io::Result<usize> {
                self.0.read_to_end(buf)
            }
        }

        Reader(self).read_to_string(buf)
    }
}

#[test]
fn symlink_validation() {
    assert!(validate_symlink("a/b", "../c"));
    assert!(!validate_symlink("a/b", "../../c"));
    assert!(!validate_symlink("a/./././b", "../../c"));
    assert!(!validate_symlink("a/b", "/c"));
    #[cfg(windows)]
    assert!(!validate_symlink("a/b", "C:/e"));
}
