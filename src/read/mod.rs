use std::{
    collections::HashMap,
    io::{self, BufRead, Read, Seek},
};

use crate::{
    CompressionMethod, Decompressor, types,
    utils::{Crc32Checker, LengthChecker, Timestamp, cp437},
};

mod extra_field;
mod raw;

use extra_field::{ExtraField, ExtraFields};

#[cold]
fn invalid(msg: &str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, msg)
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

pub struct RawArchive {
    entries: Vec<Metadata>,
    comment: Box<[u8]>,
}

impl RawArchive {
    pub fn new<R: Read + Seek>(reader: &mut R) -> io::Result<Self> {
        let (entries, comment) = raw::read_archive(reader)?;
        Ok(Self { entries, comment })
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
pub enum FileType {
    File,
    Directory,
    Symlink,
}

impl FileType {
    fn test(attr: u32, name: &str) -> Option<Self> {
        let dos_attr = attr as u16;
        let unix_mode = (attr >> 16) as u16;
        let unix_kind = unix_mode >> 12;

        let is_file = (dos_attr & (1 << 5)) != 0 || unix_kind == 8;
        let is_dir = (dos_attr & (1 << 4)) != 0 || unix_kind == 4 || name.ends_with('/');
        let is_symlink = unix_kind == 10;

        match (is_file, is_dir, is_symlink) {
            (_, false, false) => Some(FileType::File),
            (false, true, false) => Some(FileType::Directory),
            (false, false, true) => Some(FileType::Symlink),
            _ => None,
        }
    }
}

fn check_string(raw: &[u8], is_unicode: bool) -> Option<(Box<str>, Option<u32>)> {
    Some(if is_unicode {
        (str::from_utf8(raw).ok()?.into(), None)
    } else {
        let string = cp437::convert(raw);
        let crc = match string {
            std::borrow::Cow::Borrowed(_) => None,
            std::borrow::Cow::Owned(_) => Some(crc32fast::hash(raw)),
        };
        (string.into_owned().into_boxed_str(), crc)
    })
}

#[derive(Debug)]
pub struct Metadata {
    is_encrypted: bool,
    header_offset: u64,
    data_offset: u64,

    pub compressed_size: u64,
    pub uncompressed_size: u64,
    pub compression_method: CompressionMethod,
    pub crc32: u32,
    pub file_type: FileType,

    pub modification_time: Option<Timestamp>,
    pub access_time: Option<Timestamp>,
    pub creation_time: Option<Timestamp>,

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

        let (name, name_crc) = check_string(file_name, is_unicode)?;

        let mut meta = Self {
            crc32: header.crc32.get(),
            is_encrypted,
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

        let (comment, comment_crc) = check_string(comment, is_unicode)?;
        let (name, name_crc) = check_string(file_name, is_unicode)?;
        let external_attributes = header.external_attributes.get();
        let file_type = FileType::test(external_attributes, &name)?;

        let mut meta = Self {
            crc32: header.crc32.get(),
            is_encrypted,
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
                    let crc32 =
                        comment_crc.unwrap_or_else(|| crc32fast::hash(self.comment.as_bytes()));
                    if unicode.header_comment_crc32 != crc32 {
                        return None;
                    }
                    self.comment = unicode.comment.into();
                }

                ExtraField::UnicodeName(unicode) => {
                    let crc32 = name_crc.unwrap_or_else(|| crc32fast::hash(self.name.as_bytes()));
                    if unicode.header_name_crc32 != crc32 {
                        return None;
                    }
                    self.name = unicode.name.into();
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

                _ => (),
            }
        }

        Some(())
    }

    pub fn is_encrypted(&self) -> bool {
        self.is_encrypted
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

    pub fn comment(&self) -> &str {
        &self.comment
    }

    pub fn read_raw<R: Read + Seek>(&self, mut reader: R) -> io::Result<io::Take<R>> {
        reader.seek(io::SeekFrom::Start(self.data_offset))?;
        Ok(reader.take(self.compressed_size))
    }

    pub fn read<R: BufRead + Seek>(&self, reader: R) -> io::Result<impl Read + use<R>> {
        let reader = Decompressor::new(self.read_raw(reader)?, self.compression_method)?;
        Ok(self.content_checker(reader))
    }

    pub fn content_checker<R: Read>(&self, reader: R) -> impl Read + use<R> {
        Crc32Checker::new(
            LengthChecker::new(reader, self.uncompressed_size),
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

impl<'a, R: BufRead + Seek> ZipFile<'a, R> {
    pub fn metadata(&self) -> &'a Metadata {
        self.metadata
    }

    pub fn read_raw(&mut self) -> io::Result<io::Take<&mut R>> {
        self.metadata.read_raw(self.reader)
    }

    pub fn read(&mut self) -> io::Result<impl Read + '_> {
        self.metadata.read(&mut *self.reader)
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
