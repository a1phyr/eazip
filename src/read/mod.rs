use std::{
    collections::HashMap,
    io::{self, BufRead, Read, Seek},
};

use crate::{
    CompressionMethod, Decompressor,
    types::{self, Pod},
    utils::{Crc32Checker, Timestamp, cp437},
};

mod extra_field;
use extra_field::{ExtraField, ExtraFields};

trait ReadExt: Read {
    fn read_variable_fields<'a, const N: usize>(
        &mut self,
        sizes: [usize; N],
        buf: &'a mut Vec<u8>,
    ) -> io::Result<[&'a [u8]; N]> {
        let total = sizes.iter().sum();
        buf.resize(total, 0);
        self.read_exact(buf)?;

        let mut buf = &**buf;
        Ok(sizes.map(|size| {
            let (head, tail) = buf.split_at(size);
            buf = tail;
            head
        }))
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

fn read_central_directory(
    reader: &mut dyn ReadSeek,
    offset: u64,
    len: u64,
) -> io::Result<Vec<Metadata>> {
    // We can't support zip archives with more than ~2 billions entries on 32 bits
    // platforms, but these archives are probably broken anyway.
    let len = len.try_into().map_err(|_| invalid_zip())?;

    // FIXME: change to `try_with_capacity` once it is stable.
    let mut entries = Vec::new();
    entries.try_reserve_exact(len)?;

    reader.seek(io::SeekFrom::Start(offset))?;

    let mut buf = Vec::new();
    for _ in 0..len {
        entries.push(Metadata::read_central(reader, &mut buf)?);
    }

    // Check that the local headers match the central ones and fill the missing data offset
    for entry in &mut entries {
        reader.seek(io::SeekFrom::Start(entry.header_offset))?;
        let local_entry = Metadata::read_local(reader, &mut buf)?;

        if entry.compression_method != local_entry.compression_method {
            return Err(invalid_entry());
        }

        entry.data_offset = entry.header_offset + local_entry.data_offset;
    }

    Ok(entries)
}

struct CentralDirectory {
    offset: u64,
    size: u64,
    eocd_offset: u64,
    entries: u64,
}

type EocdData = (u64, types::EndOfCentralDirectory, Box<[u8]>);

impl CentralDirectory {
    fn find_end_in_buffer(buffer_offset: u64, buffer: &[u8]) -> io::Result<Option<EocdData>> {
        let signature = types::EndOfCentralDirectory::SIGNATURE.as_bytes();

        if let Some(i) = memchr::memmem::rfind(buffer, signature) {
            let mut buffer = &buffer[i..];
            let record: types::EndOfCentralDirectory = buffer.read_pod()?;
            let offset = buffer_offset + i as u64;
            return Ok(Some((offset, record, Box::from(buffer))));
        }

        Ok(None)
    }

    fn find_end(reader: &mut dyn ReadSeek) -> io::Result<EocdData> {
        let size = reader.seek(io::SeekFrom::End(0))?;

        if size < 22 {
            return Err(not_a_zip());
        }

        // Most zip files don't have a comment
        let pos = reader.seek(io::SeekFrom::End(-22))?;

        let record = reader.read_pod::<types::EndOfCentralDirectory>()?;

        if let Some(eocd) = Self::find_end_in_buffer(pos, record.as_bytes())? {
            return Ok(eocd);
        }

        // This one does
        let read_size = std::cmp::min(size, 22 + u16::MAX as u64);
        let pos = reader.seek(io::SeekFrom::Start(size - read_size))?;

        let mut buffer = vec![0; read_size as usize];
        reader.read_exact(&mut buffer)?;

        if let Some(eocd) = Self::find_end_in_buffer(pos, &buffer)? {
            return Ok(eocd);
        }

        Err(not_a_zip())
    }

    fn read_eocd64(reader: &mut dyn ReadSeek, offset: u64) -> io::Result<Self> {
        let locator_offset = offset
            .checked_sub(size_of::<types::EndOfCentralDirectory64Locator>() as u64)
            .ok_or_else(invalid_zip)?;
        reader.seek(io::SeekFrom::Start(locator_offset))?;
        let locator: types::EndOfCentralDirectory64Locator = reader.read_pod()?;
        let eocd_offset = locator.central_directory_64_offset.get();

        if locator.signature != types::EndOfCentralDirectory64Locator::SIGNATURE
            || eocd_offset > locator_offset
        {
            return Err(invalid_zip());
        }

        if locator.disk_with_central_directory.get() != 0 || locator.total_disks.get() > 1 {
            return Err(multi_disk());
        }

        reader.seek(io::SeekFrom::Start(eocd_offset))?;
        let end_dir: types::EndOfCentralDirectory64 = reader.read_pod()?;

        // Yes, this is the third time that we do that stupid check
        if end_dir.disk_with_central_directory.get() != 0 || end_dir.disk_number.get() != 0 {
            return Err(multi_disk());
        }

        if { end_dir.total_entries } != { end_dir.entries_on_this_disk }
            || eocd_offset.checked_add(end_dir.record_size.get()) != Some(locator_offset)
        {
            return Err(invalid_zip());
        }

        Ok(Self {
            offset: end_dir.central_directory_offset.get(),
            size: end_dir.central_directory_size.get(),
            eocd_offset,
            entries: end_dir.total_entries.get(),
        })
    }

    fn read_eocd(
        reader: &mut dyn ReadSeek,
        offset: u64,
        dir_end: types::EndOfCentralDirectory,
    ) -> io::Result<Self> {
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
            return Self::read_eocd64(reader, offset);
        }

        Ok(CentralDirectory {
            offset: dir_end.central_directory_offset.get() as _,
            size: dir_end.central_directory_size.get() as _,
            eocd_offset: offset,
            entries: dir_end.total_entries.get() as _,
        })
    }

    /// Validates that that the central directory has a decent size
    fn validate_size(&self) -> Option<()> {
        let min_size =
            (size_of::<types::CentralFileHeader>() as u64 + 1).checked_mul(self.entries)?;
        let expected_size = self.eocd_offset.checked_sub(self.offset)?;

        if self.size < min_size || self.size != expected_size {
            return None;
        }

        Some(())
    }

    fn parse(reader: &mut dyn ReadSeek) -> io::Result<(Vec<Metadata>, Box<[u8]>)> {
        let (offset, dir_end, comment) = Self::find_end(reader)?;

        if dir_end.comment_length.get() as usize != comment.len() {
            return Err(invalid_zip());
        }

        let central_dir = Self::read_eocd(reader, offset, dir_end)?;
        central_dir.validate_size().ok_or_else(invalid_zip)?;

        let entries = read_central_directory(reader, central_dir.offset, central_dir.entries)?;

        Ok((entries, comment))
    }
}

pub struct RawArchive {
    entries: Vec<Metadata>,
    comment: Box<[u8]>,
}

impl RawArchive {
    pub fn new<R: Read + Seek>(reader: &mut R) -> io::Result<Self> {
        let (entries, comment) = CentralDirectory::parse(reader)?;
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
}

impl Metadata {
    fn read_local(reader: &mut dyn Read, buf: &mut Vec<u8>) -> io::Result<Self> {
        let header = reader.read_pod::<types::LocalFileHeader>()?;

        let [file_name, extra_fields] = reader.read_variable_fields(
            [
                header.file_name_length.get() as _,
                header.extra_fields_length.get() as _,
            ],
            buf,
        )?;

        Metadata::from_local_header(header, file_name, extra_fields).ok_or_else(invalid_entry)
    }

    fn from_local_header(
        header: types::LocalFileHeader,
        file_name: &[u8],
        extra_fields: &[u8],
    ) -> Option<Self> {
        let flags = header.flags.get();
        let is_unicode = flags & (1 << 11) != 0;
        let is_encrypted = flags & (1 << 0) != 0;

        if { header.signature } != types::LocalFileHeader::SIGNATURE {
            return None;
        }

        let (name, name_crc) = check_string(file_name, is_unicode)?;

        let mut meta = Self {
            crc32: header.crc32.get(),
            is_encrypted,
            header_offset: 0,
            data_offset: header.total_size(),

            compressed_size: header.compressed_size.get() as u64,
            uncompressed_size: header.uncompressed_size.get() as u64,
            compression_method: CompressionMethod(header.compression_method.get()),
            file_type: FileType::File,

            modification_time: None,
            access_time: None,
            creation_time: None,

            name,
            comment: Box::default(),
        };

        meta.parse_extra_fields(ExtraFields(extra_fields), name_crc, None)?;

        Some(meta)
    }

    fn read_central(reader: &mut dyn ReadSeek, buf: &mut Vec<u8>) -> io::Result<Self> {
        let header = reader.read_pod::<types::CentralFileHeader>()?;

        let [file_name, extra_fields, comment] = reader.read_variable_fields(
            [
                header.file_name_length.get() as _,
                header.extra_fields_length.get() as _,
                header.file_comment_length.get() as _,
            ],
            buf,
        )?;

        Self::from_central_header(header, &file_name, &extra_fields, &comment)
            .ok_or_else(invalid_entry)
    }

    fn from_central_header(
        header: types::CentralFileHeader,
        file_name: &[u8],
        extra_fields: &[u8],
        comment: &[u8],
    ) -> Option<Self> {
        let flags = header.flags.get();
        let is_unicode = flags & (1 << 11) != 0;
        let is_encrypted = flags & (1 << 0) != 0;

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
        Ok(self.read_with_decompressor(reader))
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
fn bad_length() -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, "unexpected file length")
}

pub struct LengthChecker<R> {
    expected: u64,
    reader: R,
}

impl<R: Read> Read for LengthChecker<R> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let n = self.reader.read(buf)?;
        if n == 0 && self.expected != 0 {
            return Err(bad_length());
        }
        self.expected = self.expected.checked_sub(n as u64).ok_or_else(bad_length)?;
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
