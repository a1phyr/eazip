use std::{
    collections::HashMap,
    fmt,
    io::{self, BufRead, Read, Seek},
    sync::atomic,
};

use crate::{
    CompressionMethod, Decompressor,
    crc32::Crc32Checker,
    types::{self, Pod},
    utils::Timestamp,
};

pub mod extra_field;
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

impl<R: Read> ReadExt for R {}

fn parse_central_directory_header<R: Read>(reader: &mut R) -> io::Result<Metadata> {
    let header = reader.read_pod::<types::CentralFileHeader>()?;

    let file_name = reader.read_variable(header.file_name_length.get() as _)?;
    let extra_fields = reader.read_variable(header.extra_fields_length.get() as _)?;
    let comment = reader.read_variable(header.file_comment_length.get() as _)?;

    Metadata::from_central_header(header, file_name, extra_fields, comment)
}

fn find_central_directory_end_in_buffer(
    buffer: &[u8],
) -> io::Result<Option<(types::EndOfCentralDirectory, Box<[u8]>)>> {
    let signature = types::EndOfCentralDirectory::SIGNATURE.as_bytes();

    for i in memchr::memmem::rfind_iter(buffer, signature) {
        let record: types::EndOfCentralDirectory = (&buffer[i..]).read_pod()?;

        let expected_len = (buffer.len() - (i + 22)) as u16;

        if record.comment_length.get() != expected_len {
            continue;
        }

        if record.disk_number.get() != 0 || record.disk_with_central_directory.get() != 0 {
            return Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "multi-file zip are not supported",
            ));
        }

        if record.total_entries != record.entries_on_this_disk {
            return Err(invalid_zip());
        }

        return Ok(Some((record, Box::from(&buffer[i + 22..]))));
    }

    Ok(None)
}

#[cold]
fn not_a_zip() -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, "not a zip archive")
}

#[cold]
fn invalid_entry() -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, "invalid entry")
}

#[cold]
fn invalid_zip() -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, "invalid zip archive")
}

fn find_central_directory_end<R: Read + Seek>(
    reader: &mut R,
) -> io::Result<(types::EndOfCentralDirectory, Box<[u8]>)> {
    let size = reader.seek(io::SeekFrom::End(0))?;

    if size < 22 {
        return Err(not_a_zip());
    }

    // Most zip files don't have a comment
    reader.seek(io::SeekFrom::End(-22))?;

    let record = reader.read_pod::<types::EndOfCentralDirectory>()?;

    if let Some(eocd) = find_central_directory_end_in_buffer(record.as_bytes())? {
        return Ok(eocd);
    }

    // This one does
    let read_size = std::cmp::min(size, 22 + u16::MAX as u64);
    reader.seek(io::SeekFrom::Start(size - read_size))?;

    let mut buffer = vec![0; read_size as usize];
    reader.read_exact(&mut buffer)?;

    if let Some(eocd) = find_central_directory_end_in_buffer(&buffer)? {
        return Ok(eocd);
    }

    Err(not_a_zip())
}

pub struct RawArchive {
    entries: Vec<Metadata>,
    comment: Box<[u8]>,
}

impl RawArchive {
    pub fn open<R: Read + Seek>(mut reader: R) -> io::Result<Self> {
        let (end_of_central_directory, comment) = find_central_directory_end(&mut reader)?;

        let central_directory_offset =
            end_of_central_directory.central_directory_offset.get() as u64;
        reader.seek(io::SeekFrom::Start(central_directory_offset))?;

        let len = end_of_central_directory.total_entries.get() as usize;
        let mut entries = Vec::with_capacity(len);

        for _ in 0..len {
            entries.push(parse_central_directory_header(&mut reader)?);
        }

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
        mut reader: R,
        at: &std::path::Path,
    ) -> io::Result<()> {
        match std::fs::create_dir(at) {
            Ok(()) => (),
            Err(err) if err.kind() == io::ErrorKind::AlreadyExists => (),
            Err(err) => return Err(err),
        };

        for entry in &self.entries {
            entry.extract(&mut reader, at)?;
        }

        Ok(())
    }

    #[cfg(feature = "parallel")]
    pub fn parallel_extract<R: sync_file::ReadAt + sync_file::Size + Sync>(
        &self,
        reader: R,
        at: &std::path::Path,
    ) -> io::Result<()> {
        use rayon::prelude::*;

        match std::fs::create_dir(at) {
            Ok(()) => (),
            Err(err) if err.kind() == io::ErrorKind::AlreadyExists => (),
            Err(err) => return Err(err),
        };

        self.entries.par_iter().try_for_each(|entry| {
            let reader = io::BufReader::new(sync_file::Adapter::new(&reader));
            entry.extract(reader, at)
        })?;

        Ok(())
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

    pub modification_time: Option<Timestamp>,
    pub access_time: Option<Timestamp>,
    pub creation_time: Option<Timestamp>,

    raw_name: Box<[u8]>,
    name: Box<str>,

    raw_comment: Option<Box<[u8]>>,
    comment: Option<Box<str>>,

    extra_fields: ExtraFields,
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
            crate::cp437::convert(&file_name)
        };

        let mut meta = Self {
            crc32: header.crc32.get(),
            flags,
            header_offset,
            data_offset: atomic::AtomicU64::new(header_offset + header.total_size()),

            compressed_size: header.compressed_size.get() as u64,
            uncompressed_size: header.uncompressed_size.get() as u64,
            compression_method: CompressionMethod(header.compression_method.get()),
            external_attributes: None,

            modification_time: None,
            access_time: None,
            creation_time: None,

            name: name.into(),
            raw_name: file_name,

            comment: None,
            raw_comment: None,

            extra_fields: ExtraFields(extra_fields),
        };

        meta.parse_extra_fields().ok_or_else(invalid_entry)?;

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
            (
                crate::cp437::convert(&raw_name),
                crate::cp437::convert(&raw_comment),
            )
        };

        let mut meta = Self {
            crc32: header.crc32.get(),
            flags,
            header_offset: header.local_header_offset.get() as u64,
            data_offset: atomic::AtomicU64::new(0),

            compressed_size: header.compressed_size.get() as u64,
            uncompressed_size: header.uncompressed_size.get() as u64,
            compression_method: CompressionMethod(header.compression_method.get()),
            external_attributes: Some(header.external_attributes.get()),

            modification_time: None,
            access_time: None,
            creation_time: None,

            name: name.into(),
            raw_name,

            comment: Some(comment.into()),
            raw_comment: Some(raw_comment),

            extra_fields: ExtraFields(extra_fields),
        };

        meta.parse_extra_fields().ok_or_else(invalid_entry)?;

        Ok(meta)
    }

    fn parse_extra_fields(&mut self) -> Option<()> {
        for field in self.extra_fields.iter() {
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

    pub fn is_dir(&self) -> bool {
        self.name.ends_with('/')
    }

    pub fn display_name(&self) -> &str {
        &self.name
    }

    pub fn safe_name(&self) -> Option<&str> {
        if std::path::Path::new(&*self.name).has_root() || self.name.contains(['\\']) {
            return None;
        }

        let mut depth = 0u32;
        for part in self.name.split('/') {
            match part {
                "." => (),
                ".." => depth = depth.checked_sub(1)?,
                _ => depth += 1,
            }
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

    pub fn extra_fields(&self) -> extra_field::ExtraFieldIterator<'_> {
        self.extra_fields.iter()
    }

    #[cold]
    pub fn set_data_offset<R: Read + Seek>(&self, reader: &mut R) -> io::Result<()> {
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

    pub fn read_from_raw<R: BufRead>(&self, reader: R) -> io::Result<impl Read + use<R>> {
        Ok(ZipFileReader {
            reader: Crc32Checker::new(
                Decompressor::new(reader, self.compression_method)?,
                self.crc32,
            ),
            uncompressed_size: self.uncompressed_size,
        })
    }

    pub fn read<R: BufRead + Seek>(&self, reader: R) -> io::Result<impl Read + use<R>> {
        self.read_from_raw(self.read_raw(reader)?)
    }

    pub fn extract<R: BufRead + Seek>(&self, reader: R, at: &std::path::Path) -> io::Result<()> {
        let path = at.join(self.safe_name().ok_or_else(
            #[cold]
            || io::Error::new(io::ErrorKind::InvalidData, "invalid path in archive"),
        )?);

        if self.is_dir() {
            std::fs::create_dir_all(path)?;
        } else {
            std::fs::create_dir_all(path.parent().unwrap())?;
            let mut f = std::fs::File::create_new(&path)?;
            io::copy(&mut self.read(reader)?, &mut f)?;
        };

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
            .field("external_attributes", &self.external_attributes)
            .field("modification_time", &self.modification_time)
            .field("access_time", &self.access_time)
            .field("creation_time", &self.creation_time)
            .field("name", &self.name)
            .field("comment", &self.comment)
            .field("extra_fields", &self.extra_fields)
            .finish()
    }
}

pub struct ZipArchive<R> {
    inner: RawArchive,
    names: HashMap<Box<str>, usize>,
    reader: R,
}

impl<R: BufRead + Seek> ZipArchive<R> {
    pub fn new(mut reader: R) -> io::Result<Self> {
        let inner = RawArchive::open(&mut reader)?;

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

struct ZipFileReader<R> {
    reader: Crc32Checker<Decompressor<R>>,
    uncompressed_size: u64,
}

impl<R: BufRead> Read for ZipFileReader<R> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let n = self.reader.read(buf)?;
        self.uncompressed_size = self.uncompressed_size.saturating_sub(n as u64);
        Ok(n)
    }

    fn read_to_end(&mut self, buf: &mut Vec<u8>) -> io::Result<usize> {
        let size = self
            .uncompressed_size
            .try_into()
            .map_err(|_| io::ErrorKind::OutOfMemory)?;
        buf.try_reserve(size)?;
        self.reader.read_to_end(buf)
    }

    fn read_to_string(&mut self, buf: &mut String) -> io::Result<usize> {
        let size = self
            .uncompressed_size
            .try_into()
            .map_err(|_| io::ErrorKind::OutOfMemory)?;
        buf.try_reserve(size)?;
        self.reader.read_to_string(buf)
    }
}
