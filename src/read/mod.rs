use std::{
    collections::HashMap,
    fmt,
    io::{self, BufRead, Read, Seek},
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

    Ok(Metadata::from_central_header(
        header,
        file_name,
        extra_fields,
        comment,
    ))
}

fn find_central_directory_end_in_buffer(
    buffer_offset: u64,
    buffer: &[u8],
) -> io::Result<Option<(u64, types::EndOfCentralDirectory, Box<[u8]>)>> {
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
                "muli-file zip are not supported",
            ));
        }

        return Ok(Some((
            buffer_offset + i as u64,
            record,
            Box::from(&buffer[i + 22..]),
        )));
    }

    Ok(None)
}

#[cold]
fn not_a_zip() -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, "not a zip archive")
}

fn find_central_directory_end<R: Read + Seek>(
    reader: &mut R,
) -> io::Result<(u64, types::EndOfCentralDirectory, Box<[u8]>)> {
    let size = reader.seek(io::SeekFrom::End(0))?;

    if size < 22 {
        return Err(not_a_zip());
    }

    // Most zip files don't have a comment
    let buf_start = reader.seek(io::SeekFrom::End(-22))?;

    let record = reader.read_pod::<types::EndOfCentralDirectory>()?;

    if let Some(eocd) = find_central_directory_end_in_buffer(buf_start, record.as_bytes())? {
        return Ok(eocd);
    }

    // This one does
    let read_size = std::cmp::min(size, 22 + u16::MAX as u64);
    reader.seek(io::SeekFrom::Start(size - read_size))?;

    let mut buffer = vec![0; read_size as usize];
    reader.read_exact(&mut buffer)?;

    if let Some(eocd) = find_central_directory_end_in_buffer(buf_start, &buffer)? {
        return Ok(eocd);
    }

    Err(not_a_zip())
}

pub struct RawArchive {
    entries: Vec<Metadata>,
    central_directory_offset: u64,
    end_of_central_directory_offset: u64,
    comment: Box<[u8]>,
}

impl RawArchive {
    pub fn open<R: Read + Seek>(mut reader: R) -> io::Result<Self> {
        let (end_of_central_directory_offset, end_of_central_directory, comment) =
            find_central_directory_end(&mut reader)?;

        let central_directory_offset =
            end_of_central_directory.central_directory_offset.get() as u64;
        reader.seek(io::SeekFrom::Start(central_directory_offset))?;

        let len = end_of_central_directory.total_entries.get() as usize;
        let mut entries = Vec::with_capacity(len);

        for _ in 0..len {
            entries.push(parse_central_directory_header(&mut reader)?);
        }

        Ok(Self {
            entries,
            central_directory_offset,
            end_of_central_directory_offset,
            comment,
        })
    }

    pub fn entries(&self) -> &[Metadata] {
        &self.entries
    }

    pub fn central_directory_offset(&self) -> u64 {
        self.central_directory_offset
    }

    pub fn end_of_central_directory_offset(&self) -> u64 {
        self.end_of_central_directory_offset
    }

    pub fn comment(&self) -> &[u8] {
        &self.comment
    }
}

#[derive(Clone)]
pub struct Metadata {
    pub crc32: u32,
    flags: u16,
    header_offset: Option<u64>,
    pub compressed_size: u64,
    pub uncompressed_size: u64,
    pub compression_method: CompressionMethod,
    external_attributes: Option<u32>,

    pub modification_time: Option<Timestamp>,
    pub access_time: Option<Timestamp>,
    pub creation_time: Option<Timestamp>,

    raw_name: Box<[u8]>,
    name: Box<str>,

    raw_comment: Option<Box<[u8]>>,
    comment: Option<Box<str>>,

    pub extra_fields: ExtraFields,
}

impl Metadata {
    pub(crate) fn from_local_header(
        header: types::LocalFileHeader,
        file_name: Box<[u8]>,
        extra_fields: Box<[u8]>,
    ) -> Self {
        let flags = header.flags.get();
        let is_unicode = flags & (1 << 11) != 0;

        let name = if is_unicode {
            String::from_utf8_lossy(&file_name)
        } else {
            crate::cp437::convert(&file_name)
        };

        let mut meta = Self {
            crc32: header.crc32.get(),
            flags,
            header_offset: None,
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

        meta.parse_extra_fields();

        meta
    }

    pub(crate) fn from_central_header(
        header: types::CentralFileHeader,
        raw_name: Box<[u8]>,
        extra_fields: Box<[u8]>,
        raw_comment: Box<[u8]>,
    ) -> Self {
        let flags = header.flags.get();
        let is_unicode = flags & (1 << 11) != 0;

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
            header_offset: Some(header.local_header_offset.get() as u64),
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

        meta.parse_extra_fields();

        meta
    }

    fn parse_extra_fields(&mut self) {
        for field in self.extra_fields.iter() {
            match field {
                ExtraField::UnicodeComment(comment) => {
                    let Some(com) = self.raw_comment.as_deref() else {
                        debug_assert!(false);
                        continue;
                    };
                    if comment.header_name_crc32 == crc32fast::hash(com) {
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
    }

    pub fn is_encrypted(&self) -> bool {
        self.flags & (1 << 0) != 0
    }

    pub fn has_descriptor(&self) -> bool {
        self.flags & (1 << 3) != 0
    }

    pub fn is_dir(&self) -> bool {
        self.name().ends_with('/')
    }

    pub fn raw_name(&self) -> &[u8] {
        &self.raw_name
    }

    pub fn name(&self) -> &str {
        &self.name
    }

    pub fn raw_comment(&self) -> Option<&[u8]> {
        self.raw_comment.as_deref()
    }

    pub fn comment(&self) -> Option<&str> {
        self.comment.as_deref()
    }

    pub fn read_raw<R: Read + Seek>(&self, mut reader: R) -> io::Result<io::Take<R>> {
        reader.seek(io::SeekFrom::Start(self.header_offset.unwrap()))?;
        let header = reader.read_pod::<types::LocalFileHeader>()?;

        if { header.signature } != types::LocalFileHeader::SIGNATURE {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "invalid file signature",
            ));
        }

        if ({ header.compression_method.get() } != self.compression_method.0) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "inconsistent headers",
            ));
        }

        let extra_data =
            header.file_name_length.get() as i64 + header.extra_fields_length.get() as i64;
        reader.seek_relative(extra_data)?;

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
            .map(|(i, meta)| (meta.name().into(), i))
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
