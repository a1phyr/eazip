use std::{
    borrow::Cow,
    collections::HashMap,
    fmt,
    io::{self, BufRead, Read, Seek},
};

use crate::{
    CompressionMethod, Decompressor,
    crc32::Crc32Checker,
    types::{self, Pod},
};

mod extra_field;
pub mod stream;

pub use extra_field::*;

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
    pub flags: u16,
    pub header_offset: Option<u64>,
    pub compressed_size: u64,
    pub uncompressed_size: u64,
    pub compression_method: CompressionMethod,
    pub external_attributes: Option<u32>,

    pub file_name: Box<[u8]>,
    pub extra_fields: ExtraFields,
    pub comment: Option<Box<[u8]>>,
}

impl Metadata {
    pub(crate) fn from_local_header(
        header: types::LocalFileHeader,
        file_name: Box<[u8]>,
        extra_fields: Box<[u8]>,
    ) -> Self {
        Self {
            crc32: header.crc32.get(),
            flags: header.flags.get(),
            header_offset: None,
            compressed_size: header.compressed_size.get() as u64,
            uncompressed_size: header.uncompressed_size.get() as u64,
            compression_method: CompressionMethod(header.compression_method.get()),
            external_attributes: None,

            file_name,
            extra_fields: ExtraFields(extra_fields),
            comment: None,
        }
    }

    pub(crate) fn from_central_header(
        header: types::CentralFileHeader,
        file_name: Box<[u8]>,
        extra_fields: Box<[u8]>,
        comment: Box<[u8]>,
    ) -> Self {
        Self {
            crc32: header.crc32.get(),
            flags: header.flags.get(),
            header_offset: Some(header.local_header_offset.get() as u64),
            compressed_size: header.compressed_size.get() as u64,
            uncompressed_size: header.uncompressed_size.get() as u64,
            compression_method: CompressionMethod(header.compression_method.get()),
            external_attributes: Some(header.external_attributes.get()),

            file_name,
            extra_fields: ExtraFields(extra_fields),
            comment: Some(comment),
        }
    }

    pub fn is_encrypted(&self) -> bool {
        self.flags & (1 << 0) != 0
    }

    pub fn has_descriptor(&self) -> bool {
        self.flags & (1 << 3) != 0
    }

    fn uses_utf8(&self) -> bool {
        self.flags & (1 << 11) != 0
    }

    pub fn path(&self) -> Cow<str> {
        if self.uses_utf8() {
            String::from_utf8_lossy(&self.file_name)
        } else {
            crate::cp437::convert(&self.file_name)
        }
    }

    pub fn read_raw<R: Read + Seek>(&self, mut reader: R) -> io::Result<io::Take<R>> {
        reader.seek(io::SeekFrom::Start(self.header_offset.unwrap()))?;
        let header = reader.read_pod::<types::LocalFileHeader>()?;

        let extra_data = header.file_name_len.get() as i64 + header.extra_fields_len.get() as i64;
        reader.seek_relative(extra_data)?;

        Ok(reader.take(self.compressed_size))
    }

    pub fn read<R: BufRead + Seek>(&self, reader: R) -> io::Result<impl Read + use<R>> {
        let raw = self.read_raw(reader)?;

        Ok(Crc32Checker::new(
            Decompressor::new(raw, self.compression_method)?,
            self.crc32,
        ))
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
            .field("name", &String::from_utf8_lossy(&self.file_name))
            .field("extra_fields", &self.extra_fields)
            .finish()
    }
}

pub struct ZipArchive<R> {
    inner: RawArchive,
    paths: HashMap<Box<str>, usize>,
    reader: R,
}

impl<R: BufRead + Seek> ZipArchive<R> {
    pub fn new(mut reader: R) -> io::Result<Self> {
        let inner = RawArchive::open(&mut reader)?;

        let paths = inner
            .entries()
            .iter()
            .enumerate()
            .map(|(i, meta)| (meta.path().into(), i))
            .collect();

        Ok(Self {
            inner,
            paths,
            reader,
        })
    }

    pub fn get_by_index(&mut self, index: usize) -> Option<ZipFile<'_, R>> {
        let metadata = self.inner.entries().get(index)?;
        Some(ZipFile {
            metadata,
            reader: &mut self.reader,
        })
    }

    pub fn get_by_name(&mut self, path: &str) -> Option<ZipFile<'_, R>> {
        let index = *self.paths.get(path)?;
        self.get_by_index(index)
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
