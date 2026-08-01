use super::{Metadata, ReadSeek};
use crate::{
    types::{self, Pod},
    utils::Counter,
};
use std::io;

#[inline]
fn not_a_zip() -> io::Error {
    super::invalid("not a zip archive")
}

#[inline]
fn invalid_entry() -> io::Error {
    super::invalid("invalid entry")
}

fn invalid_zip() -> io::Error {
    super::invalid("invalid zip archive")
}

#[cold]
fn multi_disk() -> io::Error {
    io::Error::new(
        io::ErrorKind::Unsupported,
        "multi-disk archives are not supported",
    )
}

/// Checks equality between the content of the options if both are `Some`.
#[inline]
fn opt_eq<T: Eq>(a: &Option<T>, b: &Option<T>) -> bool {
    match (a, b) {
        (Some(a), Some(b)) => a == b,
        _ => true,
    }
}

trait ReadExt: io::Read {
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

    fn read_pod<T: Pod>(&mut self) -> io::Result<T> {
        let mut buf = T::zeroed();
        self.read_exact(buf.as_bytes_mut())?;
        Ok(buf)
    }
}

impl<R: io::Read + ?Sized> ReadExt for R {}

pub struct CentralDirectory {
    offset: u64,
    size: u64,
    eocd_offset: u64,
    entries: u64,
}

impl CentralDirectory {
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
}

type EocdData = (u64, types::EndOfCentralDirectory, Box<[u8]>);

fn find_eocd_in_buffer(buffer_offset: u64, buffer: &[u8]) -> io::Result<Option<EocdData>> {
    let signature = types::EndOfCentralDirectory::SIGNATURE.as_bytes();

    if let Some(i) = memchr::memmem::rfind(buffer, signature) {
        let mut buffer = &buffer[i..];
        let record: types::EndOfCentralDirectory = buffer.read_pod()?;
        let offset = buffer_offset + i as u64;
        return Ok(Some((offset, record, Box::from(buffer))));
    }

    Ok(None)
}

fn find_eocd(reader: &mut dyn ReadSeek) -> io::Result<EocdData> {
    let size = reader.seek(io::SeekFrom::End(0))?;

    if size < 22 {
        return Err(not_a_zip());
    }

    // Most zip files don't have a comment
    let pos = reader.seek(io::SeekFrom::End(-22))?;

    let record = reader.read_pod::<types::EndOfCentralDirectory>()?;

    if let Some(eocd) = find_eocd_in_buffer(pos, record.as_bytes())? {
        return Ok(eocd);
    }

    // This one does
    let read_size = std::cmp::min(size, 22 + u16::MAX as u64);
    let pos = reader.seek(io::SeekFrom::Start(size - read_size))?;

    let mut buffer = vec![0; read_size as usize];
    reader.read_exact(&mut buffer)?;

    if let Some(eocd) = find_eocd_in_buffer(pos, &buffer)? {
        return Ok(eocd);
    }

    Err(not_a_zip())
}

fn read_eocd64(reader: &mut dyn ReadSeek, offset: u64) -> io::Result<CentralDirectory> {
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
        || eocd_offset.checked_add(end_dir.record_size.get() + 12) != Some(locator_offset)
    {
        return Err(invalid_zip());
    }

    Ok(CentralDirectory {
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
) -> io::Result<CentralDirectory> {
    if dir_end.disk_number.get() != 0 || dir_end.disk_with_central_directory.get() != 0 {
        return Err(multi_disk());
    }

    if dir_end.total_entries != dir_end.entries_on_this_disk {
        return Err(invalid_zip());
    }

    if dir_end.total_entries.get() == u16::MAX || dir_end.central_directory_offset.get() == u32::MAX
    {
        // This is a Zip64
        return read_eocd64(reader, offset);
    }

    Ok(CentralDirectory {
        offset: dir_end.central_directory_offset.get() as _,
        size: dir_end.central_directory_size.get() as _,
        eocd_offset: offset,
        entries: dir_end.total_entries.get() as _,
    })
}

fn read_local_header(
    reader: &mut Counter<&mut dyn ReadSeek>,
    buf: &mut Vec<u8>,
) -> io::Result<Metadata> {
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

fn read_central_header(reader: &mut dyn ReadSeek, buf: &mut Vec<u8>) -> io::Result<Metadata> {
    let header = reader.read_pod::<types::CentralFileHeader>()?;

    let [file_name, extra_fields, comment] = reader.read_variable_fields(
        [
            header.file_name_length.get() as _,
            header.extra_fields_length.get() as _,
            header.file_comment_length.get() as _,
        ],
        buf,
    )?;

    Metadata::from_central_header(header, file_name, extra_fields, comment)
        .ok_or_else(invalid_entry)
}

fn read_data_descriptor(
    reader: &mut Counter<&mut dyn ReadSeek>,
    meta: &mut Metadata,
) -> io::Result<()> {
    if !meta.is_streaming {
        return Ok(());
    }

    if meta.is_zip64 {
        let descriptor = reader.read_pod::<types::DataDescriptor64>()?;
        if descriptor.signature != types::DataDescriptor64::SIGNATURE {
            return Err(invalid_entry());
        }
        meta.compressed_size = descriptor.compressed_size.get();
        meta.uncompressed_size = descriptor.uncompressed_size.get();
        meta.crc32 = descriptor.crc32.get();
    } else {
        let descriptor = reader.read_pod::<types::DataDescriptor32>()?;
        if descriptor.signature != types::DataDescriptor32::SIGNATURE {
            return Err(invalid_entry());
        }
        meta.compressed_size = descriptor.compressed_size.get() as _;
        meta.uncompressed_size = descriptor.uncompressed_size.get() as _;
        meta.crc32 = descriptor.crc32.get();
    }

    Ok(())
}

fn check_local_entry(
    reader: &mut Counter<&mut dyn ReadSeek>,
    entry: &mut Metadata,
    buf: &mut Vec<u8>,
) -> io::Result<()> {
    let mut local_entry = read_local_header(reader, buf)?;
    entry.data_offset = reader.amt;

    if entry.file_type.is_directory() && entry.uncompressed_size != 0 {
        // Directories should always be empty
        return Err(invalid_entry());
    } else {
        // Skip the compressed file
        reader.advance(entry.compressed_size as _)?;
    }

    // Read the data descriptor if needed
    read_data_descriptor(reader, &mut local_entry)?;

    // Now we can check that both header are consistent
    if entry.compression_method != local_entry.compression_method
        || entry.name != local_entry.name
        || entry.compressed_size != local_entry.compressed_size
        || entry.uncompressed_size != local_entry.uncompressed_size
        || entry.crc32 != local_entry.crc32
        || entry.flags != local_entry.flags
        || !opt_eq(&entry.modification_time, &local_entry.modification_time)
        || !opt_eq(&entry.access_time, &local_entry.access_time)
        || !opt_eq(&entry.creation_time, &local_entry.creation_time)
    {
        return Err(invalid_entry());
    }

    // Bonus consistency check
    if entry.compression_method == crate::CompressionMethod::STORE
        && entry.compressed_size != entry.uncompressed_size
        && entry.encryption.is_none()
    {
        return Err(invalid_entry());
    }

    // Extended timestamp entries usually stores creation and access timestamps
    // in local headers only
    if entry.creation_time.is_none() {
        entry.creation_time = local_entry.creation_time;
    }
    if entry.access_time.is_none() {
        entry.access_time = local_entry.access_time;
    }

    Ok(())
}

fn read_central_directory(
    reader: &mut dyn ReadSeek,
    offset: u64,
    len: u64,
) -> io::Result<Vec<Metadata>> {
    if len == 0 {
        return Ok(Vec::new());
    }

    // We can't support zip archives with more than ~2 billions entries on 32 bits
    // platforms, but these archives are probably broken anyway.
    let len = len.try_into().map_err(|_| invalid_zip())?;

    // FIXME: change to `try_with_capacity` once it is stable.
    let mut entries = Vec::new();
    entries.try_reserve(len)?;

    reader.seek(io::SeekFrom::Start(offset))?;
    let mut buf = Vec::new();
    for _ in 0..len {
        entries.push(read_central_header(reader, &mut buf)?);
    }

    // Check that the local headers match the central ones and fill the missing data offset.
    // We expect local entries to be in order. Although this is not compulsory by the spec (but at
    // this point you have probably understood that very few things are), this is the "normal"
    // behavior, and deviations from it are only used by malicious attempts to do confusion attacks
    // or zip bombs.
    let first_offset = entries.first().unwrap().header_offset;
    reader.seek(io::SeekFrom::Start(first_offset))?;

    let mut reader = crate::utils::Counter {
        inner: reader,
        amt: first_offset,
    };

    for entry in &mut entries {
        check_local_entry(&mut reader, entry, &mut buf)?;
    }

    if reader.amt != offset {
        return Err(invalid_zip());
    }

    Ok(entries)
}

pub(crate) fn read_archive(reader: &mut dyn ReadSeek) -> io::Result<super::RawArchive> {
    let (offset, dir_end, comment) = find_eocd(reader)?;

    if dir_end.comment_length.get() as usize != comment.len() {
        return Err(invalid_zip());
    }

    let central_dir = read_eocd(reader, offset, dir_end)?;
    central_dir.validate_size().ok_or_else(invalid_zip)?;

    let entries = read_central_directory(reader, central_dir.offset, central_dir.entries)?;

    let mut names = crate::utils::NameTable::with_capacity(entries.len());
    for i in 0..entries.iter().len() {
        if !names.insert(i, |i| entries[*i].stripped_name()) {
            return Err(super::invalid("duplicated name in archive"));
        }
    }

    Ok(super::RawArchive {
        entries,
        names,
        comment,
    })
}
