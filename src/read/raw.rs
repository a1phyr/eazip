use super::{Metadata, ReadSeek};
use crate::types::{self, Pod};
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
        || eocd_offset.checked_add(end_dir.record_size.get()) != Some(locator_offset)
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

fn read_local_header(reader: &mut dyn ReadSeek, buf: &mut Vec<u8>) -> io::Result<Metadata> {
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

    Metadata::from_central_header(header, &file_name, &extra_fields, &comment)
        .ok_or_else(invalid_entry)
}

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
        entries.push(read_central_header(reader, &mut buf)?);
    }

    // Check that the local headers match the central ones and fill the missing data offset
    for entry in &mut entries {
        reader.seek(io::SeekFrom::Start(entry.header_offset))?;
        let local_entry = read_local_header(reader, &mut buf)?;

        if entry.compression_method != local_entry.compression_method {
            return Err(invalid_entry());
        }

        entry.data_offset = entry.header_offset + local_entry.data_offset;
    }

    Ok(entries)
}

pub(crate) fn read_archive(reader: &mut dyn ReadSeek) -> io::Result<(Vec<Metadata>, Box<[u8]>)> {
    let (offset, dir_end, comment) = find_eocd(reader)?;

    if dir_end.comment_length.get() as usize != comment.len() {
        return Err(invalid_zip());
    }

    let central_dir = read_eocd(reader, offset, dir_end)?;
    central_dir.validate_size().ok_or_else(invalid_zip)?;

    let entries = read_central_directory(reader, central_dir.offset, central_dir.entries)?;

    Ok((entries, comment))
}
