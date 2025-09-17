use super::ReadExt;
use crate::{
    read::Metadata,
    types::{CentralFileHeader, LocalFileHeader},
};

use std::io::{self, BufRead, Read};

fn skip<R: BufRead>(r: R, amt: u64) -> io::Result<()> {
    let mut r = r.take(amt);

    loop {
        let n = r.fill_buf()?.len();
        if n == 0 {
            break;
        }
        r.consume(n);
    }

    if r.limit() != 0 {
        return Err(io::Error::new(
            io::ErrorKind::UnexpectedEof,
            "failed to fill whole buffer",
        ));
    }

    Ok(())
}

pub struct ZipArchive<R: BufRead> {
    reader: R,
    data_left: u64,
}

impl<R: BufRead> ZipArchive<R> {
    pub fn new(reader: R) -> Self {
        Self {
            reader,
            data_left: 0,
        }
    }

    pub fn next_file(&mut self) -> io::Result<Option<ZipFile<'_, R>>> {
        if self.data_left != 0 {
            skip(&mut self.reader, self.data_left)?;
            self.data_left = 0;
        }

        let header = self.reader.read_pod::<LocalFileHeader>()?;

        match header.signature {
            LocalFileHeader::SIGNATURE => (),
            CentralFileHeader::SIGNATURE => return Ok(None),
            _ => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "unknown signature",
                ));
            }
        }

        let file_name = self
            .reader
            .read_variable(header.file_name_length.get() as _)?;
        let extra_fields = self
            .reader
            .read_variable(header.extra_fields_length.get() as _)?;

        let metadata = Metadata::from_local_header(header, file_name, extra_fields)?;

        if (metadata.flags & 8) != 0 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "file length unavailable in local header",
            ));
        }

        Ok(Some(ZipFile {
            reader: self.reader.by_ref().take(metadata.compressed_size),
            data_left: &mut self.data_left,
            metadata,
        }))
    }
}

pub struct ZipFile<'a, R: BufRead> {
    reader: io::Take<&'a mut R>,
    data_left: &'a mut u64,
    metadata: Metadata,
}

impl<R: BufRead> ZipFile<'_, R> {
    pub fn metadata(&self) -> &Metadata {
        &self.metadata
    }

    pub fn raw_reader(&mut self) -> impl Read + '_ {
        &mut self.reader
    }

    pub fn reader(&mut self) -> io::Result<impl Read + '_> {
        self.metadata.read_from_raw(&mut self.reader)
    }
}

impl<R: BufRead> Drop for ZipFile<'_, R> {
    fn drop(&mut self) {
        *self.data_left = self.reader.limit();
    }
}
