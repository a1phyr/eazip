use std::io::{self, Read, Write};

pub struct Crc32Checker<R> {
    hasher: crc32fast::Hasher,
    expected: u32,
    reader: R,
}

impl<R> Crc32Checker<R> {
    #[inline]
    pub fn new(reader: R, expected: u32) -> Self {
        Self {
            hasher: crc32fast::Hasher::new(),
            expected,
            reader,
        }
    }
}

impl<R: Read> Read for Crc32Checker<R> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let n = self.reader.read(buf)?;

        if n == 0 && self.hasher.clone().finalize() != self.expected {
            return Err(crc32_check_fail());
        }

        self.hasher.update(&buf[..n]);

        Ok(n)
    }

    fn read_to_end(&mut self, buf: &mut Vec<u8>) -> io::Result<usize> {
        let start = buf.len();
        let res = self.reader.read_to_end(buf);

        self.hasher.update(&buf[start..]);

        if res.is_ok() && self.hasher.clone().finalize() != self.expected {
            return Err(crc32_check_fail());
        }

        res
    }

    fn read_to_string(&mut self, buf: &mut String) -> io::Result<usize> {
        let start = buf.len();
        let res = self.reader.read_to_string(buf);

        self.hasher.update(&buf.as_bytes()[start..]);

        if res.is_ok() && self.hasher.clone().finalize() != self.expected {
            return Err(crc32_check_fail());
        }

        res
    }
}

#[cold]
fn crc32_check_fail() -> io::Error {
    io::Error::new(
        io::ErrorKind::InvalidData,
        "invalid CRC32 check: data was corrupted",
    )
}

pub struct Crc32Writer<W> {
    hasher: crc32fast::Hasher,
    writer: W,
}

impl<W: Write> Crc32Writer<W> {
    #[inline]
    pub fn new(writer: W) -> Self {
        Self {
            hasher: crc32fast::Hasher::new(),
            writer,
        }
    }

    #[inline]
    pub fn into_inner(self) -> W {
        self.writer
    }

    #[inline]
    pub fn result(&self) -> u32 {
        self.hasher.clone().finalize()
    }
}

impl<W: Write> Write for Crc32Writer<W> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        let n = self.writer.write(buf)?;
        self.hasher.update(&buf[..n]);
        Ok(n)
    }

    #[inline]
    fn flush(&mut self) -> io::Result<()> {
        self.writer.flush()
    }
}
