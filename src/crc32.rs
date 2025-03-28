use std::io::{self, Read};

pub struct Crc32Checker<R> {
    hasher: crc32fast::Hasher,
    expected: u32,
    reader: R,
}

impl<R> Crc32Checker<R> {
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
