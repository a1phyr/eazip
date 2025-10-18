pub mod cp437;
mod crc32;

pub use crc32::{Crc32Checker, Crc32Writer};

use std::{fmt, io, time::SystemTime};

#[derive(Clone, Copy)]
pub struct Timestamp(pub u64);

impl Timestamp {
    pub fn now() -> Self {
        Self::from_std(SystemTime::now())
    }

    pub fn from_ntfs(time: u64) -> Self {
        /// Time in seconds between NT and Unix epochs
        const NT_EPOCH: u64 = 11_644_473_600;

        let time = time.saturating_sub(NT_EPOCH * 10_000_000);

        Self(time / 10_000_000)
    }

    pub fn from_unix(time: u64) -> Self {
        Self(time)
    }

    pub fn from_std(t: SystemTime) -> Self {
        Self(t.duration_since(SystemTime::UNIX_EPOCH).unwrap().as_secs())
    }

    pub fn to_std(self) -> SystemTime {
        SystemTime::UNIX_EPOCH + std::time::Duration::from_secs(self.0)
    }
}

impl fmt::Debug for Timestamp {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Timestamp({})", self.0)
    }
}

#[derive(Default)]
pub(crate) struct Counter<T> {
    pub amt: u64,
    pub inner: T,
}

impl<T> Counter<T> {
    pub const fn new(inner: T) -> Self {
        Self { amt: 0, inner }
    }

    pub(crate) fn advance(&mut self, amt: u64) -> io::Result<()>
    where
        T: io::Seek,
    {
        let Ok(offset) = amt.try_into() else { todo!() };

        self.amt = self.amt.checked_add(amt).unwrap();
        self.inner.seek_relative(offset)
    }
}

impl<R: io::Read> io::Read for Counter<R> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let n = self.inner.read(buf)?;
        self.amt += n as u64;
        Ok(n)
    }
}

impl<R: io::BufRead> io::BufRead for Counter<R> {
    fn fill_buf(&mut self) -> io::Result<&[u8]> {
        self.inner.fill_buf()
    }

    fn consume(&mut self, amount: usize) {
        self.amt += amount as u64;
    }
}

impl<W: io::Write> io::Write for Counter<W> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        let n = self.inner.write(buf)?;
        self.amt += n as u64;
        Ok(n)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.inner.flush()
    }
}

#[cold]
fn bad_length() -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, "unexpected file length")
}

pub(crate) struct LengthChecker<R> {
    expected: u64,
    reader: R,
}

impl<R> LengthChecker<R> {
    #[inline]
    pub fn new(reader: R, expected: u64) -> Self {
        Self { expected, reader }
    }
}

impl<R: io::Read> io::Read for LengthChecker<R> {
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
        impl<R: io::Read> io::Read for Reader<R> {
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
