pub mod cp437;
mod crc32;

pub use crc32::{Crc32Checker, Crc32Writer};

use std::{fmt, io, time::SystemTime};

#[must_use]
pub(crate) fn validate_name(name: &str) -> Option<Box<str>> {
    if name.starts_with('/')
        || name.contains('\\')
        || name.contains('\0')
        || (cfg!(windows) && name.contains(':'))
    {
        return None;
    }

    let mut dst = String::with_capacity(name.len());
    for part in name.split_inclusive('/') {
        match part {
            // Forbid parent parts as they have weird interactions with symlinks
            "." | ".." | "../" => return None,
            "/" | "./" => (),
            _ => dst.push_str(part),
        }
    }

    if dst.is_empty() {
        return None;
    }

    Some(dst.into_boxed_str())
}

pub(crate) fn validate_symlink(name: &str, target: &str) -> bool {
    if target.starts_with('/')
        || target.contains('\\')
        || target.contains('\0')
        || (cfg!(windows) && target.contains(':'))
    {
        return false;
    }

    let mut depth = Some(name.split('/').count() - 1);

    for part in target.split('/') {
        match part {
            "" | "." => (),
            ".." => match depth.and_then(|d| d.checked_sub(1)) {
                Some(d) => depth = Some(d),
                None => return false,
            },
            // Once the link goes down, forbid it going up again (eg "a/../b")
            // to prevent it using another link as a "trampoline" to escape.
            _ => depth = None,
        }
    }

    true
}

/// The type of an entry in an archive.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FileType {
    /// A file.
    File,
    /// A directory.
    Directory,
    /// A symlink.
    Symlink,
}

impl FileType {
    /// Returns whether `self` is `FileType::File`.
    #[inline]
    pub fn is_file(&self) -> bool {
        matches!(self, FileType::File)
    }

    /// Returns whether `self` is `FileType::Directory`.
    #[inline]
    pub fn is_directory(&self) -> bool {
        matches!(self, FileType::Directory)
    }

    /// Returns whether `self` is `FileType::Symlink`.
    #[inline]
    pub fn is_symlink(&self) -> bool {
        matches!(self, FileType::Symlink)
    }
}

/// A timestamp for an entry in an archive.
///
/// It is stored as a 64-bits UNIX timestamp, and therefore has second precision.
#[derive(Default, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Timestamp(u64);

impl Timestamp {
    /// Returns the timestamp corresponding to "now".
    #[inline]
    pub fn now() -> Self {
        Self::from_std(SystemTime::now())
    }

    /// Returns a `Timestamp` from a NTFS timestamp.
    ///
    /// Sub-second precision is lost in the process.
    pub fn from_ntfs(time: u64) -> Self {
        /// Time in seconds between NT and Unix epochs
        const NT_EPOCH: u64 = 11_644_473_600;

        let time = time.saturating_sub(NT_EPOCH * 10_000_000);

        Self(time / 10_000_000)
    }

    /// Returns a `Timestamp` from an UNIX timestamp.
    #[inline]
    pub fn from_unix(time: u64) -> Self {
        Self(time)
    }

    /// Returns a `Timestamp` from a [`SystemTime`].
    ///
    /// Sub-second precision is lost in the process.
    #[inline]
    pub fn from_std(t: SystemTime) -> Self {
        Self(t.duration_since(SystemTime::UNIX_EPOCH).unwrap().as_secs())
    }

    /// Converts this timestamp to an UNIX timestamp.
    #[inline]
    pub fn to_unix(self) -> u64 {
        self.0
    }

    /// Converts this timestamp to a [`SystemTime`].
    #[inline]
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
    #[inline]
    pub const fn new(inner: T) -> Self {
        Self { amt: 0, inner }
    }

    pub(crate) fn advance(&mut self, amt: u64) -> io::Result<()>
    where
        T: io::Seek,
    {
        #[cold]
        fn out_of_range() -> io::Error {
            io::Error::new(io::ErrorKind::InvalidInput, "seek out of range")
        }

        let offset = amt.try_into().map_err(|_| out_of_range())?;
        self.amt = self.amt.checked_add(amt).ok_or_else(out_of_range)?;
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
    #[inline]
    fn fill_buf(&mut self) -> io::Result<&[u8]> {
        self.inner.fill_buf()
    }

    #[inline]
    fn consume(&mut self, amount: usize) {
        self.amt += amount as u64;
        self.inner.consume(amount);
    }
}

impl<W: io::Write> io::Write for Counter<W> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        let n = self.inner.write(buf)?;
        self.amt += n as u64;
        Ok(n)
    }

    fn write_vectored(&mut self, bufs: &[io::IoSlice<'_>]) -> io::Result<usize> {
        let n = self.inner.write_vectored(bufs)?;
        self.amt += n as u64;
        Ok(n)
    }

    #[inline]
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

#[test]
fn symlink_validation() {
    assert!(validate_symlink("a/b", "../c"));
    assert!(!validate_symlink("a/b", "../../c"));
    assert!(!validate_symlink("a/b", "/c"));
    assert!(!validate_symlink("a/b", ".//////../../c"));
    assert!(!validate_symlink("a/b", "a/../c"));
    #[cfg(windows)]
    assert!(!validate_symlink("a/b", "C:/e"));
}
