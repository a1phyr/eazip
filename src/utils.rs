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
