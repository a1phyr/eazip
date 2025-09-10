use std::{fmt, time::SystemTime};

#[derive(Clone, Copy)]
pub struct Timestamp(pub u64);

impl Timestamp {
    pub fn now() -> Self {
        Self::from(SystemTime::now())
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

    pub fn to_std(self) -> SystemTime {
        SystemTime::UNIX_EPOCH + std::time::Duration::from_secs(self.0)
    }
}

impl From<SystemTime> for Timestamp {
    fn from(t: SystemTime) -> Self {
        Self(t.duration_since(SystemTime::UNIX_EPOCH).unwrap().as_secs())
    }
}

impl fmt::Debug for Timestamp {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Timestamp({})", self.0)
    }
}
