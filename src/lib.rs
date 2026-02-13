#[cfg(not(feature = "std"))]
compile_error!("`no_std` is not supported yet");

mod compression;
pub mod read;
mod types;
mod utils;
pub mod write;

pub use compression::{CompressionMethod, Compressor, Decompressor};
pub use read::Archive;
pub use utils::{FileType, Timestamp};
pub use write::ArchiveWriter;
