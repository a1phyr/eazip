#[cfg(not(feature = "std"))]
compile_error!("`no_std` is not supported yet");

mod compression;
mod cp437;
mod crc32;
pub mod read;
mod types;
mod utils;
pub mod write;

pub use compression::{CompressionMethod, Compressor, Decompressor};

pub use read::ZipArchive;
pub use utils::Timestamp;
