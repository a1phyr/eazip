//! An simple yet flexible zip library.
//!
//! This crate provides tools to read and write ZIP archives. It aims at being
//! nice to use for developpers, which includes a good and flexible API,
//! readable source code and clean maintenance.
//!
//! Given how loose the ZIP spec is about what is a valid ZIP file and the
//! history of security issues around them, this crate also aims at being robust
//! and secure against malicious input. It might therefore may reject some
//! "technically valid" ZIP files. If your ZIP file does not validate but you
//! think it should, feel free to file an issue.
//!
//! See [`ArchiveReader`] for reading archives and [`ArchiveWriter`] for creating ones.
//!
//! # Cargo features
//!
//! - `std`: mandatory feature for forward-compatibility.
//! - `deflate`: enable deflate compression and decompression.
//! - `zstd`: enable zstd compression and decompression.
//! - `parallel`: enable parallel ZIP file extraction.
//!
//! # Example
//!
//! ```no_run
//! use std::io;
//!
//! // Open a ZIP archive from a file path
//! let mut archive = eazip::ArchiveReader::open("example.zip")?;
//!
//! // Print some metadata for every entry in the archive
//! for entry in archive.entries() {
//!     println!("File \"{}\" of type {:?} and compressed size {}", entry.name(), entry.file_type, entry.compressed_size);
//! }
//!
//! // Print the content of the file "hello.txt"
//! let mut hello = archive.get_by_name("hello.txt").ok_or(io::ErrorKind::NotFound)?;
//! let content = io::read_to_string(hello.read()?)?;
//!
//! println!("Content of hello.txt: {content}");
//! # Ok::<(), io::Error>(())
//! ```

#![cfg_attr(docsrs, feature(doc_cfg))]
#![warn(missing_debug_implementations)]

#[cfg(not(feature = "std"))]
compile_error!("`no_std` is not supported yet");

mod compression;
pub mod read;
mod types;
mod utils;
pub mod write;

pub use compression::{CompressionMethod, Compressor, Decompressor};
pub use read::{Archive, ArchiveReader};
pub use utils::{FileType, Timestamp};
pub use write::ArchiveWriter;
