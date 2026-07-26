# Eazip

[![Crates.io](https://img.shields.io/crates/v/eazip.svg)](https://crates.io/crates/eazip)
[![Docs.rs](https://docs.rs/eazip/badge.svg)](https://docs.rs/eazip/)

An simple yet flexible zip library.

This crate provides tools to read and write ZIP archives. It aims at being nice to use for developpers, which includes a good and flexible API, readable source code and clean maintenance.

Given how loose the ZIP spec is about what is a valid ZIP file and the history of security issues around them, this crate also aims at being robust and secure against malicious input. It might therefore may reject some "technically valid" ZIP files. If your ZIP file does not validate but you think it should, feel free to file an issue.

## Examples

### Reading a file

```rust
use std::io;

// Open a ZIP archive from a file path
let mut archive = eazip::Archive::open("example.zip")?;

// Print some metadata for every entry in the archive
for entry in archive.entries() {
    println!("File \"{}\" of type {:?} and compressed size {}", entry.name(), entry.file_type, entry.compressed_size);
}

// Print the content of the file "hello.txt"
let mut hello = archive.get_by_name("hello.txt").ok_or(io::ErrorKind::NotFound)?;
let content = io::read_to_string(hello.read()?)?;

println!("Content of hello.txt: {content}");
```

### Writing a file

```rust
use std::io::prelude::*;

// Create a new archive to a file
let mut archive = eazip::ArchiveWriter::create("example.zip")?;
let options = eazip::write::FileOptions::default();

// Add a file
archive.add_file("hello.txt", "Hello world!\n".as_bytes(), &options)?;

// Add a directory
archive.add_directory("dir/")?;

// Stream a file
let mut writer = archive.stream_file("dir/streaming.txt", &options)?;
writer.write_all(b"some data\n")?;
writer.finish()?;

// Finish writing the archive
archive.finish()?;
```

## Goals

- Protect against malicious archives and zip confusion attack.
- Don't panic under any input.
- Have readable code and a simple API.
- Well-tested against common ZIP files tools.
- Be performant.

## Non-goals

- Manage to read every half-broken zip archive out there. This library goes out of its way to ensure that zip archives are well-formed.
- Have a built-in support for every compression algorithm.
  By default, this library only supports deflate (because it is everywhere) and zstd (because it is good).
- Non-unicode file names. Those are rare, weird and non-portable. Please fix your files.
- Read or write encrypted files. This crate does not do cryptography; though if you need to read such files, `eazip` provides the necessary encryption metadata.

## License

Licensed under either of

- Apache License, Version 2.0 (LICENSE-APACHE or http://www.apache.org/licenses/LICENSE-2.0)
- MIT license (LICENSE-MIT or http://opensource.org/licenses/MIT)

at your option.
