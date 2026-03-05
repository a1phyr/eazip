# Changelog

## 0.2.3

- Improve validation checks when reading.
- Fix `creation_time` and `access_time` sometimes missing in `Metadata`.
- Use vectored IO where possible when writing.
- Specialize `write_vectored` methods for `Compressor` and `FileStreamer`.
- Validate and canonicalize file names when writing.
- Add `get_ref` method to `Compressor` and `Decompressor`.
- Implement common traits for `Timestamp`
- Implement `Debug` for all public types

## 0.2.2

- Add `Archive::open_parallel` to easily open files for `parallel_extract`
- Add `File::read_stored` and `Metadata::read_stored` methods to easily read files that are not compressed while keeping `Seek` and `BufRead` impls
- Add `ArchiveWriter::get_ref` and `Archive::get_ref` methods
- Add tests for Go and Python

## 0.2.1

- Add `Archive::index_of` and `File::into_reader` methods ([#1](https://github.com/a1phyr/eazip/pull/1), thanks @sunshowers!)
- Add public `Metadata::data_offset`
- Add `read::EncryptionMethod` type and `Metadata::encryption` field to get encryption metadata
- Add documention
- Add tests Windows 11 and InfoZIP tests

## 0.2.0

Initial public release.