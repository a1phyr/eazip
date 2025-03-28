use std::{fmt, io};

#[derive(Clone, Copy, PartialEq, Eq)]
pub struct CompressionMethod(pub u16);

impl fmt::Debug for CompressionMethod {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let name = match *self {
            Self::STORE => "store",
            Self::DEFLATE => "deflate",
            Self::DEFLATE64 => "deflate64",
            Self::BZIP2 => "bzip2",
            Self::LZMA => "lzma",
            Self::ZSTD_DEPRECATED => "zstd (deprecated)",
            Self::ZSTD => "zstd",
            Self::XZ => "xz",
            Self::AES => "aes",
            Self(n) => return write!(f, "unknown ({n})"),
        };

        f.write_str(name)
    }
}

impl CompressionMethod {
    pub const STORE: Self = Self(0);
    pub const DEFLATE: Self = Self(8);
    pub const DEFLATE64: Self = Self(9);
    pub const BZIP2: Self = Self(12);
    pub const LZMA: Self = Self(14);
    pub const ZSTD_DEPRECATED: Self = Self(20);
    pub const ZSTD: Self = Self(93);
    pub const XZ: Self = Self(95);
    pub const AES: Self = Self(99);

    pub const SUPPORTED: &[CompressionMethod] = &[
        Self::STORE,
        #[cfg(feature = "deflate")]
        Self::DEFLATE,
        #[cfg(feature = "zstd")]
        Self::ZSTD,
    ];
}

#[cold]
fn unsupported_method(method: CompressionMethod) -> io::Error {
    io::Error::new(
        io::ErrorKind::Unsupported,
        format!("Unsupported compression method: {method:?}"),
    )
}

pub struct Decompressor<R>(DecompressorImpl<R>);

enum DecompressorImpl<R> {
    Store(R),
    #[cfg(feature = "deflate")]
    Deflate(flate2::bufread::DeflateDecoder<R>),
    #[cfg(feature = "zstd")]
    Zstd(zstd::Decoder<'static, R>),
}

impl<R: io::BufRead> Decompressor<R> {
    pub fn new(reader: R, method: CompressionMethod) -> io::Result<Self> {
        let inner = match method {
            CompressionMethod::STORE => DecompressorImpl::Store(reader),
            #[cfg(feature = "deflate")]
            CompressionMethod::DEFLATE => {
                DecompressorImpl::Deflate(flate2::bufread::DeflateDecoder::new(reader))
            }
            #[cfg(feature = "zstd")]
            CompressionMethod::ZSTD => DecompressorImpl::Zstd(zstd::Decoder::with_buffer(reader)?),
            _ => return Err(unsupported_method(method)),
        };

        Ok(Self(inner))
    }

    pub fn get_mut(&mut self) -> &mut R {
        match &mut self.0 {
            DecompressorImpl::Store(r) => r,
            #[cfg(feature = "deflate")]
            DecompressorImpl::Deflate(r) => r.get_mut(),
            #[cfg(feature = "zstd")]
            DecompressorImpl::Zstd(r) => r.get_mut(),
        }
    }
}

impl<R: io::BufRead> io::Read for Decompressor<R> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        match &mut self.0 {
            DecompressorImpl::Store(r) => r.read(buf),
            #[cfg(feature = "deflate")]
            DecompressorImpl::Deflate(r) => r.read(buf),
            #[cfg(feature = "zstd")]
            DecompressorImpl::Zstd(r) => r.read(buf),
        }
    }

    fn read_to_end(&mut self, buf: &mut Vec<u8>) -> io::Result<usize> {
        match &mut self.0 {
            DecompressorImpl::Store(r) => r.read_to_end(buf),
            #[cfg(feature = "deflate")]
            DecompressorImpl::Deflate(r) => r.read_to_end(buf),
            #[cfg(feature = "zstd")]
            DecompressorImpl::Zstd(r) => r.read_to_end(buf),
        }
    }

    fn read_to_string(&mut self, buf: &mut String) -> io::Result<usize> {
        match &mut self.0 {
            DecompressorImpl::Store(r) => r.read_to_string(buf),
            #[cfg(feature = "deflate")]
            DecompressorImpl::Deflate(r) => r.read_to_string(buf),
            #[cfg(feature = "zstd")]
            DecompressorImpl::Zstd(r) => r.read_to_string(buf),
        }
    }
}

pub struct Compressor<W: io::Write>(CompressorImpl<W>);

enum CompressorImpl<W: io::Write> {
    Store(W),
    #[cfg(feature = "deflate")]
    Deflate(flate2::write::DeflateEncoder<W>),
    #[cfg(feature = "zstd")]
    Zstd(zstd::Encoder<'static, W>),
}

impl<W: io::Write> Compressor<W> {
    pub fn new(writer: W, method: CompressionMethod, _level: Option<i32>) -> io::Result<Self> {
        let inner = match method {
            CompressionMethod::STORE => CompressorImpl::Store(writer),
            #[cfg(feature = "deflate")]
            CompressionMethod::DEFLATE => {
                let level = flate2::Compression::default();
                CompressorImpl::Deflate(flate2::write::DeflateEncoder::new(writer, level))
            }
            #[cfg(feature = "zstd")]
            CompressionMethod::ZSTD => CompressorImpl::Zstd(zstd::Encoder::new(writer, 0)?),
            _ => return Err(unsupported_method(method)),
        };

        Ok(Self(inner))
    }

    pub fn get_mut(&mut self) -> &mut W {
        match &mut self.0 {
            CompressorImpl::Store(w) => w,
            #[cfg(feature = "deflate")]
            CompressorImpl::Deflate(w) => w.get_mut(),
            #[cfg(feature = "zstd")]
            CompressorImpl::Zstd(w) => w.get_mut(),
        }
    }

    pub fn do_finish(&mut self) -> io::Result<()> {
        match &mut self.0 {
            CompressorImpl::Store(_) => Ok(()),
            #[cfg(feature = "deflate")]
            CompressorImpl::Deflate(w) => w.try_finish(),
            #[cfg(feature = "zstd")]
            CompressorImpl::Zstd(w) => w.do_finish(),
        }
    }

    pub fn finish(self) -> io::Result<W> {
        match self.0 {
            CompressorImpl::Store(w) => Ok(w),
            #[cfg(feature = "deflate")]
            CompressorImpl::Deflate(w) => w.finish(),
            #[cfg(feature = "zstd")]
            CompressorImpl::Zstd(w) => w.finish(),
        }
    }
}

impl<W: io::Write> io::Write for Compressor<W> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        match &mut self.0 {
            CompressorImpl::Store(w) => w.write(buf),
            #[cfg(feature = "deflate")]
            CompressorImpl::Deflate(w) => w.write(buf),
            #[cfg(feature = "zstd")]
            CompressorImpl::Zstd(w) => w.write(buf),
        }
    }

    fn write_all(&mut self, buf: &[u8]) -> io::Result<()> {
        match &mut self.0 {
            CompressorImpl::Store(w) => w.write_all(buf),
            #[cfg(feature = "deflate")]
            CompressorImpl::Deflate(w) => w.write_all(buf),
            #[cfg(feature = "zstd")]
            CompressorImpl::Zstd(w) => w.write_all(buf),
        }
    }

    fn flush(&mut self) -> io::Result<()> {
        match &mut self.0 {
            CompressorImpl::Store(w) => w.flush(),
            #[cfg(feature = "deflate")]
            CompressorImpl::Deflate(w) => w.flush(),
            #[cfg(feature = "zstd")]
            CompressorImpl::Zstd(w) => w.flush(),
        }
    }
}
