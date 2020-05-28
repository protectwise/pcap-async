use thiserror::Error as ThisError;

#[derive(Debug, ThisError)]
pub enum Error {
    #[error("IO Error")]
    Io(#[from] std::io::Error),
    #[error("Null pointer when dealing with ffi")]
    Ffi(#[from] std::ffi::NulError),
    #[error("Nul Error when dealing with ffi")]
    FfiNul(#[from] std::ffi::FromBytesWithNulError),
    #[error("Utf8 conversion error")]
    Utf8(#[from] std::str::Utf8Error),
    #[error("Time conversion error")]
    Time(#[from] std::time::SystemTimeError),
    #[error("Null ptr returned")]
    NullPtr,
    #[error("Libpcap failed populate header")]
    CreatePacketHeader,
    #[error("Libpcap encountered an error: {0}")]
    LibPcapError(String),
    #[error("Failed to create live capture for interface {iface}: {error}")]
    LiveCapture { iface: String, error: String },
    #[error("Failed to create file capture for file {file}: {error}")]
    FileCapture { file: String, error: String },
    #[error("{0}")]
    Custom(String),
}

unsafe impl Sync for Error {}
unsafe impl Send for Error {}
