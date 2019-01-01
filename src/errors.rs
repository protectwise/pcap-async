use failure::{err_msg, Fail};

#[derive(Debug, Fail)]
pub enum Error {
    #[fail(display = "IO Error")]
    Io(#[fail(cause)] std::io::Error),
    #[fail(display = "Null pointer when dealing with ffi")]
    Ffi(#[fail(cause)] std::ffi::NulError),
    #[fail(display = "Utf8 conversion error")]
    Utf8(#[fail(cause)] std::str::Utf8Error),
    #[fail(display = "TokioTimer error")]
    TokioTimer(#[fail(cause)] tokio_timer::Error),
    #[fail(display = "Null ptr returned")]
    NullPtr,
    #[fail(display = "Libpcap failed populate header")]
    CreatePacketHeader,
    #[fail(display = "Libpcap encountered an error: {}", msg)]
    LibPcapError { msg: String },
    #[fail(display = "Failed to create live capture for interface {}", iface)]
    LiveCapture {
        iface: String,
        #[fail(cause)]
        error: failure::Error,
    },
    #[fail(display = "Failed to create file capture for file {}", file)]
    FileCapture {
        file: String,
        #[fail(cause)]
        error: failure::Error,
    },
}

unsafe impl Sync for Error {}
unsafe impl Send for Error {}
