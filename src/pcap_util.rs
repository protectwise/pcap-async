use crate::errors::Error;
use libc;
use log::*;
use std;

#[inline]
pub fn check_libpcap_error(handle: *mut pcap_sys::pcap_t, success: bool) -> Result<(), Error> {
    if success {
        Ok(())
    } else {
        Err(convert_libpcap_error(handle))
    }
}

#[inline]
pub fn convert_libpcap_error(handle: *mut pcap_sys::pcap_t) -> Error {
    let error = unsafe { pcap_sys::pcap_geterr(handle) };
    match cstr_to_string(error as _) {
        Err(e) => e,
        Ok(err) => {
            error!("LibPcap encountered an error: {}", err);
            Error::LibPcapError(err)
        }
    }
}

#[inline]
pub fn cstr_to_string(err: *mut libc::c_char) -> Result<String, Error> {
    if err.is_null() {
        Err(Error::NullPtr)
    } else {
        unsafe { std::ffi::CStr::from_ptr(err as _) }
            .to_str()
            .map_err(Error::Utf8)
            .map(|s| s.to_owned())
    }
}
