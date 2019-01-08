use crate::{errors::Error, pcap_util};
use log::*;
use std;

#[derive(Clone)]
pub struct Handle {
    handle: *mut pcap_sys::pcap_t,
    live_capture: bool,
}

unsafe impl Send for Handle {}
unsafe impl Sync for Handle {}

impl Handle {
    pub fn is_live_capture(&self) -> bool {
        self.live_capture
    }

    pub fn live_capture(iface: &str) -> Result<std::sync::Arc<Handle>, Error> {
        let device_str = std::ffi::CString::new(iface).map_err(Error::Ffi)?;

        let errbuf = ([0i8; 256]).as_mut_ptr();
        let h = unsafe { pcap_sys::pcap_create(device_str.as_ptr(), errbuf) };
        let r = if h.is_null() {
            pcap_util::cstr_to_string(errbuf).and_then(|msg| {
                error!("Failed to create live stream: {}", msg);
                Err(Error::LiveCapture {
                    iface: iface.to_string(),
                    error: Error::LibPcapError { msg: msg }.into(),
                })
            })
        } else {
            info!("Live stream created for interface {}", iface);
            let handle = std::sync::Arc::new(Handle {
                handle: h,
                live_capture: false,
            });
            Ok(handle)
        };
        drop(errbuf);
        r
    }

    pub fn file_capture(path: &str) -> Result<std::sync::Arc<Handle>, Error> {
        let device_str = std::ffi::CString::new(path).map_err(Error::Ffi)?;

        let errbuf = ([0i8; 256]).as_mut_ptr();
        let h = unsafe { pcap_sys::pcap_open_offline(device_str.as_ptr(), errbuf) };
        let r = if h.is_null() {
            pcap_util::cstr_to_string(errbuf).and_then(|msg| {
                error!("Failed to create file stream: {}", msg);
                Err(Error::FileCapture {
                    file: path.to_string(),
                    error: Error::LibPcapError { msg: msg }.into(),
                })
            })
        } else {
            info!("File stream created for file {}", path);
            let handle = std::sync::Arc::new(Handle {
                handle: h,
                live_capture: false,
            });
            Ok(handle)
        };
        drop(errbuf);
        r
    }

    pub fn lookup() -> Result<std::sync::Arc<Handle>, Error> {
        let errbuf = ([0i8; 256]).as_mut_ptr();
        let dev = unsafe { pcap_sys::pcap_lookupdev(errbuf) };
        let res = if dev.is_null() {
            pcap_util::cstr_to_string(errbuf as _)
                .and_then(|msg| Err(Error::LibPcapError { msg: msg }))
        } else {
            pcap_util::cstr_to_string(dev as _).and_then(|s| {
                debug!("Lookup found interface {}", s);
                Handle::live_capture(&s)
            })
        };
        drop(errbuf);
        res
    }

    pub fn set_non_block(&self) -> Result<&Self, Error> {
        let errbuf = ([0i8; 256]).as_mut_ptr();
        if -1 == unsafe { pcap_sys::pcap_setnonblock(self.handle, 1, errbuf) } {
            pcap_util::cstr_to_string(errbuf as _).and_then(|msg| {
                error!("Failed to set non block: {}", msg);
                Err(Error::LibPcapError { msg: msg })
            })
        } else {
            Ok(self)
        }
    }

    pub fn set_promiscuous(&self) -> Result<&Self, Error> {
        if 0 != unsafe { pcap_sys::pcap_set_promisc(self.handle, 1) } {
            Err(pcap_util::convert_libpcap_error(self.handle))
        } else {
            Ok(self)
        }
    }

    pub fn set_snaplen(
        &self,
        snaplen: u32,
    ) -> Result<&Self, Error> {
        if 0 != unsafe { pcap_sys::pcap_set_snaplen(self.handle, snaplen as _) } {
            Err(pcap_util::convert_libpcap_error(self.handle))
        } else {
            Ok(self)
        }
    }

    pub fn set_timeout(
        &self,
        dur: &std::time::Duration,
    ) -> Result<&Self, Error> {
        if 0 != unsafe { pcap_sys::pcap_set_timeout(self.handle, dur.as_millis() as _) } {
            Err(pcap_util::convert_libpcap_error(self.handle))
        } else {
            Ok(self)
        }
    }

    pub fn set_buffer_size(
        &self,
        buffer_size: u32,
    ) -> Result<&Self, Error> {
        if 0 != unsafe { pcap_sys::pcap_set_buffer_size(self.handle, buffer_size as _) } {
            Err(pcap_util::convert_libpcap_error(self.handle))
        } else {
            Ok(self)
        }
    }

    pub fn set_bpf(
        &self,
        bpf: &String,
    ) -> Result<&Self, Error> {
        let mut bpf_program = pcap_sys::bpf_program {
            bf_len: 0,
            bf_insns: std::ptr::null_mut(),
        };

        let bpf_str = std::ffi::CString::new(bpf.to_string()).map_err(Error::Ffi)?;

        if 0 != unsafe {
            pcap_sys::pcap_compile(
                self.handle,
                &mut bpf_program,
                bpf_str.as_ptr(),
                1,
                pcap_sys::PCAP_NETMASK_UNKNOWN,
            )
        } {
            return Err(pcap_util::convert_libpcap_error(self.handle));
        }

        let ret_code = unsafe { pcap_sys::pcap_setfilter(self.handle, &mut bpf_program) };
        unsafe {
            pcap_sys::pcap_freecode(&mut bpf_program);
        }
        if ret_code != 0 {
            return Err(pcap_util::convert_libpcap_error(self.handle));
        }
        Ok(self)
    }

    pub fn activate(
        &self
    ) -> Result<&Self, Error> {
        if 0 != unsafe { pcap_sys::pcap_activate(self.handle) } {
            Err(pcap_util::convert_libpcap_error(self.handle))
        } else {
            Ok(self)
        }
    }

    pub fn as_mut_ptr(&self) -> *mut pcap_sys::pcap_t {
        self.handle
    }

    pub fn interrupt(&self) {
        unsafe {
            pcap_sys::pcap_breakloop(self.handle);
        }
    }
}

impl Drop for Handle {
    fn drop(&mut self) {
        unsafe {
            pcap_sys::pcap_close(self.handle);
        }
    }
}

#[cfg(test)]
mod tests {
    extern crate env_logger;

    use super::*;
    use std::path::PathBuf;

    #[test]
    fn open_file() {
        let _ = env_logger::try_init();

        let pcap_path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("resources")
            .join("canary.pcap");

        let handle = Handle::file_capture(pcap_path.to_str().expect("No path found"));

        assert!(handle.is_ok());
    }
    #[test]
    fn lookup() {
        let _ = env_logger::try_init();

        let handle = Handle::lookup();

        assert!(handle.is_ok());
    }
}
