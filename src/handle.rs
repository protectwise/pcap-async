use crate::{errors::PcapError, pcap_util};
use log::*;
use std;

pub struct Handle {
    handle: std::ptr::Unique<pcap_sys::pcap_t>,
    live_capture: bool,
}

impl Handle {
    pub fn is_live_capture(&self) -> bool {
        self.live_capture
    }

    pub fn handle(self) -> std::ptr::Unique<pcap_sys::pcap_t> {
        self.handle
    }

    pub fn live_capture(iface: &str) -> Result<Handle, PcapError> {
        let device_str = std::ffi::CString::new(iface).map_err(|e| PcapError::Ffi(e))?;

        let errbuf = ([0i8; 256]).as_mut_ptr();
        let h = unsafe { pcap_sys::pcap_create(device_str.as_ptr(), errbuf) };
        let r = if h.is_null() {
            pcap_util::cstr_to_string(errbuf).and_then(|msg| {
                error!("Failed to create live stream: {}", msg);
                Err(PcapError::LiveCapture {
                    iface: iface.to_string(),
                    error: PcapError::LibPcapError { msg: msg }.into(),
                })
            })
        } else {
            info!("Live stream created for interface {}", iface);
            let handle = unsafe { std::ptr::Unique::new_unchecked(h) };
            Ok(Handle {
                handle: handle,
                live_capture: true,
            })
        };
        drop(errbuf);
        r
    }

    pub fn file_capture(path: &str) -> Result<Handle, PcapError> {
        let device_str = std::ffi::CString::new(path).map_err(|e| PcapError::Ffi(e))?;

        let errbuf = ([0i8; 256]).as_mut_ptr();
        let h = unsafe { pcap_sys::pcap_open_offline(device_str.as_ptr(), errbuf) };
        let r = if h.is_null() {
            pcap_util::cstr_to_string(errbuf).and_then(|msg| {
                error!("Failed to create file stream: {}", msg);
                Err(PcapError::FileCapture {
                    file: path.to_string(),
                    error: PcapError::LibPcapError { msg: msg }.into(),
                })
            })
        } else {
            info!("File stream created for file {}", path);
            let handle = unsafe { std::ptr::Unique::new_unchecked(h) };
            Ok(Handle {
                handle: handle,
                live_capture: false,
            })
        };
        drop(errbuf);
        r
    }

    pub fn lookup() -> Result<Handle, PcapError> {
        let errbuf = ([0i8; 256]).as_mut_ptr();
        let dev = unsafe { pcap_sys::pcap_lookupdev(errbuf) };
        let res = if dev.is_null() {
            pcap_util::cstr_to_string(errbuf as _)
                .and_then(|msg| Err(PcapError::LibPcapError { msg: msg }))
        } else {
            pcap_util::cstr_to_string(dev as _).and_then(|s| {
                debug!("Lookup found interface {}", s);
                Handle::live_capture(&s)
            })
        };
        drop(errbuf);
        res
    }

    pub fn set_non_block(
        handle: *mut pcap_sys::pcap_t,
    ) -> Result<*mut pcap_sys::pcap_t, PcapError> {
        let errbuf = ([0i8; 256]).as_mut_ptr();
        if -1 == unsafe { pcap_sys::pcap_setnonblock(handle, 1, errbuf) } {
            pcap_util::cstr_to_string(errbuf as _).and_then(|msg| {
                error!("Failed to set non block: {}", msg);
                Err(PcapError::LibPcapError { msg: msg })
            })
        } else {
            Ok(handle)
        }
    }

    pub fn set_promiscuous(
        handle: *mut pcap_sys::pcap_t,
    ) -> Result<*mut pcap_sys::pcap_t, PcapError> {
        if 0 != unsafe { pcap_sys::pcap_set_promisc(handle, 1) } {
            Err(pcap_util::convert_libpcap_error(handle))
        } else {
            Ok(handle)
        }
    }

    pub fn set_snaplen(
        handle: *mut pcap_sys::pcap_t,
        snaplen: u32,
    ) -> Result<*mut pcap_sys::pcap_t, PcapError> {
        if 0 != unsafe { pcap_sys::pcap_set_snaplen(handle, snaplen as _) } {
            Err(pcap_util::convert_libpcap_error(handle))
        } else {
            Ok(handle)
        }
    }

    pub fn set_timeout(
        handle: *mut pcap_sys::pcap_t,
        dur: &std::time::Duration,
    ) -> Result<*mut pcap_sys::pcap_t, PcapError> {
        if 0 != unsafe { pcap_sys::pcap_set_timeout(handle, dur.as_millis() as _) } {
            Err(pcap_util::convert_libpcap_error(handle))
        } else {
            Ok(handle)
        }
    }

    pub fn set_buffer_size(
        handle: *mut pcap_sys::pcap_t,
        buffer_size: u32,
    ) -> Result<*mut pcap_sys::pcap_t, PcapError> {
        if 0 != unsafe { pcap_sys::pcap_set_buffer_size(handle, buffer_size as _) } {
            Err(pcap_util::convert_libpcap_error(handle))
        } else {
            Ok(handle)
        }
    }

    pub fn set_bpf(
        handle: *mut pcap_sys::pcap_t,
        bpf: &String,
    ) -> Result<*mut pcap_sys::pcap_t, PcapError> {
        let mut bpf_program = pcap_sys::bpf_program {
            bf_len: 0,
            bf_insns: std::ptr::null_mut(),
        };

        let bpf_str = std::ffi::CString::new(bpf.to_string()).map_err(PcapError::Ffi)?;

        if 0 != unsafe {
            pcap_sys::pcap_compile(
                handle,
                &mut bpf_program,
                bpf_str.as_ptr(),
                1,
                pcap_sys::PCAP_NETMASK_UNKNOWN,
            )
        } {
            return Err(pcap_util::convert_libpcap_error(handle));
        }

        let ret_code = unsafe { pcap_sys::pcap_setfilter(handle, &mut bpf_program) };
        unsafe {
            pcap_sys::pcap_freecode(&mut bpf_program);
        }
        if ret_code != 0 {
            return Err(pcap_util::convert_libpcap_error(handle));
        }
        Ok(handle)
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
