use crate::bpf::Bpf;
use crate::{errors::Error, pcap_util, stats::Stats};
use log::*;
use pcap_sys::{pcap_fileno, pcap_set_immediate_mode};
use std::os::raw::c_int;
use std::path::Path;

/// Wrapper around a pcap_t handle to indicate live or offline capture, and allow the handle to
/// be interrupted to stop capture.
#[derive(Clone)]
pub struct Handle {
    handle: *mut pcap_sys::pcap_t,
    live_capture: bool,
    interrupted: std::sync::Arc<std::sync::Mutex<bool>>,
}

unsafe impl Send for Handle {}
unsafe impl Sync for Handle {}

impl Handle {
    pub fn is_live_capture(&self) -> bool {
        self.live_capture
    }

    /// Create a live capture from a string representing an interface
    pub fn live_capture(iface: &str) -> Result<std::sync::Arc<Handle>, Error> {
        let device_str = std::ffi::CString::new(iface).map_err(Error::Ffi)?;

        let errbuf = ([0 as std::os::raw::c_char; 256]).as_mut_ptr();
        let h = unsafe { pcap_sys::pcap_create(device_str.as_ptr() as _, errbuf) };
        let r = if h.is_null() {
            pcap_util::cstr_to_string(errbuf).and_then(|msg| {
                error!("Failed to create live stream: {}", msg);
                Err(Error::LiveCapture {
                    iface: iface.to_string(),
                    error: msg,
                })
            })
        } else {
            info!("Live stream created for interface {}", iface);
            let handle = std::sync::Arc::new(Handle {
                handle: h,
                live_capture: true,
                interrupted: std::sync::Arc::new(std::sync::Mutex::new(false)),
            });
            Ok(handle)
        };
        drop(errbuf);
        r
    }

    /// Create an offline capture from a path to a file
    pub fn file_capture<P: AsRef<Path>>(path: P) -> Result<std::sync::Arc<Handle>, Error> {
        let path = if let Some(s) = path.as_ref().to_str() {
            s
        } else {
            return Err(Error::Custom(format!("Invalid path: {:?}", path.as_ref())));
        };
        let device_str = std::ffi::CString::new(path).map_err(Error::Ffi)?;

        let errbuf = ([0 as std::os::raw::c_char; 256]).as_mut_ptr();
        let h = unsafe { pcap_sys::pcap_open_offline(device_str.as_ptr() as _, errbuf) };
        let r = if h.is_null() {
            pcap_util::cstr_to_string(errbuf as _).and_then(|msg| {
                error!("Failed to create file stream: {}", msg);
                Err(Error::FileCapture {
                    file: path.to_string(),
                    error: msg,
                })
            })
        } else {
            info!("File stream created for file {}", path);
            let handle = std::sync::Arc::new(Handle {
                handle: h,
                live_capture: false,
                interrupted: std::sync::Arc::new(std::sync::Mutex::new(false)),
            });
            Ok(handle)
        };
        drop(errbuf);
        r
    }

    /// Create a dead handle, typically used for compiling bpf's
    pub fn dead(linktype: i32, snaplen: i32) -> Result<std::sync::Arc<Handle>, Error> {
        let h = unsafe { pcap_sys::pcap_open_dead(linktype as c_int, snaplen as c_int) };
        if h.is_null() {
            error!("Failed to create dead handle");
            Err(Error::Custom("Could not create dead handle".to_owned()))
        } else {
            info!("Dead handle created");
            let handle = std::sync::Arc::new(Handle {
                handle: h,
                live_capture: false,
                interrupted: std::sync::Arc::new(std::sync::Mutex::new(false)),
            });
            Ok(handle)
        }
    }

    pub fn lookup() -> Result<std::sync::Arc<Handle>, Error> {
        let errbuf = ([0 as std::os::raw::c_char; 256]).as_mut_ptr();
        let dev = unsafe { pcap_sys::pcap_lookupdev(errbuf) };
        let res = if dev.is_null() {
            pcap_util::cstr_to_string(errbuf as _).and_then(|msg| Err(Error::LibPcapError(msg)))
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
        let errbuf = ([0 as std::os::raw::c_char; 256]).as_mut_ptr();
        if -1 == unsafe { pcap_sys::pcap_setnonblock(self.handle, 1, errbuf) } {
            pcap_util::cstr_to_string(errbuf as _).and_then(|msg| {
                error!("Failed to set non block: {}", msg);
                Err(Error::LibPcapError(msg))
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

    pub fn set_snaplen(&self, snaplen: u32) -> Result<&Self, Error> {
        if 0 != unsafe { pcap_sys::pcap_set_snaplen(self.handle, snaplen as _) } {
            Err(pcap_util::convert_libpcap_error(self.handle))
        } else {
            Ok(self)
        }
    }

    pub fn set_timeout(&self, dur: &std::time::Duration) -> Result<&Self, Error> {
        if 0 != unsafe { pcap_sys::pcap_set_timeout(self.handle, dur.as_millis() as _) } {
            Err(pcap_util::convert_libpcap_error(self.handle))
        } else {
            Ok(self)
        }
    }

    pub fn set_buffer_size(&self, buffer_size: u32) -> Result<&Self, Error> {
        if 0 != unsafe { pcap_sys::pcap_set_buffer_size(self.handle, buffer_size as _) } {
            Err(pcap_util::convert_libpcap_error(self.handle))
        } else {
            Ok(self)
        }
    }

    pub fn compile_bpf(&self, bpf: &str) -> Result<Bpf, Error> {
        let mut bpf_program = pcap_sys::bpf_program {
            bf_len: 0,
            bf_insns: std::ptr::null_mut(),
        };

        let bpf_str = std::ffi::CString::new(bpf.clone()).map_err(Error::Ffi)?;

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

        Ok(Bpf::new(bpf_program))
    }

    pub fn set_bpf(&self, bpf: Bpf) -> Result<&Self, Error> {
        let mut bpf = bpf;

        let ret_code = unsafe { pcap_sys::pcap_setfilter(self.handle, bpf.inner_mut()) };
        if ret_code != 0 {
            return Err(pcap_util::convert_libpcap_error(self.handle));
        }
        Ok(self)
    }

    pub fn set_immediate_mode(&self) -> Result<&Self, Error> {
        if 0 != unsafe { pcap_sys::pcap_set_immediate_mode(self.handle, 1) } {
            Err(pcap_util::convert_libpcap_error(self.handle))
        } else {
            Ok(self)
        }
    }

    pub fn activate(&self) -> Result<&Self, Error> {
        if 0 != unsafe { pcap_sys::pcap_activate(self.handle) } {
            Err(pcap_util::convert_libpcap_error(self.handle))
        } else {
            Ok(self)
        }
    }

    pub fn fd(&self) -> Result<i32, Error> {
        unsafe {
            let fd = pcap_sys::pcap_get_selectable_fd(self.handle);
            if fd == -1 {
                Err(pcap_util::convert_libpcap_error(self.handle))
            } else {
                Ok(fd)
            }
        }
    }

    pub fn as_mut_ptr(&self) -> *mut pcap_sys::pcap_t {
        self.handle
    }

    pub fn interrupted(&self) -> bool {
        self.interrupted.lock().map(|l| *l).unwrap_or(true)
    }

    pub fn interrupt(&self) {
        let interrupted = self
            .interrupted
            .lock()
            .map(|mut l| {
                *l = true;
                false
            })
            .unwrap_or(true);
        if !interrupted {
            unsafe {
                pcap_sys::pcap_breakloop(self.handle);
            }
        }
    }

    pub fn stats(&self) -> Result<Stats, Error> {
        let mut stats: pcap_sys::pcap_stat = pcap_sys::pcap_stat {
            ps_recv: 0,
            ps_drop: 0,
            ps_ifdrop: 0,
        };
        if 0 != unsafe { pcap_sys::pcap_stats(self.handle, &mut stats) } {
            Err(pcap_util::convert_libpcap_error(self.handle))
        } else {
            let stats = Stats {
                received: stats.ps_recv,
                dropped_by_kernel: stats.ps_drop,
                dropped_by_interface: stats.ps_ifdrop,
            };
            Ok(stats)
        }
    }

    pub fn close(&self) {
        unsafe { pcap_sys::pcap_close(self.handle) }
    }
}

impl Drop for Handle {
    fn drop(&mut self) {
        self.close();
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
    #[test]
    fn open_dead() {
        let _ = env_logger::try_init();

        let handle = Handle::dead(0, 0);

        assert!(handle.is_ok());
    }
    #[test]
    fn bpf_compile() {
        let _ = env_logger::try_init();

        let handle = Handle::dead(0, 1555).expect("Could not create dead handle");

        let bpf = handle.compile_bpf(
            "(not (net 192.168.0.0/16 and port 443)) and (not (host 192.1.2.3 and port 443))",
        );

        assert!(bpf.is_ok(), "{:?}", bpf);
    }
}
