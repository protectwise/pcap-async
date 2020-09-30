use crate::bpf::Bpf;
use crate::{pcap_util, stats::Stats, Config, Error, Interface, PacketStream};
use log::*;
use pcap_sys::{pcap_fileno, pcap_set_immediate_mode};
use std::os::raw::c_int;
use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

fn compile_bpf(handle: *mut pcap_sys::pcap_t, bpf: &str) -> Result<Bpf, Error> {
    let mut bpf_program = pcap_sys::bpf_program {
        bf_len: 0,
        bf_insns: std::ptr::null_mut(),
    };

    let bpf_str = std::ffi::CString::new(bpf).map_err(Error::Ffi)?;

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

    Ok(Bpf::new(bpf_program))
}

/// Wrapper around a pcap_t handle to indicate live or offline capture, and allow the handle to
/// be interrupted to stop capture.
#[derive(Clone)]
pub struct PendingHandle {
    handle: *mut pcap_sys::pcap_t,
    live_capture: bool,
}

impl PendingHandle {
    /// Create a live capture from a string representing an interface
    pub fn live_capture(iface: &str) -> Result<PendingHandle, Error> {
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
            let handle = PendingHandle {
                handle: h,
                live_capture: true,
            };
            Ok(handle)
        };
        drop(errbuf);
        r
    }

    /// Create an offline capture from a path to a file
    pub fn file_capture<P: AsRef<Path>>(path: P) -> Result<PendingHandle, Error> {
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
            let handle = PendingHandle {
                handle: h,
                live_capture: false,
            };
            Ok(handle)
        };
        drop(errbuf);
        r
    }

    /// Create a dead handle, typically used for compiling bpf's
    pub fn dead(linktype: i32, snaplen: i32) -> Result<PendingHandle, Error> {
        let h = unsafe { pcap_sys::pcap_open_dead(linktype as c_int, snaplen as c_int) };
        if h.is_null() {
            error!("Failed to create dead handle");
            Err(Error::Custom("Could not create dead handle".to_owned()))
        } else {
            info!("Dead handle created");
            let handle = PendingHandle {
                handle: h,
                live_capture: false,
            };
            Ok(handle)
        }
    }

    /// Create a handle by lookup of devices
    pub fn lookup() -> Result<PendingHandle, Error> {
        let errbuf = ([0 as std::os::raw::c_char; 256]).as_mut_ptr();
        let dev = unsafe { pcap_sys::pcap_lookupdev(errbuf) };
        let res = if dev.is_null() {
            pcap_util::cstr_to_string(errbuf as _).and_then(|msg| Err(Error::LibPcapError(msg)))
        } else {
            pcap_util::cstr_to_string(dev as _).and_then(|s| {
                debug!("Lookup found interface {}", s);
                PendingHandle::live_capture(&s)
            })
        };
        drop(errbuf);
        res
    }

    pub fn set_promiscuous(self) -> Result<Self, Error> {
        if 0 != unsafe { pcap_sys::pcap_set_promisc(self.handle, 1) } {
            Err(pcap_util::convert_libpcap_error(self.handle))
        } else {
            Ok(self)
        }
    }

    pub fn set_snaplen(self, snaplen: u32) -> Result<Self, Error> {
        if 0 != unsafe { pcap_sys::pcap_set_snaplen(self.handle, snaplen as _) } {
            Err(pcap_util::convert_libpcap_error(self.handle))
        } else {
            Ok(self)
        }
    }

    pub fn set_timeout(self, dur: &std::time::Duration) -> Result<Self, Error> {
        if 0 != unsafe { pcap_sys::pcap_set_timeout(self.handle, dur.as_millis() as _) } {
            Err(pcap_util::convert_libpcap_error(self.handle))
        } else {
            Ok(self)
        }
    }

    pub fn set_buffer_size(self, buffer_size: u32) -> Result<Self, Error> {
        if 0 != unsafe { pcap_sys::pcap_set_buffer_size(self.handle, buffer_size as _) } {
            Err(pcap_util::convert_libpcap_error(self.handle))
        } else {
            Ok(self)
        }
    }

    pub fn set_datalink(&self, datalink: i32) -> Result<&Self, Error> {
        if 0 != unsafe { pcap_sys::pcap_set_datalink(self.handle, datalink as _) } {
            Err(pcap_util::convert_libpcap_error(self.handle))
        } else {
            Ok(self)
        }
    }

    pub fn get_datalink(&self) -> Result<i32, Error> {
        let r = unsafe { pcap_sys::pcap_datalink(self.handle) };
        if r < 0 {
            Err(pcap_util::convert_libpcap_error(self.handle))
        } else {
            Ok(r)
        }
    }

    pub fn set_immediate_mode(self) -> Result<Self, Error> {
        if 0 != unsafe { pcap_sys::pcap_set_immediate_mode(self.handle, 1) } {
            Err(pcap_util::convert_libpcap_error(self.handle))
        } else {
            Ok(self)
        }
    }

    pub fn activate(self) -> Result<Handle, Error> {
        let h = Handle {
            handle: self.handle,
            live_capture: self.live_capture,
            interrupted: Arc::new(AtomicBool::new(false)),
        };
        if self.live_capture {
            if 0 != unsafe { pcap_sys::pcap_activate(h.handle) } {
                return Err(pcap_util::convert_libpcap_error(h.handle));
            }
        }
        Ok(h)
    }
}

impl std::convert::TryFrom<&Config> for PendingHandle {
    type Error = Error;

    fn try_from(v: &Config) -> Result<Self, Self::Error> {
        let mut pending = match v.interface() {
            Interface::Dead { linktype, snaplen } => PendingHandle::dead(*linktype, *snaplen)?,
            Interface::Lookup => PendingHandle::lookup()?,
            Interface::File(path) => PendingHandle::file_capture(path)?,
            Interface::Live(dev) => PendingHandle::live_capture(dev)?,
        };

        if pending.live_capture {
            pending = pending
                .set_snaplen(v.snaplen())?
                .set_promiscuous()?
                .set_buffer_size(v.buffer_size())?;
        }

        Ok(pending)
    }
}

/// Wrapper around a pcap_t handle to indicate live or offline capture, and allow the handle to
/// be interrupted to stop capture.
#[derive(Clone)]
pub struct Handle {
    handle: *mut pcap_sys::pcap_t,
    live_capture: bool,
    interrupted: Arc<AtomicBool>,
}

unsafe impl Send for Handle {}
unsafe impl Sync for Handle {}

impl Handle {
    pub fn is_live_capture(&self) -> bool {
        self.live_capture
    }

    /// Create a live capture from a string representing an interface
    pub fn live_capture(iface: &str) -> Result<Handle, Error> {
        PendingHandle::live_capture(iface)?.activate()
    }

    /// Create an offline capture from a path to a file
    pub fn file_capture<P: AsRef<Path>>(path: P) -> Result<Handle, Error> {
        PendingHandle::file_capture(path)?.activate()
    }

    /// Create a dead handle, typically used for compiling bpf's
    pub fn dead(linktype: i32, snaplen: i32) -> Result<Handle, Error> {
        PendingHandle::dead(linktype, snaplen)?.activate()
    }

    /// Create a handle by lookup of devices
    pub fn lookup() -> Result<Handle, Error> {
        PendingHandle::lookup()?.activate()
    }

    pub fn interrupted(&self) -> bool {
        self.interrupted.load(Ordering::Relaxed)
    }

    pub fn interrupt(&self) {
        let interrupted = self.interrupted.swap(true, Ordering::Relaxed);
        if !interrupted {
            unsafe {
                pcap_sys::pcap_breakloop(self.handle);
            }
        }
    }

    pub fn set_bpf(self, mut bpf: Bpf) -> Result<Self, Error> {
        let ret_code = unsafe { pcap_sys::pcap_setfilter(self.handle, bpf.inner_mut()) };
        if ret_code != 0 {
            return Err(pcap_util::convert_libpcap_error(self.handle));
        }
        Ok(self)
    }

    pub fn set_non_block(self) -> Result<Self, Error> {
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

    pub fn set_datalink(self, datalink: i32) -> Result<Self, Error> {
        if 0 != unsafe { pcap_sys::pcap_set_datalink(self.handle, datalink as _) } {
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

    pub fn compile_bpf(&self, bpf: &str) -> Result<Bpf, Error> {
        compile_bpf(self.handle, bpf)
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

    pub fn into_stream(self, cfg: Config) -> PacketStream {
        PacketStream::new(cfg, self)
    }

    pub(crate) fn as_mut_ptr(&self) -> *mut pcap_sys::pcap_t {
        self.handle
    }
}

impl Drop for Handle {
    fn drop(&mut self) {
        self.close();
    }
}

impl std::convert::TryFrom<&Config> for Handle {
    type Error = Error;

    fn try_from(v: &Config) -> Result<Self, Self::Error> {
        let mut handle = PendingHandle::try_from(v)?.activate()?;

        if let Some(datalink) = v.datalink() {
            handle = handle.set_datalink(*datalink)?;
        }
        if handle.live_capture && !v.blocking() {
            handle = handle.set_non_block()?;
        }
        if let Some(bpf) = v.bpf() {
            let bpf = handle.compile_bpf(bpf)?;
            handle = handle.set_bpf(bpf)?;
        }

        Ok(handle)
    }
}

#[cfg(test)]
mod tests {
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
    fn set_datalink() {
        let _ = env_logger::try_init();

        let handle = Handle::dead(0, 0).unwrap();

        let r = handle.set_datalink(108);

        assert!(r.is_err());

        assert!(format!("{:?}", r.err().unwrap()).contains("not one of the DLTs supported"));
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
