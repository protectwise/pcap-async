#![allow(dead_code, unused_imports)]
#![recursion_limit = "1024"]
#![feature(duration_as_u128, ptr_internals, test, futures_api, pin, async_await, await_macro)]
#[macro_use] extern crate error_chain;

pub mod errors {
    use std;

    // Create the Error, ErrorKind, ResultExt, and Result types
    error_chain! {
        foreign_links {
            Io(std::io::Error) #[doc = "Error during IO"];
            Ffi(std::ffi::NulError) #[doc = "Error during FFI conversion"];
            Utf8(std::str::Utf8Error) #[doc = "Error during UTF8 conversion"];
            TokioTimer(tokio_timer::Error) #[doc = "Tokio timer error"];
        }
        errors {
            CreatePacketHeader {
                display("Libpcap failed to populate header")
            }
            LibPcapError(msg: String) {
                display("Libpcap encountered an error: {}", msg)
            }
            Poll {
                display("Error while polling")
            }
            LiveCapture(iface: String) {
                display("Could not create live extraction from {}", iface)
            }
            FileCapture(file: String) {
                display("Could not create extraction from {}", file)
            }
            NoMorePackets {
                display("Interface did not return packets")
            }
            TimeoutExpired {
                display("Timeout expired when capturing from interface")
            }
            NullPtr {
                display("Error returned a null pointer")
            }
            BpfCompile(bpf: String) {
                display("Could not compile bpf {}", bpf)
            }
            SetBpf(bpf: String) {
                display("Could not set bpf {}", bpf)
            }
            SetNonBlock {
                display("Could not set non block")
            }
            SetSnapLength {
                display("Could not set snap length")
            }
            SetBufferSize {
                display("Could not set buffer size")
            }
            SetPromiscuous {
                display("Could not set promiscuous")
            }
            SetTimeout {
                display("Could not set timeout")
            }
            Interrupted {
                display("Interrupted fired")
            }
            SendFailed {
                display("Channel send failed")
            }
            JoinFailed {
                display("Join thread failed")
            }
            ReceiveFailed {
                display("Channel receive failed")
            }
            Poison {
                display("Mutex is poisoned")
            }
        }
    }
}

pub mod config;
pub mod handle;
pub mod packet;
pub mod pcap_util;
pub mod provider;

pub use crate::{
    handle::Handle as Handle,
    config::Config as Config,
    packet::Packet as Packet,
    provider::PacketProvider as PacketProvider
};
use futures::compat::Future01CompatExt;
use log::*;
use tokio_timer::timer::Handle as TimerHandle;

extern "C" fn dispatch_callback(
    user: *mut u8,
    header: *const pcap_sys::pcap_pkthdr,
    data: *const u8,
) {
    if user == std::ptr::null_mut() || header == std::ptr::null() && data == std::ptr::null() {
        warn!("Invalid data passed to callback");
    } else {
        unsafe {
            let pending = std::mem::transmute::<*mut u8, &mut Vec<Packet>>(user);
            let ts = std::time::SystemTime::UNIX_EPOCH + std::time::Duration::from_secs((*header).ts.tv_sec as u64) + std::time::Duration::from_micros((*header).ts.tv_usec as u64);
            let length = (*header).caplen as usize;
            let mut data_vec = Vec::with_capacity(length);
            data_vec.set_len(length);
            std::ptr::copy(data, data_vec.as_mut_ptr(), length);
            let record = Packet::new(
                ts,
                (*header).caplen,
                (*header).len,
                data_vec
            );
            pending.push(record)
        }
    }
}

async fn next_packets(
    pcap_handle: std::ptr::Unique<pcap_sys::pcap_t>,
    timer_handle: TimerHandle,
    delay: std::time::Duration,
    max_packets_read: usize,
    packets: Vec<Packet>,
    live_capture: bool
) -> Option<Vec<Packet>> {
    let mut packets = packets;
    loop {
        let ret_code = unsafe {
            pcap_sys::pcap_dispatch(
                pcap_handle.clone().as_ptr(),
                -1,
                Some(dispatch_callback),
                &mut packets as *mut Vec<Packet> as *mut u8,
            )
        };

        debug!("Dispatch returned {}", ret_code);

        match ret_code {
            -2 => {
                debug!("Pcap breakloop invoked");
                return None;
            }
            -1 => {
                let err = pcap_util::convert_libpcap_error(pcap_handle.clone().as_ptr());
                error!("Error encountered when calling pcap_dispatch: {}", err);
                return None;
            }
            0 => {
                if !packets.is_empty() {
                    if !live_capture {
                        unsafe {
                            pcap_sys::pcap_breakloop(pcap_handle.clone().as_ptr())
                        }
                    }
                    trace!("Capture loop breaking with {} packets", packets.len());
                    return Some(packets)
                } else {
                    debug!("No packets read, delaying to retry");

                    let f = timer_handle
                        .delay(std::time::Instant::now() + delay)
                        .compat();
                    if let Err(e) = await!(f) {
                        error!("Failed to delay: {:?}", e);
                    }
                }
            }
            _ => {
                trace!(
                    "Pcap dispatch returned, after processing {} packets",
                    ret_code
                );
                if packets.len() >= max_packets_read {
                    return Some(packets);
                }
            }
        }
    }
}