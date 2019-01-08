#![allow(dead_code, unused_imports)]
#![feature(ptr_internals, test, futures_api, async_await, await_macro)]

pub mod config;
pub mod errors;
pub mod handle;
pub mod packet;
pub mod pcap_util;
pub mod provider;
pub mod stream;

pub use crate::{config::Config, handle::Handle, packet::Packet, provider::PacketProvider};
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
            let ts = std::time::SystemTime::UNIX_EPOCH
                + std::time::Duration::from_secs((*header).ts.tv_sec as u64)
                + std::time::Duration::from_micros((*header).ts.tv_usec as u64);
            let length = (*header).caplen as usize;
            let mut data_vec = Vec::with_capacity(length);
            data_vec.set_len(length);
            std::ptr::copy(data, data_vec.as_mut_ptr(), length);
            let record = Packet::new(ts, (*header).caplen, (*header).len, data_vec);
            pending.push(record)
        }
    }
}

async fn next_packets(
    pcap_handle: std::sync::Arc<Handle>,
    timer_handle: TimerHandle,
    delay: std::time::Duration,
    max_packets_read: usize,
    packets: Vec<Packet>,
    live_capture: bool,
) -> Option<Vec<Packet>> {
    let mut packets = packets;
    loop {
        let ret_code = unsafe {
            pcap_sys::pcap_dispatch(
                std::sync::Arc::new(&pcap_handle).as_mut_ptr(),
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
                let err = pcap_util::convert_libpcap_error(pcap_handle.as_mut_ptr());
                error!("Error encountered when calling pcap_dispatch: {}", err);
                return None;
            }
            0 => {
                if !packets.is_empty() {
                    if !live_capture {
                        unsafe { pcap_sys::pcap_breakloop(pcap_handle.as_mut_ptr()) }
                    }
                    trace!("Capture loop breaking with {} packets", packets.len());
                    return Some(packets);
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
