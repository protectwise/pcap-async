use crate::packet::Packets;
use crate::{Config, Error, Handle, Packet};

use failure::_core::cmp::max;
use failure::_core::ptr::slice_from_raw_parts;
use log::*;
use pin_project::pin_project;
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::Duration;
use tokio::task;

extern "C" fn dispatch_callback(
    user: *mut u8,
    header: *const pcap_sys::pcap_pkthdr,
    data: *const u8,
) {
    if user == std::ptr::null_mut() || header == std::ptr::null() && data == std::ptr::null() {
        warn!("Invalid data passed to callback");
    } else {
        unsafe {
            let packets = std::mem::transmute::<*mut u8, &mut Packets>(user);
            let ts = std::time::SystemTime::UNIX_EPOCH
                + std::time::Duration::from_secs((*header).ts.tv_sec as u64)
                + std::time::Duration::from_micros((*header).ts.tv_usec as u64);
            let length = (*header).caplen as usize;
            let mut data_vec = vec![0u8; length];
            std::ptr::copy_nonoverlapping(data, data_vec.as_mut_ptr(), length);
            let p = Packet::new(ts, (*header).caplen, (*header).len, data_vec);
            packets.push(p);
        }
    }
}

pub struct PacketIterator {
    pcap_handle: Arc<Handle>,
    max_packets_read: usize,
    snaplen: u32,
    live_capture: bool,
    is_complete: bool,
}

impl PacketIterator {
    pub fn new(config: &Config, handle: &Arc<Handle>) -> Self {
        Self {
            pcap_handle: Arc::clone(handle),
            max_packets_read: config.max_packets_read(),
            snaplen: config.snaplen(),
            live_capture: handle.is_live_capture(),
            is_complete: false,
        }
    }
}

pub enum PacketIteratorItem {
    NoPackets,
    Err(Error),
    Packets(Vec<Packet>),
}

fn dispatch(
    pcap_handle: Arc<Handle>,
    live_capture: bool,
    max_packets_read: usize,
    snaplen: u32,
) -> Option<PacketIteratorItem> {
    let mut packets = Packets::new(max_packets_read, snaplen);

    while !pcap_handle.interrupted() {
        let ret_code = unsafe {
            pcap_sys::pcap_dispatch(
                pcap_handle.as_mut_ptr(),
                max_packets_read as _,
                Some(dispatch_callback),
                &mut packets as *mut Packets as *mut u8,
            )
        };

        debug!("Dispatch returned with {}", ret_code);

        match ret_code {
            -2 => {
                debug!("Pcap breakloop invoked");
                return None;
            }
            -1 => {
                let err = crate::pcap_util::convert_libpcap_error(pcap_handle.as_mut_ptr());
                error!("Error encountered when calling pcap_dispatch: {}", err);
                return Some(PacketIteratorItem::Err(err));
            }
            0 => {
                if packets.is_empty() {
                    trace!("No packets in buffer");
                    return Some(PacketIteratorItem::NoPackets);
                } else {
                    if !live_capture {
                        debug!("Not live capture, calling breakloop");
                        unsafe { pcap_sys::pcap_breakloop(pcap_handle.as_mut_ptr()) }
                    }
                    trace!("Capture loop captured {} available packets", packets.len());
                    return Some(PacketIteratorItem::Packets(packets.into_inner()));
                }
            }
            x if x > 0 => {
                trace!("Capture loop captured {} packets", x);
                if packets.len() >= max_packets_read {
                    debug!(
                        "Capture loop captured up to maximum packets of {}",
                        max_packets_read
                    );
                    return Some(PacketIteratorItem::Packets(packets.into_inner()));
                }
            }
            _ => {
                let err = crate::pcap_util::convert_libpcap_error(pcap_handle.as_mut_ptr());
                error!("Pcap dispatch returned {}: {:?}", ret_code, err);
                return Some(PacketIteratorItem::Err(err));
            }
        }
    }

    debug!("Interrupt invoked");

    if packets.is_empty() {
        None
    } else {
        Some(PacketIteratorItem::Packets(packets.into_inner()))
    }
}

impl Iterator for PacketIterator {
    type Item = PacketIteratorItem;

    fn next(&mut self) -> Option<Self::Item> {
        if self.is_complete {
            return None;
        }

        let r = dispatch(
            self.pcap_handle.clone(),
            self.live_capture,
            self.max_packets_read,
            self.snaplen,
        );

        if let None = r {
            self.is_complete = true;
        }

        r
    }
}
