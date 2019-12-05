use crate::{Config, Error, Handle, Packet};

use log::*;
use pin_project::pin_project;
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::Duration;
use tokio_executor::blocking::Blocking;

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
            let mut data_vec = vec![0u8; length];
            std::ptr::copy(data, data_vec.as_mut_ptr(), length);
            let record = Packet::new(ts, (*header).caplen, (*header).len, data_vec);
            pending.push(record)
        }
    }
}

#[pin_project]
pub struct PacketFuture {
    pcap_handle: Arc<Handle>,
    max_packets_read: usize,
    live_capture: bool,
    outstanding: Option<Blocking<Result<Option<Vec<Packet>>, Error>>>,
}

impl PacketFuture {
    pub fn new(config: &Config, handle: &Arc<Handle>) -> PacketFuture {
        trace!("Creating new packet future");
        PacketFuture {
            pcap_handle: Arc::clone(handle),
            max_packets_read: config.max_packets_read(),
            live_capture: handle.is_live_capture(),
            outstanding: None,
        }
    }
}

fn dispatch(pcap_handle: Arc<Handle>, live_capture: bool, max_packets_read: usize) -> Blocking<Result<Option<Vec<Packet>>, Error>> {
    tokio_executor::blocking::run(move || {
        let mut packets = vec![];

        while !pcap_handle.interrupted() {
            let ret_code = unsafe {
                pcap_sys::pcap_dispatch(
                    pcap_handle.as_mut_ptr(),
                    -1,
                    Some(dispatch_callback),
                    &mut packets as *mut Vec<Packet> as *mut u8,
                )
            };

            debug!("Dispatch returned with {}", ret_code);

            match ret_code {
                -2 => {
                    debug!("Pcap breakloop invoked");
                    return Ok(None);
                }
                -1 => {
                    let err = crate::pcap_util::convert_libpcap_error(
                        pcap_handle.as_mut_ptr(),
                    );
                    error!("Error encountered when calling pcap_dispatch: {}", err);
                    return Err(err);
                }
                0 => {
                    if packets.is_empty() {
                        trace!("No packets in buffer");
                        return Ok(Some(vec![]))
                    } else {
                        if !live_capture {
                            debug!("Not live capture, calling breakloop");
                            unsafe {
                                pcap_sys::pcap_breakloop(pcap_handle.as_mut_ptr())
                            }
                        }
                        trace!("Capture loop captured {} available packets", packets.len());
                        return Ok(Some(packets));
                    }
                }
                x if x > 0 => {
                    trace!("Capture loop captured {} packets", x);
                    if packets.len() >= max_packets_read {
                        debug!(
                            "Capture loop captured up to maximum packets of {}",
                            max_packets_read
                        );
                        return Ok(Some(packets));
                    }
                }
                _ => {
                    let err = crate::pcap_util::convert_libpcap_error(
                        pcap_handle.as_mut_ptr(),
                    );
                    error!("Pcap dispatch returned {}: {:?}", ret_code, err);
                    return Err(err);
                }
            }
        }

        debug!("Interrupt invoked");

        let r = if packets.is_empty() {
            None
        } else {
            Some(packets)
        };

        return Ok(r);
    })
}

impl Future for PacketFuture {
    type Output = Result<Option<Vec<Packet>>, Error>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let this = self.project();

        let mut f = this.outstanding.take().unwrap_or_else(|| dispatch(this.pcap_handle.clone(), *this.live_capture, *this.max_packets_read));

        match Pin::new(&mut f).poll(cx) {
            Poll::Pending => {
                *this.outstanding = Some(f);
                Poll::Pending
            }
            Poll::Ready(r) => {
                Poll::Ready(r)
            },
        }
    }
}
