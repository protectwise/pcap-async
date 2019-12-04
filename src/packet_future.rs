use crate::{Config, Error, Handle, Packet};

use log::*;
use pin_project::pin_project;
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use tokio_timer::Delay;

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
    delay: std::time::Duration,
    max_packets_read: usize,
    live_capture: bool,
    pending: Option<Delay>,
}

impl PacketFuture {
    pub fn new(config: &Config, handle: &Arc<Handle>) -> PacketFuture {
        PacketFuture {
            pcap_handle: Arc::clone(handle),
            delay: config.retry_after().clone(),
            max_packets_read: config.max_packets_read(),
            live_capture: handle.is_live_capture(),
            pending: None,
        }
    }
}

impl Future for PacketFuture {
    type Output = Result<Option<Vec<Packet>>, Error>;
    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let this = self.project();

        let mut packets = vec![];

        while !this.pcap_handle.interrupted() {
            match this.pending {
                Some(p) => {
                    trace!("Checking if delay is ready");
                    let pinned = unsafe { Pin::new_unchecked(p) };
                    futures::ready!(pinned.poll(cx)); //ready will return so if we are waiting we won't get passed this point.
                    debug!("Delay complete");
                    *this.pending = None;
                }
                None => {
                    let ret_code = unsafe {
                        pcap_sys::pcap_dispatch(
                            this.pcap_handle.as_mut_ptr(),
                            -1,
                            Some(dispatch_callback),
                            &mut packets as *mut Vec<Packet> as *mut u8,
                        )
                    };

                    debug!("Dispatch returned with {}", ret_code);

                    match ret_code {
                        -2 => {
                            debug!("Pcap breakloop invoked");
                            return Poll::Ready(Ok(None));
                        }
                        -1 => {
                            let err = crate::pcap_util::convert_libpcap_error(
                                this.pcap_handle.as_mut_ptr(),
                            );
                            error!("Error encountered when calling pcap_dispatch: {}", err);
                            return Poll::Ready(Err(err));
                        }
                        x if x >= 0 => {
                            trace!("Capture loop captured {} packets", x);
                            if x == 0 && !*this.live_capture {
                                debug!("Not live capture, calling breakloop");
                                unsafe {
                                    pcap_sys::pcap_breakloop(this.pcap_handle.as_mut_ptr())
                                }
                            }
                            return Poll::Ready(Ok(Some(packets)));
                        }
                        _ => {
                            let err = crate::pcap_util::convert_libpcap_error(
                                this.pcap_handle.as_mut_ptr(),
                            );
                            error!("Pcap dispatch returned {}: {:?}", ret_code, err);
                            return Poll::Ready(Err(err));
                        }
                    }
                }
            }
        }

        debug!("Interrupt invoked");

        let r = if packets.is_empty() {
            None
        } else {
            Some(packets)
        };

        return Poll::Ready(Ok(r));
    }
}
