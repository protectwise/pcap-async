use crate::packet::Packets;
use crate::{Config, Error, Handle, Packet};

use log::*;
use mio::Evented;
use pin_project::pin_project;
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::{Duration, Instant};

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

enum PacketFutureState {
    Args(DispatchArgs),
    Pending(Pin<Box<dyn Future<Output = Result<DispatchResult, Error>> + Send>>),
}

struct DispatchArgs {
    pcap_handle: Arc<Handle>,
    fd: std::os::unix::io::RawFd,
    max_packets_read: usize,
    snaplen: u32,
    live_capture: bool,
    buffer_for: Duration,
}

pub enum InterfaceReady {
    Yes,
    No,
}

fn poll_ready(
    fd: std::os::unix::io::RawFd,
    timeout: Option<Duration>,
) -> Result<InterfaceReady, Error> {
    let poll = mio::Poll::new().map_err(Error::Io)?;
    let ev = mio::unix::EventedFd(&fd);
    let ready =
        mio::Ready::from_usize(mio::Ready::all().as_usize() & !mio::Ready::writable().as_usize());
    let opts = mio::PollOpt::edge();
    ev.register(&poll, mio::Token(0), ready, opts)
        .map_err(Error::Io)?;
    let mut events = mio::Events::with_capacity(1);
    if poll.poll(&mut events, timeout).map_err(Error::Io)? > 0 {
        for event in events {
            if event.readiness().is_readable() {
                return Ok(InterfaceReady::Yes);
            }
        }
    }
    Ok(InterfaceReady::No)
}

impl DispatchArgs {
    async fn poll(&self, timeout: Option<Duration>) -> Result<InterfaceReady, Error> {
        trace!("Polling FD with timeout {:?}", timeout);
        let fd = self.fd.clone();
        smol::unblock(move || poll_ready(fd, timeout)).await
    }
}

struct DispatchResult {
    args: DispatchArgs,
    result: Option<Vec<Packet>>,
}

#[pin_project]
pub struct PacketFuture {
    is_complete: bool,
    pending: Option<PacketFutureState>,
}

impl PacketFuture {
    pub fn new(config: &Config, handle: &Arc<Handle>) -> Result<Self, Error> {
        let fd: std::os::unix::io::RawFd = handle.fd()? as _;
        let args = DispatchArgs {
            fd: fd,
            pcap_handle: Arc::clone(handle),
            max_packets_read: config.max_packets_read(),
            snaplen: config.snaplen(),
            live_capture: handle.is_live_capture(),
            buffer_for: config.buffer_for().clone(),
        };

        Ok(Self {
            pending: Some(PacketFutureState::Args(args)),
            is_complete: false,
        })
    }
}

async fn dispatch(args: DispatchArgs) -> Result<DispatchResult, Error> {
    let started_at = Instant::now();
    let mut packets = Packets::new(args.max_packets_read, args.snaplen);

    let should_return_packets = |len: usize| {
        len >= args.max_packets_read || Instant::now().duration_since(started_at) > args.buffer_for
    };

    while !args.pcap_handle.interrupted() {
        trace!("Calling pcap_dispatch.");
        let ret_code = unsafe {
            pcap_sys::pcap_dispatch(
                args.pcap_handle.as_mut_ptr(),
                args.max_packets_read as _,
                Some(dispatch_callback),
                &mut packets as *mut Packets as *mut u8,
            )
        };

        debug!("Dispatch returned with {}", ret_code);

        match ret_code {
            -2 => {
                debug!("Pcap breakloop invoked");
                return Ok(DispatchResult {
                    args: args,
                    result: None,
                });
            }
            -1 => {
                let err = crate::pcap_util::convert_libpcap_error(args.pcap_handle.as_mut_ptr());
                error!("Error encountered when calling pcap_dispatch: {}", err);
                return Err(err);
            }
            0 => {
                if args.live_capture {
                    trace!("No packets in buffer");
                    if should_return_packets(packets.len()) {
                        debug!(
                            "Capture loop returning with {} packets",
                            args.max_packets_read
                        );
                        return Ok(DispatchResult {
                            args: args,
                            result: Some(packets.into_inner()),
                        });
                    } else {
                        let timeout = if packets.is_empty() {
                            None
                        } else {
                            args.buffer_for
                                .checked_sub(Instant::now().duration_since(started_at))
                        };
                        if let InterfaceReady::No = args.poll(timeout).await? {
                            return Ok(DispatchResult {
                                args: args,
                                result: Some(packets.into_inner()),
                            });
                        }
                    }
                } else {
                    debug!("Not live capture and no packets, calling breakloop");
                    unsafe { pcap_sys::pcap_breakloop(args.pcap_handle.as_mut_ptr()) }
                    let res = if packets.is_empty() {
                        None
                    } else {
                        Some(packets.into_inner())
                    };
                    return Ok(DispatchResult {
                        args: args,
                        result: res,
                    });
                }
            }
            x if x > 0 => {
                trace!("Capture loop captured {} packets", x);
                if should_return_packets(packets.len()) {
                    debug!(
                        "Capture loop returning with {} packets",
                        args.max_packets_read
                    );
                    return Ok(DispatchResult {
                        args: args,
                        result: Some(packets.into_inner()),
                    });
                }
            }
            _ => {
                let err = crate::pcap_util::convert_libpcap_error(args.pcap_handle.as_mut_ptr());
                error!("Pcap dispatch returned {}: {:?}", ret_code, err);
                return Err(err);
            }
        }
    }

    debug!("Interrupt invoked");

    if packets.is_empty() {
        return Ok(DispatchResult {
            args: args,
            result: None,
        });
    } else {
        return Ok(DispatchResult {
            args: args,
            result: Some(packets.into_inner()),
        });
    }
}

impl std::future::Future for PacketFuture {
    type Output = Option<Result<Vec<Packet>, Error>>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let this = self.project();
        if *this.is_complete {
            return Poll::Ready(None);
        }

        let mut f = match this.pending.take().unwrap() {
            PacketFutureState::Args(args) => Box::pin(dispatch(args)),
            PacketFutureState::Pending(f) => f,
        };

        match f.as_mut().poll(cx) {
            Poll::Pending => {
                *this.pending = Some(PacketFutureState::Pending(f));
                Poll::Pending
            }
            Poll::Ready(Err(e)) => Poll::Ready(Some(Err(e))),
            Poll::Ready(Ok(r)) => {
                if r.result.is_none() {
                    *this.is_complete = true;
                }
                *this.pending = Some(PacketFutureState::Args(r.args));
                Poll::Ready(r.result.map(|v| Ok(v)))
            }
        }
    }
}
