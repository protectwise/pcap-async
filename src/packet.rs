use crate::{
    errors::Error,
    Config,
    Handle,
    pcap_util
};
use futures::{
    compat::Future01CompatExt,
    stream::StreamExt,
    future::FutureExt,
    Future
};
use log::*;
use pin_utils::pin_mut;
use std::{
    self,
    pin::Pin,
    task::Poll
};
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

pub struct Packet {
    timestamp: std::time::SystemTime,
    actual_length: u32,
    original_length: u32,
    data: Vec<u8>
}

impl Packet {
    pub fn timestamp(&self) -> &std::time::SystemTime { &self.timestamp }
    pub fn data(&self) -> &Vec<u8> { &self.data }
    pub fn actual_length(&self) -> u32 { self.actual_length }
    pub fn original_length(&self) -> u32 { self.original_length }

    pub fn new(
        timestamp: std::time::SystemTime,
        actual_length: u32,
        original_length: u32,
        data: Vec<u8>
    ) -> Packet {
        Packet {
            timestamp: timestamp,
            actual_length: actual_length,
            original_length: original_length,
            data
        }
    }
}

pub struct PacketStream {
    pcap_handle: std::ptr::Unique<pcap_sys::pcap_t>,
    inner: Option<Pin<Box<futures::Stream<Item=Vec<Packet>>>>>
}

impl PacketStream {
    pub fn take_stream(&mut self) -> Option<Pin<Box<futures::Stream<Item=Vec<Packet>>>>> {
        self.inner.take()
    }

    pub fn new(
        config: &Config,
        handle: Handle,
        timer_handle: TimerHandle
    ) -> Result<PacketStream, Error> {
        let live_capture = handle.is_live_capture();

        let handle_ptr = handle.handle();

        let activated = if !live_capture {
            Ok(handle_ptr.as_ptr())
        } else {
            let configured = Handle::set_snaplen(handle_ptr.as_ptr(), config.snaplen())
                .and_then(|h_snap| Handle::set_non_block(h_snap))
                .and_then(|h_nonblock| Handle::set_promiscuous(h_nonblock))
                .and_then(|h_prom| Handle::set_timeout(h_prom, config.timeout()))
                .and_then(|h_time| Handle::set_buffer_size(h_time, config.buffer_size()))?;

            let ret_code = unsafe { pcap_sys::pcap_activate(configured) };

            pcap_util::check_libpcap_error(configured, 0 == ret_code).and_then(|_| {
                if let Some(ref s) = config.bpf() {
                    Handle::set_bpf(configured, s)
                } else {
                    Ok(configured)
                }
            })
        }?;

        let max_packets_read = config.max_packets_read();
        let retry_after = config.retry_after().clone();

        let poll_fn = futures::stream::poll_fn({
            let mut complete = false;
            let mut waiting_for_packets: Option<futures::compat::Compat01As03<tokio_timer::Delay>> = None;

            move |w| {
                if complete {
                    unsafe {
                        pcap_sys::pcap_close(activated);
                    }
                    return Poll::Ready(None);
                }

                let mut packets: Vec<Packet> = vec![];
                let packets_ptr = &mut packets as *mut Vec<Packet>;

                loop {
                    if let Some(mut to) = waiting_for_packets.take() {
                        if let Poll::Pending = to.poll_unpin(&w) {
                            waiting_for_packets = Some(to);
                            return Poll::Pending;
                        }
                    }
                    let ret_code = unsafe {
                        pcap_sys::pcap_dispatch(
                            activated,
                            -1,
                            Some(dispatch_callback),
                            packets_ptr as *mut u8,
                        )
                    };

                    debug!("Dispatch returned {}", ret_code);

                    match ret_code {
                        -2 => {
                            debug!("Pcap breakloop invoked");
                            return Poll::Ready(None);
                        }
                        -1 => {
                            let err = pcap_util::convert_libpcap_error(activated);
                            error!("Error encountered when calling pcap_dispatch: {}", err);
                            unsafe {
                                pcap_sys::pcap_close(activated);
                            }
                            return Poll::Ready(None);
                        }
                        0 => {
                            if live_capture {
                                if !packets.is_empty() {
                                    trace!("Capture loop breaking with {} packets", packets.len());
                                    return Poll::Ready(Some(packets))
                                } else {
                                    debug!("No packets read, delaying to retry");

                                    let mut compat_future = timer_handle
                                        .delay(std::time::Instant::now() + retry_after)
                                        .compat();
                                    match compat_future.poll_unpin(&w) {
                                        Poll::Pending => {
                                            waiting_for_packets = Some(compat_future);
                                            return Poll::Pending;
                                        }
                                        Poll::Ready(Ok(_)) => {
                                            //ready, keep going
                                        }
                                        Poll::Ready(Err(e)) => {
                                            error!("Timer failed: {:?}", e);
                                            unsafe {
                                                pcap_sys::pcap_close(activated);
                                            }
                                            return Poll::Ready(None)
                                        }
                                    }
                                }
                            } else if !complete {
                                complete = true;
                                return Poll::Ready(Some(packets));
                            } else {
                                return Poll::Pending;
                            }
                        }
                        _ => {
                            trace!(
                                "Pcap dispatch returned, after processing {} packets",
                                ret_code
                            );
                            if packets.len() >= max_packets_read {
                                return Poll::Ready(Some(packets));
                            }
                        }
                    }
                }
            }
        });

        Ok(PacketStream {
            pcap_handle: unsafe {
                std::ptr::Unique::new_unchecked(activated)
            },
            inner: Some(poll_fn.boxed())
        })
    }

    pub fn interrupt(&self) {
        let h = self.pcap_handle.clone().as_ptr();
        unsafe {
            pcap_sys::pcap_breakloop(h);
        }
    }
}

#[cfg(test)]
mod tests {
    extern crate test;

    use self::test::Bencher;

    use super::*;
    use futures::{
        Future,
        Stream
    };
    use std::path::PathBuf;

    #[test]
    fn packets_from_file() {
        let _ = env_logger::try_init();

        let interrupt = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        let interrupt_clone = std::sync::Arc::clone(&interrupt);

        let mut t = tokio_timer::Timer::default();
        let h = t.handle();

        let packets_thread = std::thread::spawn(move || {
            let pcap_path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
                .join("resources")
                .join("canary.pcap");

            info!("Testing against {:?}", pcap_path);

            let handle = Handle::file_capture(pcap_path.to_str().expect("No path found"))
                .expect("No handle created");

            let fut_stats = PacketStream::new(&Config::default(), handle, h)
                .expect("Could not build stream")
                .take_stream()
                .expect("No stream available")
                .map(|s| futures::stream::iter(s))
                .flatten()
                .fold(0, |agg, _s| {
                    futures::future::ready(agg + 1)
                });

            let stats = futures::executor::block_on(fut_stats);

            interrupt_clone.store(true, std::sync::atomic::Ordering::Relaxed);

            stats
        });

        while !interrupt.load(std::sync::atomic::Ordering::Relaxed) {
            t.turn(Some(std::time::Duration::from_secs(1))).expect("Failed to turn");
        }

        let packets = packets_thread.join().expect("Failed to join");

        assert_eq!(packets, 10);
    }

    #[test]
    fn packets_from_lookup() {
        let _ = env_logger::try_init();

        let t = tokio_timer::Timer::default();
        let h = t.handle();

        let handle = Handle::lookup().expect("No handle created");

        let stream = PacketStream::new(&Config::default(), handle, h);

        assert!(
            stream.is_ok(),
            format!("Could not build stream {}", stream.err().unwrap())
        );
    }

    #[bench]
    fn bench_packets_from_large_file(b: &mut Bencher) {
        let _ = env_logger::try_init();

        let mut t = tokio_timer::Timer::default();
        let h = t.handle();

        let pcap_path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("resources")
            .join("4SICS-GeekLounge-151020.pcap");

        info!("Benchmarking against {:?}", pcap_path);

        b.iter(|| {
            let interrupt = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
            let interrupt_clone = std::sync::Arc::clone(&interrupt);

            let clone_path = pcap_path.clone();
            let timer_handle = h.clone();

            let packets_thread = std::thread::spawn(move || {
                let handle = Handle::file_capture(clone_path.to_str().expect("No path found"))
                    .expect("No handle created");

                let mut cfg = Config::default();
                cfg.with_max_packets_read(500);

                let fut_stats = PacketStream::new(&cfg, handle, timer_handle)
                    .expect("Could not build stream")
                    .take_stream()
                    .expect("No stream to take")
                    .map(|s| futures::stream::iter(s))
                    .flatten()
                    .fold(0, |agg, _s| {
                        futures::future::ready(agg + 1)
                    });

                let packets = futures::executor::block_on(fut_stats);

                interrupt_clone.store(true, std::sync::atomic::Ordering::Relaxed);

                packets
            });

            while !interrupt.load(std::sync::atomic::Ordering::Relaxed) {
                t.turn(Some(std::time::Duration::from_secs(1))).expect("Failed to turn");
            }

            let packets = packets_thread.join().expect("Failed to join");

            assert_eq!(packets, 246137);
        });
    }
}
