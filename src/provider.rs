use crate::{dispatch_callback, errors::Error, pcap_util, Config, Handle, Packet};
use futures::{compat::Future01CompatExt, future::FutureExt, stream::StreamExt, Future};
use log::*;
use std::{self, pin::Pin, task::Poll};
use tokio_timer::timer::Handle as TimerHandle;

pub struct PacketProvider {
    pcap_handle: std::ptr::Unique<pcap_sys::pcap_t>,
    timer_handle: TimerHandle,
    max_packets_read: usize,
    retry_after: std::time::Duration,
    live_capture: bool,
}

async fn next_packets(
    pcap_handle: std::ptr::Unique<pcap_sys::pcap_t>,
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
                        unsafe { pcap_sys::pcap_breakloop(pcap_handle.clone().as_ptr()) }
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

impl PacketProvider {
    pub fn next_packets(&mut self) -> impl std::future::Future<Output = Option<Vec<Packet>>> {
        next_packets(
            self.pcap_handle.clone(),
            self.timer_handle.clone(),
            self.retry_after.clone(),
            self.max_packets_read,
            vec![],
            self.live_capture,
        )
    }

    pub fn new(
        config: &Config,
        handle: Handle,
        timer_handle: TimerHandle,
    ) -> Result<PacketProvider, Error> {
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

        Ok(PacketProvider {
            pcap_handle: unsafe { std::ptr::Unique::new_unchecked(activated) },
            timer_handle: timer_handle,
            max_packets_read: config.max_packets_read(),
            retry_after: config.retry_after().clone(),
            live_capture: live_capture,
        })
    }

    pub fn interrupt(&self) {
        let h = self.pcap_handle.clone().as_ptr();
        unsafe {
            pcap_sys::pcap_breakloop(h);
        }
    }
}

impl Drop for PacketProvider {
    fn drop(&mut self) {
        let h = self.pcap_handle.clone().as_ptr();
        unsafe {
            pcap_sys::pcap_close(h);
        }
    }
}

#[cfg(test)]
mod tests {
    extern crate test;

    use self::test::Bencher;

    use super::*;
    use futures::{Future, Stream};
    use std::path::PathBuf;

    async fn get_packets(provider: PacketProvider) -> usize {
        let mut provider = provider;
        let mut agg = 0;
        loop {
            if let Some(p) = await!(provider.next_packets()) {
                agg += p.len();
            } else {
                break;
            }
        }
        agg
    }

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

            let packet_provider =
                PacketProvider::new(&Config::default(), handle, h).expect("Failed to build");
            let fut_packets: std::pin::Pin<Box<std::future::Future<Output = usize> + Send>> =
                get_packets(packet_provider).boxed();
            let packets = futures::executor::block_on(fut_packets);

            interrupt_clone.store(true, std::sync::atomic::Ordering::Relaxed);

            packets
        });

        while !interrupt.load(std::sync::atomic::Ordering::Relaxed) {
            t.turn(Some(std::time::Duration::from_secs(1)))
                .expect("Failed to turn");
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

        let stream = PacketProvider::new(&Config::default(), handle, h);

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

        info!("Benchmarking against {:?}", pcap_path.clone());

        b.iter(|| {
            let interrupt = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
            let interrupt_clone = std::sync::Arc::clone(&interrupt);

            let clone_path = pcap_path.clone();
            let timer_handle = h.clone();

            let packets_thread = std::thread::spawn(move || {
                let handle = Handle::file_capture(clone_path.to_str().expect("No path found"))
                    .expect("No handle created");

                let mut cfg = Config::default();
                cfg.with_max_packets_read(5000);

                let packet_provider =
                    PacketProvider::new(&cfg, handle, timer_handle).expect("Failed to build");
                let fut_packets = get_packets(packet_provider);
                let packets = futures::executor::block_on(fut_packets);

                interrupt_clone.store(true, std::sync::atomic::Ordering::Relaxed);

                packets
            });

            while !interrupt.load(std::sync::atomic::Ordering::Relaxed) {
                t.turn(Some(std::time::Duration::from_micros(1)))
                    .expect("Failed to turn");
            }

            let packets = packets_thread.join().expect("Failed to join");

            assert_eq!(packets, 246137);
        });
    }
}
