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

pub struct PacketStream {
    pcap_handle: std::ptr::Unique<pcap_sys::pcap_t>,
    timer_handle: TimerHandle,
    max_packets_read: usize,
    retry_after: std::time::Duration,
    live_capture: bool
}

impl PacketStream {
    pub fn new(
        config: &Config,
        handle: Handle,
        timer_handle: TimerHandle,
        term: std::sync::Arc<std::sync::atomic::AtomicBool>
    ) -> Result<impl Stream<Item=Vec<Packet>>, Error> {
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

        let pcap_handle = unsafe {
            std::ptr::Unique::new_unchecked(activated)
        };
        let max_packets_read = config.max_packets_read();
        let retry_after = config.retry_after().clone();
        let stream = futures::stream::poll_fn(move || {
            next_packets()
        });
        Ok(stream)
    }

    pub fn interrupt(&self) {
        let h = self.pcap_handle.clone().as_ptr();
        unsafe {
            pcap_sys::pcap_breakloop(h);
        }
    }
}

impl Drop for PacketStream {
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
    use futures::{
        Future,
        Stream
    };
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

            let packet_provider = PacketProvider::new(&Config::default(), handle, h).expect("Failed to build");
            let fut_packets: std::pin::Pin<Box<std::future::Future<Output=usize> + Send>> = get_packets(packet_provider).boxed();
            let packets = futures::executor::block_on(fut_packets);

            interrupt_clone.store(true, std::sync::atomic::Ordering::Relaxed);

            packets
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

                let packet_provider = PacketProvider::new(&cfg, handle, timer_handle).expect("Failed to build");
                let fut_packets = get_packets(packet_provider);
                let packets = futures::executor::block_on(fut_packets);

                interrupt_clone.store(true, std::sync::atomic::Ordering::Relaxed);

                packets
            });

            while !interrupt.load(std::sync::atomic::Ordering::Relaxed) {
                t.turn(Some(std::time::Duration::from_micros(1))).expect("Failed to turn");
            }

            let packets = packets_thread.join().expect("Failed to join");

            assert_eq!(packets, 246137);
        });
    }
}