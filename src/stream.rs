use crate::config::Config;
use crate::errors::Error;
use crate::handle::Handle;
use crate::packet::Packet;
use crate::pcap_util;

use futures::compat::Future01CompatExt;
use futures::stream::{Stream, StreamExt};
use futures::{Future, FutureExt};
use log::*;
use std::{self, pin::Pin, task::Poll};
use tokio_timer::timer::Handle as TimerHandle;

pub struct PacketStream {}

impl PacketStream {
    pub fn new(
        config: Config,
        handle: std::sync::Arc<Handle>,
    ) -> Result<impl Stream<Item = Vec<Packet>>, Error> {
        let live_capture = handle.is_live_capture();

        if live_capture {
            handle.set_snaplen(config.snaplen())?
                .set_non_block()?
                .set_promiscuous()?
                .set_timeout(config.timeout())?
                .set_buffer_size(config.buffer_size())?
                .activate()?;

            if let Some(bpf) = config.bpf() {
                handle.set_bpf(bpf)?;
            }
        }

        let max_packets_read = config.max_packets_read();
        let retry_after = config.retry_after().clone();

        let stream = futures::stream::repeat(())
            .then(move |_| {
                crate::next_packets(
                    std::sync::Arc::clone(&handle),
                    retry_after.clone(),
                    max_packets_read,
                    vec![],
                    live_capture,
                )
            })
            .take_while(|v| futures::future::ready(v.is_some()))
            .filter_map(|v| futures::future::ready(v));
        Ok(stream)
    }
}

#[cfg(test)]
mod tests {
    extern crate test;

    use self::test::Bencher;

    use super::*;
    use futures::{Future, Stream};
    use std::path::PathBuf;

    #[test]
    fn packets_from_file() {
        let _ = env_logger::try_init();

        let pcap_path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("resources")
            .join("canary.pcap");

        info!("Testing against {:?}", pcap_path);

        let handle = Handle::file_capture(pcap_path.to_str().expect("No path found"))
            .expect("No handle created");

        let packet_provider =
            PacketStream::new(Config::default(), std::sync::Arc::clone(&handle)).expect("Failed to build");
        let fut_packets = packet_provider.collect::<Vec<_>>();
        let packets = futures::executor::block_on(fut_packets)
            .iter()
            .flatten()
            .filter(|p| p.data().len() == p.actual_length() as _)
            .count();

        handle.interrupt();

        assert_eq!(packets, 10);
    }

    #[test]
    fn packets_from_lookup() {
        let _ = env_logger::try_init();

        let handle = Handle::lookup().expect("No handle created");

        let stream = PacketStream::new(Config::default(), handle);

        assert!(
            stream.is_ok(),
            format!("Could not build stream {}", stream.err().unwrap())
        );
    }

    #[test]
    fn packets_from_lookup_with_bpf() {
        let _ = env_logger::try_init();

        let mut cfg = Config::default();
        cfg.with_bpf("(not (net 172.16.0.0/16 and port 443)) and (not (host 172.17.76.33 and port 443))".to_owned());
        let handle = Handle::lookup().expect("No handle created");

        let stream = PacketStream::new(cfg, handle);

        assert!(
            stream.is_ok(),
            format!("Could not build stream {}", stream.err().unwrap())
        );
    }

    #[bench]
    fn bench_packets_from_large_file(b: &mut Bencher) {
        let _ = env_logger::try_init();

        let pcap_path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("resources")
            .join("4SICS-GeekLounge-151020.pcap");

        info!("Benchmarking against {:?}", pcap_path.clone());

        b.iter(|| {
            let clone_path = pcap_path.clone();

            let handle = Handle::file_capture(clone_path.to_str().expect("No path found"))
                .expect("No handle created");

            let mut cfg = Config::default();
            cfg.with_max_packets_read(5000);

            let packet_provider = PacketStream::new(Config::default(), std::sync::Arc::clone(&handle))
                .expect("Failed to build");
            let fut_packets = packet_provider.collect::<Vec<_>>();
            let packets = futures::executor::block_on(fut_packets)
                .iter()
                .flatten()
                .count();

            handle.interrupt();

            assert_eq!(packets, 246137);
        });
    }
}
