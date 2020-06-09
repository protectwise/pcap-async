use crate::config::Config;
use crate::errors::Error;
use crate::handle::Handle;
use crate::packet::{Packet, PacketFuture};
use crate::pcap_util;

use futures::stream::{Stream, StreamExt};
use log::*;
use pin_project::pin_project;
use std::future::Future;
use std::marker::PhantomData;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};

pub type StreamItem<E> = Result<Vec<Packet>, E>;

#[pin_project]
pub struct PacketStream {
    config: Config,
    handle: Arc<Handle>,
    pending: Option<PacketFuture>,
    complete: bool,
}

impl PacketStream {
    pub fn new(config: Config, handle: Arc<Handle>) -> Result<PacketStream, Error> {
        let live_capture = handle.is_live_capture();

        if live_capture {
            let h = handle
                .set_snaplen(config.snaplen())?
                .set_promiscuous()?
                .set_buffer_size(config.buffer_size())?
                .activate()?;
            h.set_non_block()?;

            if let Some(bpf) = config.bpf() {
                let bpf = handle.compile_bpf(bpf)?;
                handle.set_bpf(bpf)?;
            }
        }

        Ok(PacketStream {
            config: config,
            handle: handle,
            pending: None,
            complete: false,
        })
    }
}

impl Stream for PacketStream {
    type Item = StreamItem<Error>;

    fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        let this = self.project();

        if *this.complete {
            return Poll::Ready(None);
        }

        let mut f = if let Some(f) = this.pending.take() {
            f
        } else {
            match PacketFuture::new(this.config, this.handle) {
                Err(e) => {
                    *this.complete = true;
                    return Poll::Ready(Some(Err(e)));
                }
                Ok(f) => f,
            }
        };

        match Pin::new(&mut f).poll(cx) {
            Poll::Pending => {
                *this.pending = Some(f);
                Poll::Pending
            }
            Poll::Ready(None) => {
                debug!("Stream was complete");
                *this.complete = true;
                Poll::Ready(None)
            }
            Poll::Ready(Some(Err(e))) => {
                *this.complete = true;
                Poll::Ready(Some(Err(e)))
            }
            Poll::Ready(Some(Ok(packets))) => {
                trace!("Returning {} packets", packets.len());
                Poll::Ready(Some(Ok(packets)))
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use byteorder::{ByteOrder, ReadBytesExt};
    use futures::{Future, Stream};
    use std::io::Cursor;
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

        let packets = smol::run(async move {
            let packet_provider =
                PacketStream::new(Config::default(), Arc::clone(&handle)).expect("Failed to build");
            let fut_packets = packet_provider.collect::<Vec<_>>();
            let packets: Vec<_> = fut_packets
                .await
                .into_iter()
                .flatten()
                .flatten()
                .filter(|p| p.data().len() == p.actual_length() as usize)
                .collect();

            handle.interrupt();

            packets
        });

        assert_eq!(packets.len(), 10);

        let packet = packets.first().cloned().expect("No packets");
        let data = packet
            .into_pcap_record::<byteorder::BigEndian>()
            .expect("Failed to convert to pcap record");
        let mut cursor = Cursor::new(data);
        let ts_sec = cursor
            .read_u32::<byteorder::BigEndian>()
            .expect("Failed to read");
        let ts_usec = cursor
            .read_u32::<byteorder::BigEndian>()
            .expect("Failed to read");
        let actual_length = cursor
            .read_u32::<byteorder::BigEndian>()
            .expect("Failed to read");
        assert_eq!(
            ts_sec as u64 * 1_000_000 as u64 + ts_usec as u64,
            1513735120021685
        );
        assert_eq!(actual_length, 54);
    }

    #[test]
    fn packets_from_large_file() {
        let _ = env_logger::try_init();

        let pcap_path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("resources")
            .join("4SICS-GeekLounge-151020.pcap");

        info!("Testing against {:?}", pcap_path);

        let handle = Handle::file_capture(pcap_path.to_str().expect("No path found"))
            .expect("No handle created");

        let packets = smol::run(async move {
            let packet_provider =
                PacketStream::new(Config::default(), Arc::clone(&handle)).expect("Failed to build");
            let fut_packets = packet_provider.collect::<Vec<_>>();
            let packets: Vec<_> = fut_packets
                .await
                .into_iter()
                .flatten()
                .flatten()
                .filter(|p| p.data().len() == p.actual_length() as usize)
                .collect();

            handle.interrupt();

            packets
        });

        assert_eq!(packets.len(), 246137);
    }

    #[test]
    fn packets_from_file_next() {
        let _ = env_logger::try_init();

        let pcap_path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("resources")
            .join("canary.pcap");

        info!("Testing against {:?}", pcap_path);

        let packets = smol::run(async move {
            let handle = Handle::file_capture(pcap_path.to_str().expect("No path found"))
                .expect("No handle created");

            let packet_provider =
                PacketStream::new(Config::default(), Arc::clone(&handle)).expect("Failed to build");
            let fut_packets = async move {
                let mut packet_provider = packet_provider.boxed();
                let mut packets = vec![];
                while let Some(p) = packet_provider.next().await {
                    packets.extend(p);
                }
                packets
            };
            let packets = fut_packets
                .await
                .into_iter()
                .flatten()
                .filter(|p| p.data().len() == p.actual_length() as _)
                .count();

            handle.interrupt();

            packets
        });

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

        let mut stream = stream.unwrap();

        smol::run(async move { stream.next().await })
            .unwrap()
            .unwrap();
    }

    #[test]
    fn packets_from_lookup_with_bpf() {
        let _ = env_logger::try_init();

        let mut cfg = Config::default();
        cfg.with_bpf(
            "(not (net 172.16.0.0/16 and port 443)) and (not (host 172.17.76.33 and port 443))"
                .to_owned(),
        );
        let handle = Handle::lookup().expect("No handle created");

        let stream = PacketStream::new(cfg, handle);

        assert!(
            stream.is_ok(),
            format!("Could not build stream {}", stream.err().unwrap())
        );
    }
}
