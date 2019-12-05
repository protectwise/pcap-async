use crate::config::Config;
use crate::errors::Error;
use crate::handle::Handle;
use crate::packet::Packet;
use crate::packet_future::PacketFuture;
use crate::pcap_util;

use futures::stream::{Stream, StreamExt};
use log::*;
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use tokio_timer::Delay;

pub struct PacketStream {
    config: Config,
    handle: Arc<Handle>,
    delaying: Option<Delay>,
    pending: Option<PacketFuture>,
}

impl PacketStream {
    pub fn new(config: Config, handle: Arc<Handle>) -> Result<PacketStream, Error> {
        let live_capture = handle.is_live_capture();

        if live_capture {
            handle
                .set_snaplen(config.snaplen())?
                .set_non_block()?
                .set_promiscuous()?
                .set_timeout(config.timeout())?
                .set_buffer_size(config.buffer_size())?
                .activate()?;

            if let Some(bpf) = config.bpf() {
                let bpf = handle.compile_bpf(bpf)?;
                handle.set_bpf(bpf)?;
            }
        }

        Ok(PacketStream {
            config: config,
            handle: handle,
            delaying: None,
            pending: None,
        })
    }
}

impl Stream for PacketStream {
    type Item = Result<Vec<Packet>, Error>;

    fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        let this = self.project();

        let mut was_delayed = false;
        if let Some(mut existing_delay) = this.delaying.take() {
            if let Poll::Pending = Pin::new(&mut existing_delay).poll(cx) {
                *this.delaying = Some(existing_delay);
                return Poll::Pending;
            }
            was_delayed = true;
        }

        let mut existing_future = this.pending.take().unwrap_or(PacketFuture::new(this.config, &iface.handle));
        match Pin::new(&mut existing_future).poll(cx) {
            Poll::Pending => {
                *this.pending = Some(existing_future);
                Poll::Pending
            }
            Poll::Ready(Err(e)) => {
                debug!("Stream encountered an error");
                Poll::Ready(Some(Err(e)))
            }
            Poll::Ready(Ok(None)) => {
                debug!("Stream was complete");
                Poll::Ready(None)
            }
            Poll::Ready(Ok(Some(v))) => {
                if v.is_empty() && !was_delayed {
                    *this.delaying = Some(tokio_timer::delay_for(this.config.delay));
                    Poll::Pending
                } else {
                    Poll::Ready(Some(Ok(v)))
                }
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

    #[tokio::test]
    async fn packets_from_file() {
        let _ = env_logger::try_init();

        let pcap_path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("resources")
            .join("canary.pcap");

        info!("Testing against {:?}", pcap_path);

        let handle = Handle::file_capture(pcap_path.to_str().expect("No path found"))
            .expect("No handle created");

        let packet_provider =
            PacketStream::new(Config::default(), Arc::clone(&handle)).expect("Failed to build");
        let fut_packets = packet_provider.collect::<Vec<_>>();
        let packets: Vec<_> = fut_packets
            .await
            .into_iter()
            .flatten()
            .flatten()
            .filter(|p| p.data().len() == p.actual_length() as _)
            .collect();

        handle.interrupt();

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

    #[tokio::test]
    async fn packets_from_file_next() {
        let _ = env_logger::try_init();

        let pcap_path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("resources")
            .join("canary.pcap");

        info!("Testing against {:?}", pcap_path);

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
