use crate::packet::PacketFuture;
use crate::{Config, Error, Handle, Packet, Stats};

use futures::stream::{Stream, StreamExt};
use log::*;
use pin_project::pin_project;
use std::future::Future;
use std::marker::PhantomData;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};

pub type StreamItem = Result<Vec<Packet>, Error>;

pub trait Interruptable: Stream<Item = StreamItem> {
    fn interrupt(&self);
}

#[pin_project]
pub struct PacketStream {
    config: Config,
    handle: Arc<Handle>,
    pending: Option<PacketFuture>,
    complete: bool,
}

impl Interruptable for PacketStream {
    fn interrupt(&self) {
        self.handle.interrupt()
    }
}

impl PacketStream {
    pub fn new(config: Config, handle: Handle) -> PacketStream {
        PacketStream {
            config: config,
            handle: Arc::new(handle),
            pending: None,
            complete: false,
        }
    }

    pub fn handle(&self) -> Arc<Handle> {
        self.handle.clone()
    }

    pub fn stats(&self) -> Result<Stats, Error> {
        self.handle.stats()
    }

    pub fn interrupted(&self) -> bool {
        self.handle.interrupted()
    }

    pub fn interrupt(&self) {
        self.handle.interrupt()
    }
}

impl std::convert::TryFrom<Config> for PacketStream {
    type Error = Error;

    fn try_from(v: Config) -> Result<Self, Self::Error> {
        let handle = Handle::try_from(&v)?;
        Ok(PacketStream::new(v, handle))
    }
}

impl Stream for PacketStream {
    type Item = StreamItem;

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
    use crate::config::Interface;
    use byteorder::{ByteOrder, ReadBytesExt};
    use futures::{Future, Stream};
    use std::convert::TryFrom;
    use std::io::Cursor;
    use std::path::PathBuf;

    #[test]
    fn packets_from_file() {
        let _ = env_logger::try_init();

        let pcap_path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("resources")
            .join("canary.pcap");

        info!("Testing against {:?}", pcap_path);

        let mut cfg = Config::default();
        cfg.with_interface(Interface::File(pcap_path));

        let packets = smol::block_on(async move {
            let packet_provider = PacketStream::try_from(cfg).expect("Failed to build");
            let fut_packets = packet_provider.collect::<Vec<_>>();
            let packets: Vec<_> = fut_packets
                .await
                .into_iter()
                .flatten()
                .flatten()
                .filter(|p| p.data().len() == p.actual_length() as usize)
                .collect();

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

        let mut cfg = Config::default();
        cfg.with_interface(Interface::File(pcap_path));

        let packets = smol::block_on(async move {
            let packet_provider = PacketStream::try_from(cfg).expect("Failed to build");
            let fut_packets = packet_provider.collect::<Vec<_>>();
            let packets: Vec<_> = fut_packets
                .await
                .into_iter()
                .flatten()
                .flatten()
                .filter(|p| p.data().len() == p.actual_length() as usize)
                .collect();

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

        let mut cfg = Config::default();
        cfg.with_interface(Interface::File(pcap_path));

        let packets = smol::block_on(async move {
            let packet_provider = PacketStream::try_from(cfg).expect("Failed to build");
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
                .filter(|p| p.data().len() == p.actual_length() as usize)
                .count();

            packets
        });

        assert_eq!(packets, 10);
    }

    #[test]
    fn packets_from_lookup() {
        let _ = env_logger::try_init();

        let mut cfg = Config::default();
        cfg.with_interface(Interface::Lookup);

        let stream = PacketStream::try_from(cfg);

        assert!(
            stream.is_ok(),
            format!("Could not build stream {:?}", stream.err().unwrap())
        );

        let mut stream = stream.unwrap();

        smol::block_on(async move { stream.next().await })
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
        cfg.with_interface(Interface::Lookup);

        let stream = PacketStream::try_from(cfg);

        assert!(
            stream.is_ok(),
            format!("Could not build stream {:?}", stream.err().unwrap())
        );
    }
}
