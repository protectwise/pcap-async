use crate::config::Config;
use crate::errors::Error;
use crate::handle::Handle;
use crate::packet::Packet;
use crate::packet_future::PacketFuture;
use crate::pcap_util;

use futures::stream::{Stream, StreamExt};
use log::*;
use pin_project::pin_project;
use std::collections::VecDeque;
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::SystemTime;
use tokio::time::Delay;

struct BridgedInterface {
    handle: Arc<Handle>,
    pending: Option<PacketFuture>,
    delaying: Option<Delay>,
    existing: Vec<Packet>,
    current: Vec<Packet>,
    complete: bool,
}

#[pin_project]
pub struct BridgeStream {
    config: Config,
    interfaces: VecDeque<BridgedInterface>,
}

impl BridgeStream {
    pub fn new(config: Config, handles: Vec<Arc<Handle>>) -> Result<BridgeStream, Error> {
        let mut interfaces = VecDeque::with_capacity(handles.len());
        for handle in handles {
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

            let iface = BridgedInterface {
                handle: handle,
                delaying: None,
                pending: None,
                existing: vec![],
                current: vec![],
                complete: false,
            };
            interfaces.push_back(iface)
        }

        Ok(BridgeStream {
            config: config,
            interfaces: interfaces,
        })
    }
}

fn gather_packets(
    interfaces: &mut VecDeque<BridgedInterface>,
    gather_to: Option<SystemTime>,
) -> Vec<Packet> {
    let mut to_sort = vec![];
    for iface in interfaces.iter_mut() {
        let v = std::mem::replace(&mut iface.existing, vec![]);
        to_sort.extend(v);
    }
    trace!("Have {} existing packets", to_sort.len());
    if let Some(ts) = gather_to {
        for iface in interfaces.iter_mut() {
            let current = std::mem::replace(&mut iface.current, vec![]);
            let t: (Vec<_>, Vec<_>) = current.into_iter().partition(|p| *p.timestamp() < ts);
            let (before_ts, after_ts) = t;
            trace!(
                "Adding {} packets based on timestamp, {} packets adding to existing",
                before_ts.len(),
                after_ts.len()
            );
            to_sort.extend(before_ts);
            iface.existing = after_ts;
        }
    } else {
        for iface in interfaces.iter_mut() {
            trace!("Moving {} packets into existing", iface.current.len());
            std::mem::swap(&mut iface.existing, &mut iface.current);
        }
    }
    to_sort.sort_by_key(|p| *p.timestamp());
    to_sort
}

impl Stream for BridgeStream {
    type Item = Result<Vec<Packet>, Error>;

    fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        let this = self.project();
        trace!("Interfaces: {:?}", this.interfaces.len());
        let interfaces: &mut VecDeque<BridgedInterface> = this.interfaces;
        let config: &mut Config = this.config; //TODO use the Self {} extractor

        let mut gather_to: Option<SystemTime> = None;
        for iface in interfaces.iter_mut() {
            let mut was_delayed = false;

            if iface.complete {
                return Poll::Ready(None);
            }
            if let Some(mut existing_delay) = iface.delaying.take() {
                //Check the interface for a delay..
                if let Poll::Pending = Pin::new(&mut existing_delay).poll(cx) {
                    //still delayed?
                    trace!("Delaying");
                    iface.delaying = Some(existing_delay);
                    continue; // do another iteration on another iface
                }
                was_delayed = true;
            }
            let mut existing_future = iface
                .pending
                .take()
                .unwrap_or_else(|| PacketFuture::new(config, &iface.handle));
            match Pin::new(&mut existing_future).poll(cx) {
                Poll::Pending => {
                    trace!("Pending");
                    iface.pending = Some(existing_future);
                    continue;
                    //return Poll::Pending;
                }
                Poll::Ready(Err(e)) => {
                    return Poll::Ready(Some(Err(e)));
                }
                Poll::Ready(Ok(None)) => {
                    trace!("Interface has completed");
                    iface.complete = true;
                    continue;
                }
                Poll::Ready(Ok(Some(v))) => {
                    if v.is_empty() && !was_delayed {
                        iface.delaying = Some(tokio::time::delay_for(*config.retry_after()));
                        continue;
                    }
                    if let Some(p) = v.last() {
                        gather_to = gather_to
                            .map(|ts| std::cmp::min(ts, *p.timestamp()))
                            .or(Some(*p.timestamp()));
                    }
                    trace!("Adding {} packets to current", v.len());
                    iface.current.extend(v);
                }
            }
        }

        let res = gather_packets(interfaces, gather_to);

        interfaces.retain(|iface| {
            //drop the complete interfaces
            return !iface.complete;
        });

        if res.is_empty() && interfaces.is_empty() {
            return Poll::Ready(None);
        } else {
            return Poll::Ready(Some(Ok(res)));
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

        let packet_provider = BridgeStream::new(Config::default(), vec![Arc::clone(&handle)])
            .expect("Failed to build");
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
    async fn packets_from_file_next_bridge() {
        let _ = env_logger::try_init();

        let pcap_path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("resources")
            .join("canary.pcap");

        info!("Testing against {:?}", pcap_path);

        let handle = Handle::file_capture(pcap_path.to_str().expect("No path found"))
            .expect("No handle created");

        let packet_provider = BridgeStream::new(Config::default(), vec![Arc::clone(&handle)])
            .expect("Failed to build");
        let fut_packets = async move {
            let mut packet_provider = packet_provider.boxed();
            let mut packets = vec![];
            while let Some(p) = packet_provider.next().await {
                println!("packets returned {:?}", p);
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
    fn packets_from_lookup_bidge() {
        let _ = env_logger::try_init();

        let handle = Handle::lookup().expect("No handle created");

        let stream = BridgeStream::new(Config::default(), vec![handle]);

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

        let stream = BridgeStream::new(cfg, vec![handle]);

        assert!(
            stream.is_ok(),
            format!("Could not build stream {}", stream.err().unwrap())
        );
    }
}
