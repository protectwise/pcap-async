use crate::config::Config;
use crate::errors::Error;
use crate::handle::Handle;
use crate::packet::Packet;
use crate::packet_future::PacketFuture;
use crate::pcap_util;

use crate::stream::StreamItem;
use futures::future::Pending;
use futures::stream::{Stream, StreamExt};
use log::*;
use pin_project::pin_project;
use std::collections::VecDeque;
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::SystemTime;
use tokio_timer::Delay;

struct BridgeStreamState<T>
where
    T: Stream<Item = StreamItem> + Sized + Unpin,
{
    stream: T,
    existing: Vec<Packet>,
    current: Vec<Packet>,
    delaying: Option<Delay>,
    complete: bool,
}

#[pin_project]
pub struct BridgeStream<T>
where
    T: Stream<Item = StreamItem> + Sized + Unpin,
{
    config: Config,
    stream_states: VecDeque<BridgeStreamState<T>>,
}

impl<T: Stream<Item = StreamItem> + Sized + Unpin> BridgeStream<T> {
    pub fn new(config: Config, streams: Vec<T>) -> Result<BridgeStream<T>, Error> {
        let mut stream_states = VecDeque::with_capacity(streams.len());
        for stream in streams {
            let new_state = BridgeStreamState {
                stream: stream,
                existing: Vec::new(),
                current: Vec::new(),
                delaying: None,
                complete: false,
            };
            stream_states.push_back(new_state);
        }

        Ok(BridgeStream {
            config: config,
            stream_states: stream_states,
        })
    }
}

fn gather_packets<T: Stream<Item = StreamItem> + Sized + Unpin>(
    stream_states: &mut VecDeque<BridgeStreamState<T>>,
    gather_to: Option<SystemTime>,
) -> Vec<Packet> {
    let mut to_sort = vec![];
    for iface in stream_states.iter_mut() {
        let v = std::mem::replace(&mut iface.existing, vec![]);
        to_sort.extend(v);
    }
    trace!("Have {} existing packets", to_sort.len());
    if let Some(ts) = gather_to {
        for state in stream_states.iter_mut() {
            let current = std::mem::replace(&mut state.current, vec![]);
            let t: (Vec<_>, Vec<_>) = current.into_iter().partition(|p| *p.timestamp() < ts);
            let (before_ts, after_ts) = t;
            trace!(
                "Adding {} packets based on timestamp, {} packets adding to existing",
                before_ts.len(),
                after_ts.len()
            );
            to_sort.extend(before_ts);
            state.existing = after_ts;
        }
    } else {
        for iface in stream_states.iter_mut() {
            trace!("Moving {} packets into existing", iface.current.len());
            std::mem::swap(&mut iface.existing, &mut iface.current); // are we dropping exisiting here?
        }
    }
    to_sort.sort_by_key(|p| *p.timestamp());
    to_sort
}

impl<T: Stream<Item = StreamItem> + Sized + Unpin> Stream for BridgeStream<T> {
    type Item = StreamItem;

    fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        //return Poll::Pending;
        let this = self.project();
        trace!("Interfaces: {:?}", this.stream_states.len());
        let states: &mut VecDeque<BridgeStreamState<T>> = this.stream_states;
        let config: &mut Config = this.config; //TODO use the Self {} extractor

        let mut gather_to: Option<SystemTime> = None;
        for state in states.iter_mut() {
            if let Some(mut existing_delay) = state.delaying.take() {
                //Check the interface for a delay..
                if let Poll::Pending = Pin::new(&mut existing_delay).poll(cx) {
                    //still delayed?
                    trace!("Delaying");
                    state.delaying = Some(existing_delay);
                    continue; // do another iteration on another iface
                }
            }
            match Pin::new(&mut state.stream).poll_next(cx) {
                Poll::Pending => {
                    trace!("Pending");
                    continue;
                }
                Poll::Ready(Some(Err(e))) => {
                    return Poll::Ready(Some(Err(e)));
                }
                Poll::Ready(None) => {
                    trace!("Interface has completed");
                    state.complete = true;
                    continue;
                }
                Poll::Ready(Some(Ok(v))) => {
                    if v.is_empty() {
                        state.delaying = Some(tokio_timer::delay_for(*config.retry_after()));
                        continue;
                    }
                    if let Some(p) = v.last() {
                        gather_to = gather_to
                            .map(|ts| std::cmp::min(ts, *p.timestamp()))
                            .or(Some(*p.timestamp()));
                    }
                    trace!("Adding {} packets to current", v.len());
                    state.current.extend(v);
                }
            }
        }

        let res = gather_packets(states, gather_to);

        states.retain(|iface| {
            //drop the complete interfaces
            return !iface.complete;
        });

        if res.is_empty() && states.is_empty() {
            return Poll::Ready(None);
        } else {
            return Poll::Ready(Some(Ok(res)));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::PacketStream;
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

        let packet_stream =
            PacketStream::new(Config::default(), Arc::clone(&handle)).expect("Failed to build");

        let packet_provider =
            BridgeStream::new(Config::default(), vec![packet_stream]).expect("Failed to build");
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

        let packet_stream =
            PacketStream::new(Config::default(), Arc::clone(&handle)).expect("Failed to build");

        let packet_provider =
            BridgeStream::new(Config::default(), vec![packet_stream]).expect("Failed to build");
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
    fn packets_from_lookup_bridge() {
        let _ = env_logger::try_init();

        let handle = Handle::lookup().expect("No handle created");
        let packet_stream =
            PacketStream::new(Config::default(), Arc::clone(&handle)).expect("Failed to build");

        let stream = BridgeStream::new(Config::default(), vec![packet_stream]);

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
        let packet_stream =
            PacketStream::new(Config::default(), Arc::clone(&handle)).expect("Failed to build");

        let stream = BridgeStream::new(cfg, vec![packet_stream]);

        assert!(
            stream.is_ok(),
            format!("Could not build stream {}", stream.err().unwrap())
        );
    }
}
