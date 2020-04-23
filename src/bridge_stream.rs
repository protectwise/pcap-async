use crate::config::Config;
use crate::errors::Error;
use crate::handle::Handle;
use crate::packet::Packet;
use crate::pcap_util;

use crate::stream::StreamItem;
use failure::Fail;
use futures::future::Pending;
use futures::stream::{Stream, StreamExt};
use log::*;
use pin_project::pin_project;
use std::cmp::Ordering;
use std::collections::VecDeque;
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::SystemTime;
use tokio::time::Delay;

struct BridgeStreamState<E, T>
where
    E: Fail + Sync + Send,
    T: Stream<Item = StreamItem<E>> + Sized + Unpin,
{
    stream: T,
    current: Vec<Packet>,
    complete: bool,
}

#[pin_project]
pub struct BridgeStream<E: Fail + Sync + Send, T>
where
    T: Stream<Item = StreamItem<E>> + Sized + Unpin,
{
    stream_states: VecDeque<BridgeStreamState<E, T>>,
}

impl<E: Fail + Sync + Send, T: Stream<Item = StreamItem<E>> + Sized + Unpin> BridgeStream<E, T> {
    pub fn new(streams: Vec<T>) -> Result<BridgeStream<E, T>, Error> {
        let mut stream_states = VecDeque::with_capacity(streams.len());
        for stream in streams {
            let new_state = BridgeStreamState {
                stream: stream,
                current: vec![],
                complete: false,
            };
            stream_states.push_back(new_state);
        }

        Ok(BridgeStream {
            stream_states: stream_states,
        })
    }
}

fn gather_packets<E: Fail + Sync + Send, T: Stream<Item = StreamItem<E>> + Sized + Unpin>(
    stream_states: &mut VecDeque<BridgeStreamState<E, T>>,
) -> Vec<Packet> {
    // let total_len: usize = stream_states
    //     .iter()
    //     .map(|s| s.current.len()).sum();
    let mut to_sort: Option<Vec<Packet>> = None;
    let mut largest: Option<(usize, usize)> = None;
    for (current_idx, stream) in stream_states.iter().enumerate() {
        largest = largest.map(|(idx, size)| {
            match stream.current.len().cmp(&size) {
                Ordering::Greater => {
                    let len = stream.current.len();
                    (current_idx, len)
                },
                _ => (idx, size)
            }
        }).or_else(|| Some((current_idx, stream.current.len())))
    }
    if let Some((largest_idx, _)) = largest {
        to_sort = stream_states.get_mut(largest_idx).map(|s| {
            std::mem::take(&mut s.current)
        })
    }

    if let Some(mut to_sort) = to_sort.take() {
        for stream in stream_states.iter_mut() {
            to_sort.extend(std::mem::take(&mut stream.current));
        }
        to_sort.sort_by_key(|p| p.timestamp().to_owned());
        to_sort
    } else {
        vec![]
    }

    // for stream in stream_states.iter_mut() {
    //     let current = std::mem::take(&mut stream.current);
    //     to_sort.extend(current)
    // }
    //
    // to_sort.sort_by_key(|p| p.timestamp().to_owned());
    // to_sort

    /*
    loop {
        let mut current_lowest: Option<(usize, &SystemTime)> = None;
        for (i, stream) in stream_states.iter_mut().enumerate() {
            let first = stream.current.get(0);
            if let Some(first) = first {
                current_lowest = current_lowest
                    .map(
                        |(current_idx, current_time)| match first.timestamp().cmp(current_time) {
                            Ordering::Less => (i, first.timestamp()),
                            _ => (current_idx, current_time),
                        },
                    )
                    .or_else(|| Some((i, first.timestamp())));
            }
        }

        if let Some((idx, _)) = current_lowest {
            let iter = stream_states
                .get_mut(idx)
                .into_iter()
                .flat_map(|state| state.current.pop_front().into_iter());
            to_sort.extend(iter);
        } else {
            return to_sort;
        }
    }*/
}

impl<E: Fail + Sync + Send, T: Stream<Item = StreamItem<E>> + Sized + Unpin> Stream
    for BridgeStream<E, T>
{
    type Item = StreamItem<E>;

    fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        let this = self.project();
        //trace!("Interfaces: {:?}", this.stream_states.len());
        let states: &mut VecDeque<BridgeStreamState<E, T>> = this.stream_states;

        let mut delay_count = 0;
        for state in states.iter_mut() {
            match Pin::new(&mut state.stream).poll_next(cx) {
                Poll::Pending => {
                    trace!("Pending");
                    delay_count = delay_count + 1;
                    return Poll::Pending;
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
                    //trace!("Poll returns with {} packets", v.len());
                    if v.is_empty() {
                        trace!("Poll returns with no packets");
                        delay_count = delay_count + 1;
                        continue;
                    }
                    //trace!("Adding {} packets to current", v.len());
                    //std::mem::replace(&mut state.current, v);
                }
            }
        }

        //let res = gather_packets(states);
        let res = vec![];

        states.retain(|iface| {
            //drop the complete interfaces
            return !iface.complete;
        });

        if res.is_empty() && states.is_empty() {
            trace!("All ifaces are complete.");
            return Poll::Ready(None);
        } else if delay_count >= states.len() && !states.is_empty() {
            trace!("All ifaces are delayed.");
            return Poll::Pending;
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
    use futures::stream;
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

        let packet_provider = BridgeStream::new(vec![packet_stream]).expect("Failed to build");

        let fut_packets = packet_provider.collect::<Vec<_>>();
        let packets: Vec<_> = fut_packets
            .await
            .into_iter()
            .flatten()
            .flatten()
            .filter(|p| p.data().len() == p.actual_length() as usize)
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

        let packet_provider = BridgeStream::new(vec![packet_stream]).expect("Failed to build");

        let fut_packets = async move {
            let mut packet_provider = packet_provider.boxed();
            let mut packets = vec![];
            while let Some(p) = packet_provider.next().await {
                info!("packets returned {:?}", p);
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

        let stream = BridgeStream::new(vec![packet_stream]);

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

        let stream = BridgeStream::new(vec![packet_stream]);

        assert!(
            stream.is_ok(),
            format!("Could not build stream {}", stream.err().unwrap())
        );
    }
    #[tokio::test]
    async fn packets_come_out_time_ordered() {
        let mut packets1 = vec![];
        let mut packets2 = vec![];

        let base_time = std::time::SystemTime::UNIX_EPOCH;

        for s in 0..20 {
            let d = base_time + std::time::Duration::from_secs(s);
            let p = Packet::new(d, 0, 0, vec![]);
            packets1.push(p)
        }

        for s in 5..15 {
            let d = base_time + std::time::Duration::from_secs(s);
            let p = Packet::new(d, 0, 0, vec![]);
            packets2.push(p)
        }

        let item1: StreamItem<Error> = Ok(packets1.clone());
        let item2: StreamItem<Error> = Ok(packets2.clone());

        let stream1 = futures::stream::iter(vec![item1]);
        let stream2 = futures::stream::iter(vec![item2]);

        let bridge = BridgeStream::new(vec![stream1, stream2]);

        let mut result = bridge
            .expect("Unable to create BridgeStream")
            .collect::<Vec<StreamItem<Error>>>()
            .await;
        let result = result
            .into_iter()
            .map(|r| r.unwrap())
            .flatten()
            .collect::<Vec<Packet>>();
        info!("Result {:?}", result);

        let mut expected = vec![packets1, packets2]
            .into_iter()
            .flatten()
            .collect::<Vec<Packet>>();
        expected.sort_by_key(|p| p.timestamp().clone());
        let expected_time = expected.iter().map(|p| p.timestamp()).collect::<Vec<_>>();
        let result_time = result.iter().map(|p| p.timestamp()).collect::<Vec<_>>();
        assert_eq!(result.len(), expected.len());
        assert_eq!(result_time, expected_time);

        info!("result: {:?}", result);
        info!("expected: {:?}", expected);
    }
}
