use crate::config::Config;
use crate::errors::Error;
use crate::handle::Handle;
use crate::packet::{Packet, PacketIterator, PacketIteratorItem};
use crate::pcap_util;

use crate::stream::StreamItem;
use failure::Fail;
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
use tokio::time::Delay;

struct BridgeStreamState<I: Iterator<Item = PacketIteratorItem>> {
    it: I,
    current: Vec<Packet>,
    complete: bool,
    reported: bool,
    delaying: Option<Delay>,
}

#[pin_project]
pub struct BridgeStream<I: Iterator<Item = PacketIteratorItem>> {
    retry_after: std::time::Duration,
    stream_states: VecDeque<BridgeStreamState<I>>,
}

impl<I: Iterator<Item = PacketIteratorItem>> BridgeStream<I> {
    pub fn new(
        config: Config,
        handles: Vec<Arc<Handle>>,
    ) -> Result<BridgeStream<PacketIterator>, Error> {
        let states = handles
            .into_iter()
            .map(|h| {
                config.activate_handle(Arc::clone(&h)).unwrap(); //TODO use the Try fror iterops
                let it = PacketIterator::new(&config, &h);
                let new_state = BridgeStreamState {
                    it: it,
                    current: Vec::new(),
                    complete: false,
                    reported: false,
                    delaying: None,
                };
                new_state
            })
            .collect::<VecDeque<_>>();

        Ok(BridgeStream {
            retry_after: config.retry_after().to_owned(),
            stream_states: states,
        })
    }

    fn from_iterators(config: &Config, its: Vec<I>) -> Result<BridgeStream<I>, Error> {
        let states = its
            .into_iter()
            .map(|it| BridgeStreamState {
                it: it,
                current: Vec::new(),
                complete: false,
                reported: false,
                delaying: None,
            })
            .collect::<VecDeque<_>>();

        Ok(BridgeStream {
            retry_after: config.retry_after().to_owned(),
            stream_states: states,
        })
    }
}

fn gather_packets<I: Iterator<Item = PacketIteratorItem>>(
    stream_states: &mut VecDeque<BridgeStreamState<I>>,
) -> Vec<Packet> {
    let mut to_sort = vec![];
    let mut gather_to: Option<SystemTime> = None;
    for iface in stream_states.iter_mut() {
        if let Some(p) = iface.current.last() {
            gather_to = gather_to
                .map(|ts| std::cmp::min(ts, *p.timestamp()))
                .or(Some(*p.timestamp()));
        }
    }
    if let Some(ts) = gather_to {
        println!("Timestamp: {:?}", ts);
        for state in stream_states.iter_mut() {
            let current = std::mem::replace(&mut state.current, vec![]);
            let t: (Vec<_>, Vec<_>) = current.into_iter().partition(|p| *p.timestamp() < ts);
            let (before_ts, after_ts) = t;
            println!(
                "before_ts:{:?} \nafter_ts:{:?}",
                before_ts,
                after_ts
            );
            to_sort.extend(before_ts);
            state.current = after_ts;
        }
    }
    for state in stream_states.iter_mut() {
        if state.complete {
            let current = std::mem::replace(&mut state.current, vec![]);
            to_sort.extend(current);
        }
    }

    to_sort.sort_by_key(|p| *p.timestamp());
    println!("to_sort: {:?}", to_sort);
    to_sort
}

impl<I: Iterator<Item = PacketIteratorItem>> Stream for BridgeStream<I> {
    type Item = StreamItem<Error>;

    fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        //return Poll::Pending;
        let mut this = self.project();
        println!("Interfaces: {:?}", this.stream_states.len());
        let states: &mut VecDeque<BridgeStreamState<I>> = this.stream_states;
        let retry_after: &mut std::time::Duration = this.retry_after;
        println!("retry_after: {:?}", retry_after);

        let mut delay_count = 0;
        for state in states.iter_mut() {
            if let Some(mut existing_delay) = state.delaying.take() {
                //Check the interface for a delay..
                if let Poll::Pending = Pin::new(&mut existing_delay).poll(cx) {
                    delay_count = delay_count + 1;
                    println!("Delaying");
                    state.delaying = Some(existing_delay);
                    continue; // do another iteration on another iface
                }
            }

            match state.it.next() {
                Some(PacketIteratorItem::NoPackets) => {
                    println!("Pending");
                    state.delaying = Some(tokio::time::delay_for(*retry_after));
                    state.reported = true;
                    delay_count = delay_count + 1;
                    continue;
                }
                Some(PacketIteratorItem::Err(e)) => {
                    return Poll::Ready(Some(Err(e)));
                }
                None => {
                    println!("Interface has completed");
                    state.complete = true;
                    continue;
                }
                Some(PacketIteratorItem::Packets(v)) => {
                    println!("Adding {} packets to current", v.len());
                    state.reported = true;
                    state.current.extend(v);
                }
            }
        }

        let report_count = states.iter().filter(|state| {
            state.reported || state.complete
        }).count();

        let res = if report_count == states.len() {
            // We much ensure that all interfaces have reported.
            println!("All ifaces have reported.");

            for state in states.iter_mut() {
                state.reported = false;
            }
            gather_packets(states)
        } else {
            println!("{} / {} iface reported.", report_count, states.len());
            vec![]
        };

        states.retain(|iface| {
            //drop the complete interfaces
            return !iface.complete;
        });

        if !res.is_empty() {
            return Poll::Ready(Some(Ok(res)));
        } else if delay_count >= states.len() && !states.is_empty()  {
            println!("All ifaces are delayed.");
            return Poll::Pending;
        } else {
            println!("All ifaces are complete.");
            return Poll::Ready(None);
        }

        // if res.is_empty() && states.is_empty() {
        //     println!("All ifaces are complete.");
        //     return Poll::Ready(None);
        // } else if res.is_empty() && delay_count >= states.len() && !states.is_empty()  {
        //     println!("All ifaces are delayed.");
        //     return Poll::Pending;
        // } else {
        //     return Poll::Ready(Some(Ok(res)));
        // }
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
    use failure::_core::ops::RangeFull;
    use std::ops::Range;

    #[pin_project]
    struct TransformStream<I, S: Stream<Item = I> + Unpin> {
        stream: S
    }

    impl <I, S: Stream<Item = I> + Unpin> Stream for TransformStream<I, S> {
        type Item = Poll<Option<I>>;
        fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
            let mut this = self.project();
            match Pin::new(&mut this.stream).poll_next(cx) {
                Poll::Ready(None) => Poll::Ready(None),
                x => Poll::Ready(Some(x))
            }
        }
    }

    #[tokio::test]
    async fn packets_from_file() {
        let _ = env_logger::try_init();

        let pcap_path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("resources")
            .join("canary.pcap");

        info!("Testing against {:?}", pcap_path);

        let handle = Handle::file_capture(pcap_path.to_str().expect("No path found"))
            .expect("No handle created");

        let packet_stream = PacketIterator::new(&Config::default(), &Arc::clone(&handle));

        let packet_provider = BridgeStream::from_iterators(&Config::default(), vec![packet_stream])
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

        let packet_stream = PacketIterator::new(&Config::default(), &Arc::clone(&handle));

        let packet_provider = BridgeStream::from_iterators(&Config::default(), vec![packet_stream])
            .expect("Failed to build");

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
        let packet_stream = PacketIterator::new(&Config::default(), &Arc::clone(&handle));

        let stream = BridgeStream::from_iterators(&Config::default(), vec![packet_stream]);

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
        let packet_stream = PacketIterator::new(&Config::default(), &Arc::clone(&handle));

        let stream = BridgeStream::from_iterators(&cfg, vec![packet_stream]);

        assert!(
            stream.is_ok(),
            format!("Could not build stream {}", stream.err().unwrap())
        );
    }

    fn make_packets(range: Range<usize>) -> Vec<Packet> {
        let base_time = std::time::SystemTime::UNIX_EPOCH;
        let mut packets = vec![];
        for s in range {
            let d= base_time + std::time::Duration::from_secs(s as _);
            let p = Packet::new(d, 0, 0, vec![]);
            packets.push(p)
        }
        packets
    }

    #[tokio::test]
    async fn bridge_returns_pending_if_all_downstreams_are_pending() {
        let stream1 = vec![PacketIteratorItem::NoPackets].into_iter();//make_packets(0..15);
        let stream2 = vec![PacketIteratorItem::NoPackets].into_iter();
        let mut cfg = Config::default();

        let bridge = BridgeStream::from_iterators(&cfg, vec![stream1, stream2]).expect("Unable to create bridge.");
        let transformed = TransformStream{
            stream: bridge
        };

        let mut result = transformed.collect::<Vec<_>>().await;
        info!("result {:?}", result);
        match result.first() {
            Some(Poll::Pending) => {},
            _ => panic!("Should be pending and not finished")
        }
    }

    #[tokio::test]
    async fn packets_come_out_time_ordered() {
        let mut packets1 = vec![];
        let mut packets2 = vec![];
        let mut packets3 = vec![];

        let base_time = std::time::SystemTime::UNIX_EPOCH;
        let cfg = Config::default();

        packets1.extend(make_packets(0..3));
        packets2.extend(make_packets(3..10));
        packets3.extend(make_packets(3..5));

        let all_packets: Vec<Packet> = vec![packets1.clone(), packets2.clone(), packets3.clone()]
            .into_iter()
            .flatten()
            .collect::<Vec<_>>();

        println!("packets1 {:?}", packets1);
        println!("packets2 {:?}", packets2);
        println!("packets3 {:?}", packets3);

        let item1: PacketIteratorItem = PacketIteratorItem::Packets(packets1);
        let item2: PacketIteratorItem = PacketIteratorItem::Packets(packets2);
        let item3: PacketIteratorItem = PacketIteratorItem::Packets(packets3);

        let stream1 = vec![item1, PacketIteratorItem::NoPackets, item2].into_iter();
        let stream2 = vec![item3, PacketIteratorItem::NoPackets].into_iter();

        let bridge = BridgeStream::from_iterators(&cfg, vec![stream1, stream2])
            .expect("Unable to create BridgeStream");

        let mut result = bridge
            .collect::<Vec<StreamItem<Error>>>()
            .await;
        info!("Result {:?}", result);

        //assert_eq!(result.len(), 4);
        let flattened: Vec<Packet> = result
            .into_iter()
            .map(|r| r.unwrap())
            .flatten()
            .collect::<Vec<_>>();
        let result_times = flattened.iter().map(|p| p.timestamp).collect::<Vec<_>>();
        let mut all_packet_time = all_packets.iter().map(|p| p.timestamp).collect::<Vec<_>>();
        all_packet_time.sort();

        //assert_eq!(result_times.len(), all_packet_time.len());

        assert_eq!(result_times, all_packet_time);

    }
}
