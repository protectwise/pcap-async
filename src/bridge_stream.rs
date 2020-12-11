use std::cmp::Ordering;
use std::collections::VecDeque;
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use std::thread::current;
use std::time::{Duration, SystemTime};

use futures::future::Pending;
use futures::stream::{Stream, StreamExt};
use log::*;

use futures::stream::FuturesUnordered;
use pin_project::pin_project;

use crate::config::Config;
use crate::errors::Error;
use crate::handle::Handle;
use crate::packet::Packet;
use crate::pcap_util;
use crate::stream::{Interruptable, StreamItem};

#[pin_project]
struct CallbackFuture<T>
where
    T: Stream<Item = StreamItem> + Sized + Unpin,
{
    idx: usize,
    stream: Option<T>,
}

impl<T: Stream<Item = StreamItem> + Sized + Unpin> Future for CallbackFuture<T> {
    type Output = (usize, Option<(T, StreamItem)>);

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let this = self.project();
        let stream: &mut Option<T> = this.stream;
        let idx: usize = *this.idx;
        if let Some(mut stream) = stream.take() {
            let polled = Pin::new(&mut stream).poll_next(cx);
            match polled {
                Poll::Pending => {
                    let _old_stream = std::mem::replace(this.stream, Some(stream));
                    return Poll::Pending;
                }
                Poll::Ready(Some(t)) => {
                    return Poll::Ready((idx, Some((stream, t))));
                }
                _ => {
                    return Poll::Ready((idx, None));
                }
            }
        } else {
            panic!("Should not not have a stream!")
        }
    }
}

struct BridgeStreamState<T>
where
    T: Interruptable + Sized + Unpin,
{
    stream: Option<T>,
    current: Vec<Vec<Packet>>,
    complete: bool,
}

impl<T: Interruptable + Sized + Unpin> BridgeStreamState<T> {
    fn interrupt(&self) {
        if let Some(st) = &self.stream {
            st.interrupt();
        }
    }

    fn is_complete(&self) -> bool {
        self.complete && self.current.is_empty()
    }

    fn spread(&self) -> Duration {
        let min = self.current.first().map(|s| s.first()).flatten();

        let max = self.current.last().map(|s| s.last()).flatten();

        match (min, max) {
            (Some(min), Some(max)) => {
                let since = max.timestamp().duration_since(*min.timestamp());
                if let Ok(since) = since {
                    return since;
                } else {
                    Duration::from_millis(0)
                }
            }
            _ => Duration::from_millis(0),
        }
    }
}

// The BridgeStream attempts to time order packets from downstream.
// It does this by collecting a `min_states_needed` amount of packet batches, and then sorting them.
// We also allow `max_buffer_time` to act as a fallback in case we have 1 slow stream and one fast stream.
// `max_buffer_time` will check the spread of packets, and if it to large it will sort what it has and pass it on.

#[pin_project]
pub struct BridgeStream<T>
where
    T: Interruptable + Sized + Unpin,
{
    stream_states: VecDeque<BridgeStreamState<T>>,
    max_buffer_time: Duration,
    min_states_needed: usize,
    poll_queue: FuturesUnordered<CallbackFuture<T>>,
}

impl<T: Interruptable + Sized + Unpin> BridgeStream<T> {
    pub fn new(
        streams: Vec<T>,
        max_buffer_time: Duration,
        min_states_needed: usize,
    ) -> Result<BridgeStream<T>, Error> {
        let poll_queue = FuturesUnordered::new();
        let mut stream_states = VecDeque::with_capacity(streams.len());
        for (idx, stream) in streams.into_iter().enumerate() {
            let new_state = BridgeStreamState {
                stream: None,
                current: vec![],
                complete: false,
            };
            let fut = CallbackFuture {
                idx,
                stream: Some(stream),
            };
            poll_queue.push(fut);
            stream_states.push_back(new_state);
        }

        Ok(BridgeStream {
            stream_states: stream_states,
            max_buffer_time,
            min_states_needed: min_states_needed,
            poll_queue,
        })
    }

    pub fn interrupt(&self) {
        for st in &self.stream_states {
            st.interrupt();
        }
    }
}

fn gather_packets<T: Interruptable + Sized + Unpin>(
    stream_states: &mut VecDeque<BridgeStreamState<T>>,
) -> Vec<Packet> {
    let mut result = vec![];
    let mut gather_to: Option<SystemTime> = None;

    for s in stream_states.iter() {
        let last_time = s
            .current
            .last()
            .iter()
            .flat_map(|p| p.last())
            .last()
            .map(|p| *p.timestamp());

        if let Some(last_time) = last_time {
            gather_to = gather_to
                .map(|prev| prev.min(last_time))
                .or(Some(last_time));
        }
    }

    if let Some(gather_to) = gather_to {
        for s in stream_states.iter_mut() {
            let current = std::mem::take(&mut s.current);
            let (to_send, to_keep) = current
                .into_iter()
                .flat_map(|ps| ps.into_iter())
                .partition(|p| p.timestamp() <= &gather_to);

            let to_keep: Vec<Packet> = to_keep;
            if !to_keep.is_empty() {
                s.current.push(to_keep);
            }
            result.extend(to_send)
        }
    } else {
    }
    result.sort_by_key(|p| *p.timestamp()); // todo convert
    result
}

impl<T> Stream for BridgeStream<T>
where
    T: Interruptable + Sized + Unpin,
{
    type Item = StreamItem;

    fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        let this = self.project();
        trace!(
            "Interfaces: {:?} poll_queue {}",
            this.stream_states.len(),
            this.poll_queue.len()
        );
        let states: &mut VecDeque<BridgeStreamState<T>> = this.stream_states;
        let min_states_needed: usize = *this.min_states_needed;
        let max_buffer_time = this.max_buffer_time;
        let mut max_time_spread: Duration = Duration::from_millis(0);
        let mut not_pending: usize = 0;
        let mut poll_queue: &mut FuturesUnordered<CallbackFuture<T>> = this.poll_queue;

        loop {
            match Pin::new(&mut poll_queue).poll_next(cx) {
                Poll::Ready(Some((_, Some((_, Err(err)))))) => {
                    trace!("got a error, passing upstream");
                    return Poll::Ready(Some(Err(err)));
                }
                Poll::Ready(Some((idx, Some((stream, Ok(item)))))) => {
                    //When the future gives us a result we are given a index, that we use to locate an existing State, and re-add the stream.
                    //For that reason the order must never change!
                    trace!("Got Ready");
                    not_pending += 1;
                    if let Some(state) = states.get_mut(idx) {
                        trace!("Appending results");
                        max_time_spread = state.spread().max(max_time_spread);
                        state.stream = Some(stream);
                        state.current.push(item);
                    }
                }
                Poll::Ready(Some((idx, None))) => {
                    if let Some(state) = states.get_mut(idx) {
                        trace!("Interface {} has completed", idx);
                        state.complete = true;
                        continue;
                    }
                }
                Poll::Pending => {
                    trace!("Got Pending");
                    break;
                }
                Poll::Ready(None) => {
                    trace!("Reached the end.");
                    break;
                }
            }
        }

        for (idx, state) in states.iter_mut().enumerate() {
            if let Some(stream) = state.stream.take() {
                //readded = true;
                trace!("re-adding stream to poll queue {}", idx);
                let f = CallbackFuture {
                    idx,
                    stream: Some(stream),
                };
                poll_queue.push(f);
            }
        }

        let one_buffer_is_over = max_time_spread > *max_buffer_time;

        let ready_count = states
            .iter()
            .filter(|s| s.current.len() >= min_states_needed || s.complete)
            .count();

        let enough_state = ready_count == states.len();

        let res = if enough_state || one_buffer_is_over {
            trace!("Reporting");
            gather_packets(states)
        } else {
            trace!("Not reporting {} {}", enough_state, one_buffer_is_over);
            vec![]
        };

        let completed_count = states.iter().filter(|s| s.complete).count();

        if res.is_empty() && completed_count == states.len() {
            trace!("All ifaces are complete.");
            return Poll::Ready(None);
        } else if res.is_empty() && not_pending == 0 && !states.is_empty() {
            trace!("All ifaces are delayed.");
            return Poll::Pending;
        } else {
            trace!("Returning results {}", res.len());
            return Poll::Ready(Some(Ok(res)));
        }
    }
}

#[cfg(test)]
mod tests {
    use std::convert::TryFrom;
    use std::io::Cursor;
    use std::ops::Range;
    use std::path::PathBuf;

    use byteorder::{ByteOrder, ReadBytesExt};
    use futures::stream;
    use futures::{Future, Stream};
    use rand;

    use crate::{Interface, PacketStream};

    use super::*;
    use std::sync::atomic::{AtomicBool, Ordering};

    fn make_packet(ts: usize) -> Packet {
        Packet {
            timestamp: SystemTime::UNIX_EPOCH + Duration::from_millis(ts as _),
            actual_length: 0,
            original_length: 0,
            data: vec![],
        }
    }

    #[test]
    fn packets_from_file() {
        let _ = env_logger::try_init();

        let pcap_path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("resources")
            .join("canary.pcap");

        info!("Testing against {:?}", pcap_path);

        let mut cfg = Config::default();
        cfg.with_interface(Interface::File(pcap_path));

        let packet_stream = PacketStream::try_from(cfg).expect("Failed to build");

        let packet_provider = BridgeStream::new(vec![packet_stream], Duration::from_millis(100), 2)
            .expect("Failed to build");

        let packets = smol::block_on(async move {
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
    fn packets_from_file_next_bridge() {
        let _ = env_logger::try_init();

        let pcap_path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("resources")
            .join("canary.pcap");

        info!("Testing against {:?}", pcap_path);

        let mut cfg = Config::default();
        cfg.with_interface(Interface::File(pcap_path));

        let packet_stream = PacketStream::try_from(cfg).expect("Failed to build");

        let packet_provider = BridgeStream::new(vec![packet_stream], Duration::from_millis(100), 2)
            .expect("Failed to build");

        let packets = smol::block_on(async move {
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
                .filter(|p| p.data().len() == p.actual_length() as usize)
                .count();

            packets
        });

        assert_eq!(packets, 10);
    }

    #[test]
    fn packets_from_lookup_bridge() {
        let _ = env_logger::try_init();

        let cfg = Config::default();
        let packet_stream = PacketStream::try_from(cfg).expect("Failed to build");

        let stream = BridgeStream::new(vec![packet_stream], Duration::from_millis(100), 2);

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
        let packet_stream = PacketStream::try_from(cfg).expect("Failed to build");

        let stream = BridgeStream::new(vec![packet_stream], Duration::from_millis(100), 2);

        assert!(
            stream.is_ok(),
            format!("Could not build stream {}", stream.err().unwrap())
        );
    }

    #[pin_project]
    struct IterStream {
        inner: Vec<Packet>,
        interrupted: AtomicBool,
    }

    impl Interruptable for IterStream {
        fn interrupt(&self) {
            self.interrupted.store(true, Ordering::Relaxed);
        }
    }

    impl Stream for IterStream {
        type Item = StreamItem;

        fn poll_next(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
            let mut this = self;
            if !this.interrupted.load(Ordering::Relaxed) {
                let d = std::mem::replace(&mut this.inner, vec![]);
                this.interrupted.store(true, Ordering::Relaxed);
                return Poll::Ready(Some(Ok(d)));
            } else {
                return Poll::Ready(None);
            }
        }
    }

    #[test]
    fn packets_come_out_time_ordered() {
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

        let stream1 = IterStream {
            interrupted: AtomicBool::default(),
            inner: packets1.clone(),
        };
        let stream2 = IterStream {
            interrupted: AtomicBool::default(),
            inner: packets2.clone(),
        };

        let result = smol::block_on(async move {
            let bridge = BridgeStream::new(vec![stream1, stream2], Duration::from_millis(100), 0);

            let result = bridge
                .expect("Unable to create BridgeStream")
                .collect::<Vec<StreamItem>>()
                .await;
            result
                .into_iter()
                .map(|r| r.unwrap())
                .flatten()
                .collect::<Vec<Packet>>()
        });
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
