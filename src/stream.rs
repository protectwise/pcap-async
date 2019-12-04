use crate::config::Config;
use crate::errors::Error;
use crate::handle::Handle;
use crate::packet::Packet;
use crate::packet_future::PacketFuture;
use crate::pcap_util;

use futures::stream;
use futures::stream::{Stream, StreamExt, Fuse};
use log::*;
use std::collections::VecDeque;
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};

pub struct PacketStream {
    config: Config,
    handle: Arc<Handle>,
    pending: Option<PacketFuture>,
}

impl PacketStream {
    // pub async fn flatten(streams: Vec<PacketStream>) -> Result<Vec<Packet>, Error> {
    //     use futures::stream::TryStreamExt;
    //     let mut combined_stream = stream::select_all(streams);
    //     let mut all_packets: Vec<Packet> = vec![];
    //     while let Some(packets) = combined_stream.try_next().await? {
    //         all_packets.append(&mut packets.clone());
    //     }

    //     Ok(all_packets)
    // }
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
            pending: None,
        })
    }
}

impl Stream for PacketStream {
    type Item = Result<Vec<Packet>, Error>;

    fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        let Self {
            config,
            handle,
            pending,
        } = unsafe { self.get_unchecked_mut() };

        if pending.is_none() {
            *pending = Some(PacketFuture::new(config, handle))
        }
        let p = pending.as_mut().unwrap();
        let pin_pending = unsafe { Pin::new_unchecked(p) };
        let packets = futures::ready!(pin_pending.poll(cx));
        *pending = None;
        let r = match packets {
            Err(e) => Some(Err(e)),
            Ok(None) => {
                debug!("Pcap stream complete");
                None
            }
            Ok(Some(p)) => {
                debug!("Pcap stream produced {} packets", p.len());
                Some(Ok(p))
            }
        };
        Poll::Ready(r)
    }
}

/*
impl<St1, St2> Stream for Select<St1, St2>
    where St1: Stream,
          St2: Stream<Item = St1::Item>
{
    type Item = St1::Item;

    fn poll_next(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<St1::Item>> {
        let Select { flag, stream1, stream2 } =
            unsafe { self.get_unchecked_mut() };
        let stream1 = unsafe { Pin::new_unchecked(stream1) };
        let stream2 = unsafe { Pin::new_unchecked(stream2) };

        if !*flag {
            poll_inner(flag, stream1, stream2, cx)
        } else {
            poll_inner(flag, stream2, stream1, cx)
        }
    }
}*/
struct BridgedStream<St>
{
    streams: VecDeque<St>
}


impl<St: Stream<Item = Result<Vec<Packet>, Error>> + Unpin> Stream for BridgedStream<St> { //where St: Stream<Item = Result<Vec<Packet>, Error>> {
    type Item = Result<Vec<Packet>, Error>;

    fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        let this = unsafe { self.get_unchecked_mut() };
        let stream_size = this.streams.len();
        let mut interface_buffers: Vec<VecDeque<Packet>> = vec![VecDeque::new(); stream_size];

        let stream_iter = this.streams.iter_mut().enumerate();

        for (buffer_idx, mut stream) in stream_iter {
            let current_value: Poll<Option<Result<Vec<Packet>, Error>>> = Pin::new(&mut stream).poll_next(cx);
            match current_value {
                Poll::Pending => {
                    //do nothing and skip the population

                }
                Poll::Ready(Some(Result::Ok(packets))) => {
                    interface_buffers[buffer_idx].extend(packets); //build the results for this run
                }
                Poll::Ready(Some(Result::Err(err))) => {
                    return Poll::Ready(Some(Result::Err(err))); //if anything errors stop the stream
                }
                _ => {
                    //TODO handle the None case from a stream... also use Streams Fused trait to prevent craziness
                }
            }
        }

        while !interface_buffers.is_empty() {
            let mut canidate_buffer: Option<(&VecDeque<Packet>, std::time::SystemTime)> = Option::None;

            for interface_buffer in interface_buffers.iter() {
                match interface_buffer.get(0) {
                    Some(packet) => {
                        let packet_ts = *packet.timestamp();

                        canidate_buffer = canidate_buffer.map(|(current_buffer, ts)| {
                            if ts > packet_ts { //if the cannidate timestamp is greater than the current timestamp replace the canidate timestamp
                                (interface_buffer, packet_ts)
                            } else {
                                (current_buffer, ts)
                            }
                        });
                    }
                    _ => {

                    }

                }
            }
        }
        
        // for buffer_idx in 0..stream_size {
        //     let current_stream_option = this.streams.pop_front();
        //     match current_stream_option {
        //         Some(mut current_stream) => {
        //             let current_value: Poll<Option<Result<Vec<Packet>, Error>>> = Pin::new(&mut current_stream).poll_next(cx);
        //             match current_value {
        //                 Poll::Pending => {
        
        //                 }
        //                 Poll::Ready(Some(Result::Ok(packets))) => {
        //                     interface_buffers[buffer_idx].extend(packets);
        //                 }
        //                 _ => {}
        //             }
        //         }
        //         None => {

        //         }

        //     }
        // }
        
        Poll::Ready(None)

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
