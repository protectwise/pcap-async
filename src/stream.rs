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
use std::time::SystemTime;

use tokio_timer::Delay;

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

struct BridgedStream<St>
{
    delay: std::time::Duration,
    streams: Vec<St>,
    buffers: Vec<Vec<Packet>>,
    pending: Option<Delay>,
    roll_over: Vec<Packet>
}
//#![feature(drain_filter)]
impl <St: Stream<Item = Result<Vec<Packet>, Error>> + Unpin> BridgedStream<St> {

    // fn determine_min_max(buffers: &mut Vec<Vec<Packet>>) -> Option<&SystemTime> {
    //     let mut min_max_opt: Option<&SystemTime> = Option::None;
    //     for buf in buffers.iter() {
    //         let last_opt = buf.get(buf.len() - 1);
    //         min_max = last_opt.and_then(|last| {
    //             match min_max {
    //                 Some(prev) if last.timestamp() > prev => {
    //                     Some(prev)
    //                 }
    //                 None => {
    //                     Some(last.timestamp())
    //                 }
    //                 Some(prev) => {
    //                     Some(prev)
    //                 }
    //             }
    //         })
    //     }
    //     match min_max_opt {
    //         Some(min_max) => {
    //             for buf in buffers.iter_mut() {
    //                 buf.drain_filter(|packet| packet.timestamp() > min_max)
    //             }

    //         }
    //     }
    //     min_max
    // }
}


impl<St: Stream<Item = Result<Vec<Packet>, Error>> + Unpin> Stream for BridgedStream<St> { //where St: Stream<Item = Result<Vec<Packet>, Error>> {
    type Item = Result<Vec<Packet>, Error>;

    fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        let this = unsafe { self.get_unchecked_mut() };
        //let min_max = this.clone().determine_min_max();
        let stream_iter = this.streams.iter_mut().enumerate();


        match &mut this.pending {
            Some(p) => {
                trace!("Checking if delay is ready");
                //let pinned = unsafe { Pin::new_unchecked(p) };
                for (buffer_idx, mut stream) in stream_iter {
                    let current_value: Poll<Option<Result<Vec<Packet>, Error>>> = Pin::new(&mut stream).poll_next(cx);
                    match current_value {
                        Poll::Pending => {
                            //do nothing and skip the population
        
                        }
                        Poll::Ready(Some(Result::Ok(packets))) => {
                            match this.buffers.get_mut(buffer_idx) {
                                Some(existing) => {
                                    existing.extend(packets);
                                }
                                None => {
                                    this.buffers[buffer_idx] = packets;
                                }
                            }
                        }
                        Poll::Ready(Some(Result::Err(err))) => {
                            return Poll::Ready(Some(Result::Err(err))); //if anything errors stop the stream
                        }
                        Poll::Ready(None) => {
                            // this.completed += 1;
                            // if this.completed == stream_size {
                            //     return Poll::Ready(None);
                            // }
                        }
                    }
                }
                let polled = Pin::new( p).poll(cx);
                futures::ready!(polled);
                debug!("Delay complete");
                this.pending = None

            }
            None => {
                //let min_max = BridgedStream::<St>::determine_min_max(&mut this.buffers);
                
                this.pending = Some(tokio_timer::delay_for(this.delay));

            }
        }

     




        // let mut buffer: Vec<Vec<Packet>> = vec![vec![]; streams.len()];
        // let mut max_per_buffer: Vec<Option<SystemTime>> = vec![None; stream_size];

        // match this.pending {
        //     Some(p) => {
        //         trace!("Checking if delay is ready");
        //         let pinned = unsafe { Pin::new_unchecked(p) };
        //         for (buffer_idx, mut stream) in stream_iter {
        //         }
                

        //         futures::ready!(pinned.poll(cx)); //this macros will short circuit at this point if the future is not reaady
        //         debug!("Delay complete");
        //         *this.pending = None;
        //     }
        //     case None =>
        // }

        // //TODO need to impliment the min of max per buffer and store the overflow elsewhere

        // let stream_iter = this.streams.iter_mut().enumerate();

        // for (buffer_idx, mut stream) in stream_iter {
        //     let current_value: Poll<Option<Result<Vec<Packet>, Error>>> = Pin::new(&mut stream).poll_next(cx);
        //     match current_value {
        //         Poll::Pending => {
        //             //do nothing and skip the population

        //         }
        //         Poll::Ready(Some(Result::Ok(packets))) => {
        //             let max_packet_timestamp = packets.get(packets.len() - 1).map(|packet| packet.timestamp()).unwrap_or(&SystemTime::UNIX_EPOCH);
        //             max_per_buffer[buffer_idx] = Some(max_packet_timestamp.clone());
        //             buffer.extend(packets); //build the results for this run
        //         }
        //         Poll::Ready(Some(Result::Err(err))) => {
        //             return Poll::Ready(Some(Result::Err(err))); //if anything errors stop the stream
        //         }
        //         Poll::Ready(None) => {
        //             this.completed += 1;
        //             if this.completed == stream_size {
        //                 return Poll::Ready(None);
        //             }
        //         }
        //     }
        // }

        // buffer.sort();

 
        
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
