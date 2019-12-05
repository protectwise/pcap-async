//! # pcap-async
//!
//! Async/await wrappers [pcap-sys](https://github.com/protectwise/pcap-sys).
//!
//!```no_run
//! use futures::StreamExt;
//! use pcap_async::{Config, Handle, PacketStream};
//! use std::sync::Arc;
//!
//! #[tokio::main]
//! async fn main() {
//!     let handle = Handle::lookup().expect("No handle created");
//!     let mut provider = PacketStream::new(Config::default(), Arc::clone(&handle))
//!         .expect("Could not create provider")
//!         .boxed();
//!     while let Some(packets) = provider.next().await {
//!
//!     }
//!     handle.interrupt();
//! }
#![deny(unused_must_use, unused_imports, bare_trait_objects)]
#![allow(dead_code, unused_imports)]
mod bridge_stream;
pub mod bpf;
mod config;
mod errors;
mod handle;
mod info;
mod packet;
mod packet_future;
pub mod pcap_util;
mod stats;
mod stream;

pub use crate::{
    config::Config, errors::Error, handle::Handle, info::Info, packet::Packet, stats::Stats,
    stream::PacketStream,
};
use failure::Fail;
use log::*;
use std::sync::Arc;

pub fn new_stream(config: Config, handle: Arc<Handle>) -> Result<PacketStream, Error> {
    PacketStream::new(config, handle)
}

#[cfg(test)]
mod tests {
    use super::*;
    use futures::StreamExt;
    use std::path::PathBuf;

    #[tokio::test]
    async fn capture_from_file() {
        let _ = env_logger::try_init();

        let pcap_path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("resources")
            .join("4SICS-GeekLounge-151020.pcap");

        info!("Benchmarking against {:?}", pcap_path.clone());

        let clone_path = pcap_path.clone();

        let handle = Handle::file_capture(clone_path.to_str().expect("No path found"))
            .expect("No handle created");

        let mut cfg = Config::default();
        cfg.with_max_packets_read(5000);

        let packet_provider =
            new_stream(Config::default(), std::sync::Arc::clone(&handle)).expect("Failed to build");
        let fut_packets = packet_provider.collect::<Vec<_>>();
        let packets: Result<Vec<_>, Error> = fut_packets.await.into_iter().collect();
        let packets = packets
            .expect("Could not get packets")
            .iter()
            .flatten()
            .count();

        handle.interrupt();

        assert_eq!(packets, 246137);
    }
}
