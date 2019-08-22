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
pub mod bpf;
mod config;
mod errors;
mod handle;
mod packet;
mod packet_future;
pub mod pcap_util;
mod stats;
mod stream;

pub use crate::{
    config::Config, errors::Error, handle::Handle, packet::Packet, stats::Stats,
    stream::PacketStream,
};
use failure::Fail;
use log::*;
use std::sync::Arc;

pub fn new_stream(config: Config, handle: Arc<Handle>) -> Result<PacketStream, Error> {
    PacketStream::new(config, handle)
}

/// List available devices by name, that match a filter against the name of the interface
pub fn list_devices<F>(filter: F) -> Result<Vec<String>, errors::Error>
where
    F: Fn(&str) -> bool,
{
    let mut err_buf = vec![0u8 as std::os::raw::c_char; pcap_sys::PCAP_ERRBUF_SIZE as _];
    let mut device_result: *mut pcap_sys::pcap_if_t = std::ptr::null_mut();

    unsafe {
        let buf = std::mem::transmute::<&mut *mut pcap_sys::pcap_if_t, *mut *mut pcap_sys::pcap_if_t>(
            &mut device_result,
        );
        if 0 != pcap_sys::pcap_findalldevs(buf, err_buf.as_mut_ptr()) {
            let err: Vec<_> = err_buf.iter().map(|v| *v as u8).collect();
            let err_str =
                std::ffi::CStr::from_bytes_with_nul(err.as_ref()).map_err(errors::Error::FfiNul)?;
            let utf_str = err_str.to_str().map_err(errors::Error::Utf8)?;
            return Err(errors::Error::LibPcapError {
                msg: utf_str.to_owned(),
            });
        }
    }

    let mut result = vec![];

    while device_result != std::ptr::null_mut() {
        let device_name_ptr = unsafe { (*device_result).name };
        let device_name = pcap_util::cstr_to_string(device_name_ptr)?;
        if filter(&device_name) {
            result.push(device_name);
        }
        device_result = unsafe { (*device_result).next };
    }

    return Ok(result);
}

#[cfg(test)]
mod tests {
    use super::*;
    use futures::StreamExt;
    use std::path::PathBuf;

    #[test]
    fn test_list_devices() {
        let devices = list_devices(|_| true).expect("Failed to list");

        println!("Devices={:?}", devices);

        assert!(devices.is_empty() == false);
    }

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
