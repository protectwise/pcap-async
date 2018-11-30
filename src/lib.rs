#![allow(dead_code, unused_imports)]
#![recursion_limit = "1024"]
#![feature(duration_as_u128, ptr_internals, test, futures_api, pin, async_await, await_macro)]
#[macro_use] extern crate error_chain;

pub mod errors {
    use std;

    // Create the Error, ErrorKind, ResultExt, and Result types
    error_chain! {
        foreign_links {
            Io(std::io::Error) #[doc = "Error during IO"];
            Ffi(std::ffi::NulError) #[doc = "Error during FFI conversion"];
            Utf8(std::str::Utf8Error) #[doc = "Error during UTF8 conversion"];
            TokioTimer(tokio_timer::Error) #[doc = "Tokio timer error"];
        }
        errors {
            CreatePacketHeader {
                display("Libpcap failed to populate header")
            }
            LibPcapError(msg: String) {
                display("Libpcap encountered an error: {}", msg)
            }
            Poll {
                display("Error while polling")
            }
            LiveCapture(iface: String) {
                display("Could not create live extraction from {}", iface)
            }
            FileCapture(file: String) {
                display("Could not create extraction from {}", file)
            }
            NoMorePackets {
                display("Interface did not return packets")
            }
            TimeoutExpired {
                display("Timeout expired when capturing from interface")
            }
            NullPtr {
                display("Error returned a null pointer")
            }
            BpfCompile(bpf: String) {
                display("Could not compile bpf {}", bpf)
            }
            SetBpf(bpf: String) {
                display("Could not set bpf {}", bpf)
            }
            SetNonBlock {
                display("Could not set non block")
            }
            SetSnapLength {
                display("Could not set snap length")
            }
            SetBufferSize {
                display("Could not set buffer size")
            }
            SetPromiscuous {
                display("Could not set promiscuous")
            }
            SetTimeout {
                display("Could not set timeout")
            }
            Interrupted {
                display("Interrupted fired")
            }
            SendFailed {
                display("Channel send failed")
            }
            JoinFailed {
                display("Join thread failed")
            }
            ReceiveFailed {
                display("Channel receive failed")
            }
            Poison {
                display("Mutex is poisoned")
            }
        }
    }
}

pub mod config;
pub mod handle;
pub mod packet;
pub mod pcap_util;

pub use crate::{
    handle::Handle as Handle,
    config::Config as Config,
    packet::Packet as Packet,
    packet::PacketStream as PacketStream
};