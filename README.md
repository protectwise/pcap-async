# pcap-async

[![build status][travis-badge]][travis-url]
[![crates.io version][crates-badge]][crates-url]
[![docs.rs docs][docs-badge]][docs-url]
[![MIT licensed][mit-badge]][mit-url]

Rust async wrapper around [pcap-sys](https://github.com/protectwise/pcap-sys). Utilizes [Futures 0.3](https://github.com/rust-lang-nursery/futures-rs) and [Smol](https://github.com/stjepang/smol).

[Documentation](https://docs.rs/pcap-async/latest/)

[travis-badge]: https://travis-ci.com/protectwise/pcap-async.svg?branch=master
[travis-url]: https://travis-ci.com/protectwise/pcap-async
[crates-badge]: https://img.shields.io/crates/v/pcap-async.svg?style=flat-square
[crates-url]: https://crates.io/crates/pcap-async
[docs-badge]: https://img.shields.io/badge/docs.rs-latest-blue.svg?style=flat-square
[docs-url]: https://docs.rs/pcap-async
[mit-badge]: https://img.shields.io/badge/license-MIT-blue.svg?style=flat-square
[mit-url]: LICENSE-MIT

## Usage

First, add this to your `Cargo.toml`:

```toml
[dependencies]
pcap-async = "0.5"
```

Next, add this to your crate:

```rust
use futures::StreamExt;
use pcap_async::{Config, Handle, PacketStream};
use std::convert::TryFrom;

fn main() {
    smol::run(async move {
        let cfg = Config::default();
        let mut provider = PacketStream::try_from(cfg)
            .expect("Could not create provider");
        while let Some(packets) = provider.next().await {
    
        }
        provider.interrupt();
    })
}
```
