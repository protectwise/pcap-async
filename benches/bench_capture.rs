#![deny(unused_must_use, unused_imports, bare_trait_objects)]
use criterion::{criterion_group, criterion_main, Bencher, Criterion};
use futures::StreamExt;
use log::*;
use pcap_async::{BridgeStream, Config, Handle, PacketStream};
use std::path::PathBuf;

fn bench_stream_from_large_file(b: &mut Bencher) {
    let _ = env_logger::try_init();

    let pcap_path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("resources")
        .join("4SICS-GeekLounge-151020.pcap");

    info!("Benchmarking against {:?}", pcap_path.clone());

    b.iter(|| {
        let mut rt = tokio::runtime::Runtime::new().expect("Failed to create runtime");

        let clone_path = pcap_path.clone();

        let handle = Handle::file_capture(clone_path.to_str().expect("No path found"))
            .expect("No handle created");

        let mut cfg = Config::default();
        cfg.with_max_packets_read(5000);

        let packet_provider = PacketStream::new(Config::default(), std::sync::Arc::clone(&handle))
            .expect("Failed to build");
        let packets = rt.block_on(packet_provider.collect::<Vec<_>>());
        let packets: Result<Vec<_>, pcap_async::Error> = packets.into_iter().collect();
        let packets = packets
            .expect("Failed to get packets")
            .iter()
            .flatten()
            .count();

        handle.interrupt();

        assert_eq!(packets, 246137);
    });
}

fn bench_stream(c: &mut Criterion) {
    let benchmark = criterion::Benchmark::new("4sics", bench_stream_from_large_file);

    c.bench(
        "stream",
        benchmark
            .sample_size(20)
            .nresamples(1)
            .measurement_time(std::time::Duration::from_secs(15)),
    );
}

fn bench_stream_next_from_large_file_bridge(b: &mut Bencher) {
    let _ = env_logger::try_init();

    let pcap_path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("resources")
        .join("4SICS-GeekLounge-151020.pcap");

    info!("Benchmarking against {:?}", pcap_path.clone());

    b.iter(|| {
        let mut rt = tokio::runtime::Runtime::new().expect("Failed to create runtime");

        let clone_path = pcap_path.clone();

        let handle1 = Handle::file_capture(clone_path.to_str().expect("No path found"))
            .expect("No handle created");

        let handle2 = Handle::file_capture(clone_path.to_str().expect("No path found"))
            .expect("No handle created");

        let mut cfg = Config::default();
        cfg.with_max_packets_read(5000);

        let streams = vec![handle1.clone(), handle2.clone()]
            .into_iter()
            .map(|h| PacketStream::new(Config::default(), h).unwrap())
            .collect();

        let packet_provider = BridgeStream::new(Config::default().retry_after().clone(), streams)
            .expect("Failed to build");
        let fut_packets = async move {
            let mut packet_provider = packet_provider.boxed();
            let mut packets = vec![];
            while let Some(p) = packet_provider.next().await {
                let p = p.expect("Could not get packets");
                packets.extend(p);
            }
            packets
        };
        let packets = rt.block_on(fut_packets).len();

        handle1.interrupt();
        handle2.interrupt();

        assert_eq!(packets, 246137 * 2);
    });
}

fn bench_stream_next_from_large_file(b: &mut Bencher) {
    let _ = env_logger::try_init();

    let pcap_path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("resources")
        .join("4SICS-GeekLounge-151020.pcap");

    info!("Benchmarking against {:?}", pcap_path.clone());

    b.iter(|| {
        let mut rt = tokio::runtime::Runtime::new().expect("Failed to create runtime");

        let clone_path = pcap_path.clone();

        let handle = Handle::file_capture(clone_path.to_str().expect("No path found"))
            .expect("No handle created");

        let mut cfg = Config::default();
        cfg.with_max_packets_read(5000);

        let packet_provider = PacketStream::new(Config::default(), std::sync::Arc::clone(&handle))
            .expect("Failed to build");
        let fut_packets = async move {
            let mut packet_provider = packet_provider.boxed();
            let mut packets = vec![];
            while let Some(p) = packet_provider.next().await {
                let p = p.expect("Could not get packets");
                packets.extend(p);
            }
            packets
        };
        let packets = rt.block_on(fut_packets).len();

        handle.interrupt();

        assert_eq!(packets, 246137);
    });
}

fn bench_stream_next_bridge(c: &mut Criterion) {
    let benchmark =
        criterion::Benchmark::new("4sics-bridge", bench_stream_next_from_large_file_bridge);

    c.bench(
        "stream_next",
        benchmark
            .sample_size(20)
            .nresamples(1)
            .measurement_time(std::time::Duration::from_secs(15)),
    );
}

fn bench_stream_next(c: &mut Criterion) {
    let benchmark = criterion::Benchmark::new("4sics", bench_stream_next_from_large_file);

    c.bench(
        "stream_next",
        benchmark
            .sample_size(20)
            .nresamples(1)
            .measurement_time(std::time::Duration::from_secs(15)),
    );
}

criterion_group!(
    benches,
    bench_stream,
    bench_stream_next,
    bench_stream_next_bridge
);

// Benchmark: cargo bench --verbose

criterion_main!(benches);
