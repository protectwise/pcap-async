use std;

#[derive(Clone, Debug)]
pub struct Config {
    max_packets_read: usize,
    snaplen: u32,
    buffer_size: u32,
    bpf: Option<String>,
    buffer_for: std::time::Duration,
    blocking: bool,
}

impl Config {
    pub fn max_packets_read(&self) -> usize {
        self.max_packets_read
    }

    pub fn with_max_packets_read(&mut self, amt: usize) -> &mut Self {
        self.max_packets_read = amt;
        self
    }

    pub fn snaplen(&self) -> u32 {
        self.snaplen
    }

    pub fn with_snaplen(&mut self, amt: u32) -> &mut Self {
        self.snaplen = amt;
        self
    }

    pub fn buffer_size(&self) -> u32 {
        self.buffer_size
    }

    pub fn with_buffer_size(&mut self, amt: u32) -> &mut Self {
        self.buffer_size = amt;
        self
    }

    pub fn bpf(&self) -> &Option<String> {
        &self.bpf
    }

    pub fn with_bpf(&mut self, amt: String) -> &mut Self {
        self.bpf = Some(amt);
        self
    }

    pub fn buffer_for(&self) -> &std::time::Duration {
        &self.buffer_for
    }

    pub fn with_buffer_for(&mut self, amt: std::time::Duration) -> &mut Self {
        self.buffer_for = amt;
        self
    }

    pub fn blocking(&self) -> bool {
        self.blocking
    }

    pub fn with_blocking(&mut self, blocking: bool) -> &mut Self {
        self.blocking = blocking;
        self
    }

    pub fn new(
        max_packets_read: usize,
        snaplen: u32,
        buffer_size: u32,
        bpf: Option<String>,
        buffer_for: std::time::Duration,
        blocking: bool,
    ) -> Config {
        Config {
            max_packets_read,
            snaplen,
            buffer_size,
            bpf,
            buffer_for,
            blocking,
        }
    }
}

impl Default for Config {
    fn default() -> Config {
        Config {
            max_packets_read: 1000,
            snaplen: 65535,
            buffer_size: 16777216,
            bpf: None,
            buffer_for: std::time::Duration::from_millis(100),
            blocking: false,
        }
    }
}
