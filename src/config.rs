use std;

pub struct Config {
    max_packets_read: usize,
    snaplen: u32,
    timeout: std::time::Duration,
    buffer_size: u32,
    bpf: Option<String>,
    retry_after: std::time::Duration
}

impl Config {
    pub fn max_packets_read(&self) -> usize { self.max_packets_read }

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

    pub fn timeout(&self) -> &std::time::Duration {
        &self.timeout
    }

    pub fn with_timeout(&mut self, amt: std::time::Duration) -> &mut Self {
        self.timeout = amt;
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

    pub fn with_bf(&mut self, amt: String) -> &mut Self {
        self.bpf = Some(amt);
        self
    }

    pub fn retry_after(&self) -> &std::time::Duration { &self.retry_after }

    pub fn with_retry_after(&mut self, amt: std::time::Duration) -> &mut Self {
        self.retry_after = amt;
        self
    }

    pub fn new(
        max_packets_read: usize,
        snaplen: u32,
        timeout: std::time::Duration,
        buffer_size: u32,
        bpf: Option<String>,
        retry_after: std::time::Duration,
    ) -> Config {
        Config {
            max_packets_read,
            snaplen,
            timeout,
            buffer_size,
            bpf,
            retry_after
        }
    }
}

impl Default for Config {
    fn default() -> Config {
        Config {
            max_packets_read: 1000,
            snaplen: 65535,
            timeout: std::time::Duration::from_millis(100),
            buffer_size: 16777216,
            bpf: None,
            retry_after: std::time::Duration::from_millis(100)
        }
    }
}
