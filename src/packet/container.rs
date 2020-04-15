use crate::Packet;

pub struct Container {
    inner: Vec<Packet>,
}

impl Container {
    pub fn new(max_packets_read: usize, _snaplen: u32) -> Self {
        Self {
            inner: Vec::with_capacity(max_packets_read),
        }
    }

    pub fn timestamp(&self) -> &std::time::SystemTime {
        self.inner.last().map(|p| p.timestamp()).unwrap_or(&std::time::UNIX_EPOCH)
    }

    pub fn push(&mut self, packet: Packet) {
        self.inner.push(packet);
    }

    pub fn is_empty(&self) -> bool {
        self.inner.is_empty()
    }

    pub fn len(&self) -> usize {
        self.inner.len()
    }

    pub fn into_inner(self) -> Vec<Packet> {
        self.inner
    }
}