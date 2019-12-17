#[derive(Clone, Debug, Default)]
pub struct Stats {
    pub received: u32,
    pub dropped_by_kernel: u32,
    pub dropped_by_interface: u32,
}

impl Stats {
    pub fn combine(&self, other: &Stats) -> Stats {
        Stats {
            received: self.received + other.received,
            dropped_by_kernel: self.dropped_by_kernel + other.dropped_by_kernel,
            dropped_by_interface: self.dropped_by_interface + other.dropped_by_interface,
        }
    }
}
