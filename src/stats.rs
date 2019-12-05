#[derive(Clone, Debug)]
pub struct Stats {
    pub received: u32,
    pub dropped_by_kernel: u32,
    pub dropped_by_interface: u32,
}

pub const EMPTY_STATS: Stats = Stats{ received: 0, dropped_by_kernel: 0, dropped_by_interface: 0 };

impl Stats {
    fn combine(&self, other: &Stats) -> Stats {
        Stats {
            received: self.received + other.received,
            dropped_by_kernel: self.dropped_by_kernel + other.dropped_by_kernel,
            dropped_by_interface: self.dropped_by_interface + other.dropped_by_interface
        }
    }
}
