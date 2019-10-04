#[derive(Clone, Debug)]
pub struct Stats {
    pub received: u32,
    pub dropped_by_kernel: u32,
    pub dropped_by_interface: u32,
}
