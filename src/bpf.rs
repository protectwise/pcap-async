/// Wrapper for bpf_program to ensure correct drops
#[derive(Debug)]
pub struct Bpf {
    inner: pcap_sys::bpf_program,
}

impl Bpf {
    pub fn new(inner: pcap_sys::bpf_program) -> Bpf {
        Bpf {
            inner
        }
    }
    pub fn inner_mut(&mut self) -> &mut pcap_sys::bpf_program {
        &mut self.inner
    }
}

impl Drop for Bpf {
    fn drop(&mut self) {
        unsafe {
            pcap_sys::pcap_freecode(&mut self.inner);
        }
    }
}