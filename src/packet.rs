pub struct Packet {
    timestamp: std::time::SystemTime,
    actual_length: u32,
    original_length: u32,
    data: Vec<u8>,
}

impl Packet {
    pub fn into_data(self) -> Vec<u8> { self.data }
    pub fn timestamp(&self) -> &std::time::SystemTime {
        &self.timestamp
    }
    pub fn data(&self) -> &Vec<u8> {
        &self.data
    }
    pub fn actual_length(&self) -> u32 {
        self.actual_length
    }
    pub fn original_length(&self) -> u32 {
        self.original_length
    }

    pub fn new(
        timestamp: std::time::SystemTime,
        actual_length: u32,
        original_length: u32,
        data: Vec<u8>,
    ) -> Packet {
        Packet {
            timestamp: timestamp,
            actual_length: actual_length,
            original_length: original_length,
            data,
        }
    }
}
