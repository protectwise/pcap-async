use crate::Error;

use byteorder::{ByteOrder, WriteBytesExt};
use futures::AsyncWriteExt;
use std::io::Cursor;
use std::cmp::Ordering;

#[derive(Clone, Debug, Eq)]
pub struct Packet {
    timestamp: std::time::SystemTime,
    actual_length: u32,
    original_length: u32,
    data: Vec<u8>,
}

impl PartialEq for Packet {
    fn eq(&self, other: &Self) -> bool {
        self.timestamp() == other.timestamp()
    }
}

impl PartialOrd for Packet {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

//impl Eq for Packet {}

impl Ord for Packet {
    fn cmp(&self, other: &Self) -> Ordering {
        return self.timestamp().cmp(other.timestamp());
    }
}

impl Packet {
    pub fn into_data(self) -> Vec<u8> {
        self.data
    }
    pub fn into_pcap_record<T: ByteOrder>(self) -> Result<Vec<u8>, Error> {
        let dur = self
            .timestamp
            .duration_since(std::time::UNIX_EPOCH)
            .map_err(Error::Time)?;
        let data = Vec::with_capacity(self.data.len() + 4 * std::mem::size_of::<u32>());
        let mut cursor = Cursor::new(data);
        cursor
            .write_u32::<T>(dur.as_secs() as _)
            .map_err(Error::Io)?;
        cursor
            .write_u32::<T>(dur.subsec_micros())
            .map_err(Error::Io)?;
        cursor
            .write_u32::<T>(self.actual_length)
            .map_err(Error::Io)?;
        cursor
            .write_u32::<T>(self.original_length)
            .map_err(Error::Io)?;
        let mut res = cursor.into_inner();
        res.extend(self.data);
        Ok(res)
    }
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

#[cfg(test)]
mod tests {
    use super::*;
    use byteorder::ReadBytesExt;
    use std::io::Read;
    use std::time::SystemTime;

    #[test]
    fn converts_to_record() {
        let ts = SystemTime::now();
        let data = vec![0u8; 100];
        let packet = Packet {
            timestamp: ts,
            actual_length: 100,
            original_length: 200,
            data: data.clone(),
        };
        let bytes = packet
            .into_pcap_record::<byteorder::LittleEndian>()
            .expect("Failed to convert to record");

        let dur = ts
            .duration_since(std::time::UNIX_EPOCH)
            .expect("Could not convert to dur");

        let mut cursor = Cursor::new(bytes);
        assert_eq!(
            cursor
                .read_u32::<byteorder::LittleEndian>()
                .expect("Failed to read"),
            dur.as_secs() as u32
        );
        assert_eq!(
            cursor
                .read_u32::<byteorder::LittleEndian>()
                .expect("Failed to read"),
            dur.subsec_micros()
        );
        assert_eq!(
            cursor
                .read_u32::<byteorder::LittleEndian>()
                .expect("Failed to read"),
            100
        );
        assert_eq!(
            cursor
                .read_u32::<byteorder::LittleEndian>()
                .expect("Failed to read"),
            200
        );
        let mut read_data = vec![];
        assert_eq!(
            cursor.read_to_end(&mut read_data).expect("Failed to read"),
            100
        );
        assert_eq!(read_data, data);
    }
}
