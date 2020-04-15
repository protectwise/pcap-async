mod container;
mod iterator;

pub use container::Container as Packets;
pub use iterator::{PacketIteratorItem, PacketIterator};

use crate::Error;

use byteorder::{ByteOrder, WriteBytesExt};
use futures::AsyncWriteExt;
use std::io::Cursor;

#[derive(Clone, Debug)]
pub struct Packet {
    pub(crate) timestamp: std::time::SystemTime,
    pub(crate) actual_length: u32,
    pub(crate) original_length: u32,
    pub(crate) data: Vec<u8>,
}

impl Packet {
    pub fn into_pcap_record<T: ByteOrder>(self) -> Result<Vec<u8>, Error> {
        self.as_pcap_record::<T>()
    }

    pub fn as_pcap_record<T: ByteOrder>(&self) -> Result<Vec<u8>, Error> {
        let data = Vec::with_capacity(self.data.len() + 4 * std::mem::size_of::<u32>());
        let mut cursor = Cursor::new(data);
        self.write_pcap_record::<T, Cursor<Vec<u8>>>(&mut cursor)?;
        Ok(cursor.into_inner())
    }

    pub fn write_pcap_record<B: ByteOrder, C: WriteBytesExt>(
        &self,
        cursor: &mut C,
    ) -> Result<(), Error> {
        let dur = self
            .timestamp
            .duration_since(std::time::UNIX_EPOCH)
            .map_err(Error::Time)?;

        cursor
            .write_u32::<B>(dur.as_secs() as _)
            .map_err(Error::Io)?;
        cursor
            .write_u32::<B>(dur.subsec_micros())
            .map_err(Error::Io)?;
        cursor
            .write_u32::<B>(self.actual_length)
            .map_err(Error::Io)?;
        cursor
            .write_u32::<B>(self.original_length)
            .map_err(Error::Io)?;
        cursor.write(self.data.as_slice()).map_err(Error::Io)?;
        Ok(())
    }

    pub fn timestamp(&self) -> &std::time::SystemTime {
        &self.timestamp
    }
    pub fn data(&self) -> &[u8] {
        self.data.as_slice()
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
        let packet = Packet {
            timestamp: ts,
            actual_length: 100,
            original_length: 200,
            data: vec![0u8; 100],
        };
        let bytes = packet
            .as_pcap_record::<byteorder::LittleEndian>()
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
        assert_eq!(read_data, packet.data);
    }
}
