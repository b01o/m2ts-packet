use tokio_util::codec::Decoder;

use crate::*;

pub struct TsPacket {
    pub header: TransportStreamHeader,
    pub adaptation_field: Option<AdaptationField>,
    pub payload: Bytes,
}

impl std::fmt::Debug for TsPacket {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TsPacket")
            .field("header", &self.header)
            .field("adaptation_field", &self.adaptation_field)
            .field("payload_len", &self.payload.len())
            .finish()
    }
}

impl TsPacket {
    pub const PACKET_SIZE: usize = 188;
    pub fn from_bytes(data: Bytes) -> Option<Self> {
        if data.len() < Self::PACKET_SIZE {
            return None;
        }
        let header =
            TransportStreamHeader::from_bits(u32::from_be_bytes(data.get(0..4)?.try_into().ok()?));
        if header.sync_byte() != 0x47 {
            return None;
        }
        let mut adaption_field = None;
        let mut index = 4;
        if header.adaptation_field() {
            let adaption_field_length = *data.get(index)? as usize;
            index += 1;
            if index + adaption_field_length > data.len() {
                return None;
            }
            if adaption_field_length > 0 {
                let field_data = data.slice(index..index + adaption_field_length);
                index += adaption_field_length;
                adaption_field = Some(AdaptationField::from_bytes(field_data)?);
            }
        }
        Some(Self {
            header,
            adaptation_field: adaption_field,
            payload: data.slice(index..Self::PACKET_SIZE),
        })
    }
}

/// Decoder that reads 188-byte MPEG-TS packets from a byte stream.
pub struct TsPacketDecoder {
    pub stream_position: u64,
}

impl TsPacketDecoder {
    pub fn new(stream_position: u64) -> Self {
        Self { stream_position }
    }
}

impl Decoder for TsPacketDecoder {
    type Item = (u64, TsPacket);
    type Error = TsPacketError;
    fn decode(&mut self, src: &mut BytesMut) -> Result<Option<Self::Item>> {
        if src.len() < TsPacket::PACKET_SIZE {
            return Ok(None);
        }

        // Scan for a valid sync byte: 0x47 at current position AND 0x47 at +PACKET_SIZE
        // (or current position is at end-of-buffer, in which case we accept a single sync).
        loop {
            // Skip non-0x47 bytes
            while !src.is_empty() && src[0] != 0x47 {
                self.stream_position += 1;
                src.advance(1);
            }

            if src.len() < TsPacket::PACKET_SIZE {
                return Ok(None);
            }

            // Verify: the byte at +PACKET_SIZE should also be 0x47 (if data available),
            // otherwise this 0x47 is likely a false positive.
            if src.len() > TsPacket::PACKET_SIZE && src[TsPacket::PACKET_SIZE] != 0x47 {
                // False sync — skip this byte and continue scanning
                self.stream_position += 1;
                src.advance(1);
                continue;
            }

            break;
        }

        let position = self.stream_position;
        self.stream_position += TsPacket::PACKET_SIZE as u64;

        let packet = TsPacket::from_bytes(src.split_to(TsPacket::PACKET_SIZE).freeze())
            .ok_or(TsPacketError::InvalidPacket)?;
        Ok(Some((position, packet)))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a minimal valid 188-byte TS packet with payload only (no adaptation field).
    /// PID = pid, continuity_counter = cc, payload filled with `fill`.
    fn make_packet(pid: u16, cc: u8, fill: u8) -> [u8; TsPacket::PACKET_SIZE] {
        let mut buf = [fill; TsPacket::PACKET_SIZE];
        // Header: sync=0x47, TEI=0, PUSI=0, priority=0, PID=pid,
        //         scrambling=00, adaptation_field=0, payload=1, cc
        buf[0] = 0x47;
        buf[1] = (pid >> 8) as u8 & 0x1F; // top 5 bits of PID
        buf[2] = pid as u8; // low 8 bits of PID
        // byte 3: scrambling(2)=00, AF(1)=0, payload(1)=1, cc(4)
        buf[3] = 0x10 | (cc & 0x0F);
        buf
    }

    /// Build a 188-byte TS packet with an adaptation field (flags only, rest stuffing).
    fn make_packet_with_af(pid: u16, af_len: u8, af_flags: u8) -> [u8; TsPacket::PACKET_SIZE] {
        let mut buf = [0xFF; TsPacket::PACKET_SIZE];
        buf[0] = 0x47;
        buf[1] = (pid >> 8) as u8 & 0x1F;
        buf[2] = pid as u8;
        // AF=1, payload=1
        buf[3] = 0x30;
        buf[4] = af_len;
        if af_len > 0 {
            buf[5] = af_flags;
        }
        buf
    }

    // ------- TsPacket::from_bytes tests -------

    #[test]
    fn test_from_bytes_valid_payload_only() {
        let pkt = make_packet(0x100, 3, 0xAB);
        let ts = TsPacket::from_bytes(Bytes::copy_from_slice(&pkt)).unwrap();
        assert_eq!(ts.header.pid(), 0x100);
        assert_eq!(ts.header.continuity_counter(), 3);
        assert!(ts.header.payload());
        assert!(!ts.header.adaptation_field());
        assert!(ts.adaptation_field.is_none());
        assert_eq!(ts.payload.len(), 184); // 188 - 4
    }

    #[test]
    fn test_from_bytes_with_adaptation_field() {
        let pkt = make_packet_with_af(0x01, 7, 0x10); // af_flags=PCR set
        // We need valid PCR bytes; the make helper fills with 0xFF which is fine for PCR data
        let ts = TsPacket::from_bytes(Bytes::copy_from_slice(&pkt)).unwrap();
        assert!(ts.header.adaptation_field());
        assert!(ts.adaptation_field.is_some());
        let af = ts.adaptation_field.unwrap();
        assert!(af.flags.pcr_flag());
    }

    #[test]
    fn test_from_bytes_bad_sync_returns_none() {
        let mut pkt = make_packet(0x00, 0, 0);
        pkt[0] = 0x00; // corrupt sync byte
        assert!(TsPacket::from_bytes(Bytes::copy_from_slice(&pkt)).is_none());
    }

    #[test]
    fn test_from_bytes_too_short_returns_none() {
        assert!(TsPacket::from_bytes(Bytes::from_static(&[0x47, 0x00, 0x00, 0x10])).is_none());
    }

    // ------- TsPacketDecoder tests -------

    #[test]
    fn test_decoder_not_enough_data() {
        let mut decoder = TsPacketDecoder::new(0);
        let mut buf = BytesMut::from(&[0x47u8; 100][..]);
        let result = decoder.decode(&mut buf).unwrap();
        assert!(result.is_none());
        // Buffer should not be consumed
        assert_eq!(buf.len(), 100);
    }

    #[test]
    fn test_decoder_exact_packet() {
        let mut decoder = TsPacketDecoder::new(0);
        let pkt = make_packet(0x20, 5, 0x00);
        let mut buf = BytesMut::from(&pkt[..]);
        let result = decoder.decode(&mut buf).unwrap();
        assert!(result.is_some());
        let (pos, ts) = result.unwrap();
        assert_eq!(pos, 0);
        assert_eq!(ts.header.pid(), 0x20);
        assert_eq!(ts.header.continuity_counter(), 5);
        assert_eq!(buf.len(), 0);
    }

    #[test]
    fn test_decoder_skips_garbage_before_sync() {
        let mut decoder = TsPacketDecoder::new(0);
        let pkt1 = make_packet(0x30, 7, 0xCC);
        let pkt2 = make_packet(0x31, 0, 0x00);
        let mut buf = BytesMut::new();
        buf.extend_from_slice(&[0x00, 0xFF, 0xAA]); // 3 garbage bytes
        buf.extend_from_slice(&pkt1);
        buf.extend_from_slice(&pkt2); // needed so sync at pkt1 can be verified
        let (pos, ts) = decoder.decode(&mut buf).unwrap().unwrap();
        assert_eq!(pos, 3); // skipped 3 garbage bytes
        assert_eq!(ts.header.pid(), 0x30);
        assert_eq!(buf.len(), 188); // pkt2 remains
    }

    #[test]
    fn test_decoder_two_packets_sequential() {
        let mut decoder = TsPacketDecoder::new(0);
        let pkt1 = make_packet(0x100, 0, 0x11);
        let pkt2 = make_packet(0x200, 1, 0x22);
        let mut buf = BytesMut::new();
        buf.extend_from_slice(&pkt1);
        buf.extend_from_slice(&pkt2);

        let (pos1, ts1) = decoder.decode(&mut buf).unwrap().unwrap();
        assert_eq!(pos1, 0);
        assert_eq!(ts1.header.pid(), 0x100);
        assert_eq!(buf.len(), 188);

        let (pos2, ts2) = decoder.decode(&mut buf).unwrap().unwrap();
        assert_eq!(pos2, 188);
        assert_eq!(ts2.header.pid(), 0x200);
        assert_eq!(buf.len(), 0);
    }

    #[test]
    fn test_decoder_partial_then_complete() {
        let mut decoder = TsPacketDecoder::new(0);
        let pkt = make_packet(0x42, 2, 0xDD);
        let mut buf = BytesMut::new();

        // Feed first half
        buf.extend_from_slice(&pkt[..100]);
        assert!(decoder.decode(&mut buf).unwrap().is_none());

        // Feed remaining
        buf.extend_from_slice(&pkt[100..]);
        let (pos, ts) = decoder.decode(&mut buf).unwrap().unwrap();
        assert_eq!(pos, 0);
        assert_eq!(ts.header.pid(), 0x42);
        assert_eq!(buf.len(), 0);
    }

    #[test]
    fn test_decoder_empty_buffer() {
        let mut decoder = TsPacketDecoder::new(0);
        let mut buf = BytesMut::new();
        assert!(decoder.decode(&mut buf).unwrap().is_none());
    }

    #[test]
    fn test_decoder_with_initial_stream_position() {
        let mut decoder = TsPacketDecoder::new(1000);
        let pkt1 = make_packet(0x50, 0, 0x00);
        let pkt2 = make_packet(0x51, 1, 0x00);
        let mut buf = BytesMut::new();
        buf.extend_from_slice(&pkt1);
        buf.extend_from_slice(&pkt2);

        let (pos, ts) = decoder.decode(&mut buf).unwrap().unwrap();
        assert_eq!(pos, 1000);
        assert_eq!(ts.header.pid(), 0x50);
        assert_eq!(decoder.stream_position, 1188);
    }

    #[test]
    fn test_decoder_false_sync_byte_skipped() {
        // A 0x47 byte that does NOT have another 0x47 at +188 should be skipped.
        let mut decoder = TsPacketDecoder::new(0);
        let pkt = make_packet(0x60, 0, 0x00);
        let mut buf = BytesMut::new();
        // Put a false 0x47 followed by garbage, then a real packet pair
        buf.extend_from_slice(&[0x47]); // false sync at offset 0
        buf.extend_from_slice(&[0x00; 187]); // padding (total 188 so far)
        buf.extend_from_slice(&[0x00]); // byte at 188 is NOT 0x47 → false sync
        buf.extend_from_slice(&[0x00; 187]); // more padding
        // Now at offset 376 place two real packets
        let pkt2 = make_packet(0x61, 1, 0x00);
        buf.extend_from_slice(&pkt);
        buf.extend_from_slice(&pkt2);

        let (pos, ts) = decoder.decode(&mut buf).unwrap().unwrap();
        // Should have skipped past the false 0x47 and found the real packet
        assert_eq!(pos, 376);
        assert_eq!(ts.header.pid(), 0x60);
    }
}
