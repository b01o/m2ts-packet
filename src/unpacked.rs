/// Unpacked Elementary Stream Item from a TS packet
///
/// Usage:
/// ```ignore
/// let packet_stream = tokio_util::codec::FramedRead::new(file, ts_packet::TsPacketDecoder);
/// let mut unpacked_stream = UnpackedDecoder::new(packet_stream);
/// while let Some(item) = unpacked_stream.next().await { ... }
/// ```
use crate::*;
use std::collections::{HashMap, VecDeque};
use std::pin::Pin;
use std::task::{Context, Poll};
use tokio_stream::Stream;

use pat::*;
mod pat;

use pmt::*;
mod pmt;

const NULL_PID: u16 = 0x1FFF;

/// Unpacked Elementary Stream Item from a TS packet
pub enum Unpacked {
    Video {
        pid: u16,
        random_access: Option<bool>, // can be None if adaptation_field is not present
        pts: Option<u64>,
        dts: Option<u64>,
        payload: Bytes,
    },
    Audio {
        pid: u16,
        random_access: Option<bool>, // can be None if adaptation_field is not present
        pts: Option<u64>,
        payload: Bytes,
    },
    PMT(ProgramMapTable),
    PAT(ProgramAssociationTable),

    // unparsed packetized elementary stream
    PES {
        stream_id: u8,
        data: Bytes,
    },
    // Unparsed sections
    Section {
        table_id: u8,
        data: Bytes,
    },
    Null,
    // fallback for unrecognized payloads
    Private(Bytes),
}
impl std::fmt::Debug for Unpacked {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Unpacked::Video {
                pid,
                pts,
                dts,
                payload,
                random_access,
            } => f
                .debug_struct("Video")
                .field("pid", &format_args!("0x{pid:02X}"))
                .field("pts", pts)
                .field("dts", dts)
                .field("random_access", random_access)
                .field("payload_len", &payload.len())
                .field("payload_preview", &&payload[..payload.len().min(16)])
                .finish(),
            Unpacked::Audio {
                pid,
                pts,
                payload,
                random_access,
            } => f
                .debug_struct("Audio")
                .field("pid", &format_args!("0x{pid:02X}"))
                .field("pts", pts)
                .field("random_access", random_access)
                .field("payload_len", &payload.len())
                .field("payload_preview", &&payload[..payload.len().min(16)])
                .finish(),
            Unpacked::PMT(pmt) => write!(f, "PMT({pmt:?})"),
            Unpacked::PAT(pat) => write!(f, "PAT({pat:?})"),
            Unpacked::PES { stream_id, data } => f
                .debug_struct("PES")
                .field("stream_id", &format_args!("0x{stream_id:02X}"))
                .field("data_prefix", &&data[..data.len().min(16)])
                .field("data_len", &data.len())
                .finish(),
            Unpacked::Section { table_id, data } => f
                .debug_struct("Section")
                .field("table_id", &format_args!("0x{table_id:02X}"))
                .field("data_prefix", &&data[..data.len().min(16)])
                .field("data_len", &data.len())
                .finish(),
            Unpacked::Null => write!(f, "Null"),
            Unpacked::Private(data) => f
                .debug_struct("Private")
                .field("data_prefix", &&data[..data.len().min(16)])
                .field("data_len", &data.len())
                .finish(),
        }
    }
}

// ---------------------------------------------------------------------------
// PES header helpers
// ---------------------------------------------------------------------------

/// Parse a 33-bit timestamp (PTS or DTS) from 5 bytes in the PES header.
///
/// Layout of each 5-byte timestamp field:
/// ```text
/// byte 0: [4-bit marker] [bit32..30 of TS] [marker bit]
/// byte 1: [bit29..22 of TS]
/// byte 2: [bit21..15 of TS] [marker bit]
/// byte 3: [bit14..7 of TS]
/// byte 4: [bit6..0 of TS] [marker bit]
/// ```
fn parse_timestamp(data: &[u8]) -> Option<u64> {
    if data.len() < 5 {
        return None;
    }
    let ts = ((data[0] as u64 >> 1) & 0x07) << 30
        | (data[1] as u64) << 22
        | ((data[2] as u64 >> 1) & 0x7F) << 15
        | (data[3] as u64) << 7
        | (data[4] as u64 >> 1) & 0x7F;
    Some(ts)
}

/// Try to parse a complete PES packet and produce the correct [`Unpacked`] variant.
///
/// PES header layout (minimum 9 bytes):
/// ```text
/// [0..3]  start code prefix (00 00 01) + stream_id
/// [4..5]  PES packet length
/// [6]     flags byte 1 (marker, scrambling, priority, alignment, copyright, original)
/// [7]     flags byte 2 (PTS_DTS_flags in bits 7-6, + other flags)
/// [8]     PES header data length
/// [9..]   optional PTS/DTS, then ES payload
/// ```
fn unpack_pes(pid: u16, random_access_indicator: Option<bool>, data: Bytes) -> Unpacked {
    if data.len() < 9 {
        // Too short to be a valid PES — keep as raw PES
        let stream_id = if data.len() >= 4 { data[3] } else { 0 };
        return Unpacked::PES { stream_id, data };
    }

    let stream_id = data[3];
    let pts_dts_flags = (data[7] >> 6) & 0x03;
    let pes_header_data_length = data[8] as usize;
    let header_end = 9 + pes_header_data_length;

    let optional_header = &data[9..data.len().min(header_end)];

    let pts = if pts_dts_flags >= 0b10 && optional_header.len() >= 5 {
        parse_timestamp(&optional_header[0..5])
    } else {
        None
    };

    let dts = if pts_dts_flags == 0b11 && optional_header.len() >= 10 {
        parse_timestamp(&optional_header[5..10])
    } else {
        None
    };

    let payload_start = header_end.min(data.len());
    let payload = data.slice(payload_start..);

    // Video stream IDs: 0xE0 – 0xEF
    if (0xE0..=0xEF).contains(&stream_id) {
        return Unpacked::Video {
            pid,
            random_access: random_access_indicator,
            pts,
            dts,
            payload,
        };
    }

    // Audio stream IDs: 0xC0 – 0xDF
    if (0xC0..=0xDF).contains(&stream_id) {
        return Unpacked::Audio {
            pid,
            random_access: random_access_indicator,
            pts,
            payload,
        };
    }

    // Other PES (e.g. private stream 1 = 0xBD, padding, etc.)
    Unpacked::PES { stream_id, data }
}

/// Try to parse a section and produce the correct [`Unpacked`] variant.
fn unpack_section(data: Bytes) -> Unpacked {
    if data.is_empty() {
        return Unpacked::Private(data);
    }
    let table_id = data[0];
    match table_id {
        0x00 => {
            if let Some(pat) = ProgramAssociationTable::from_bytes(&data) {
                return Unpacked::PAT(pat);
            }
        }
        0x02 => {
            if let Some(pmt) = ProgramMapTable::from_bytes(&data) {
                return Unpacked::PMT(pmt);
            }
        }
        _ => {}
    }
    // Fallback: generic section
    Unpacked::Section { table_id, data }
}

struct PidBuffer {
    data: BytesMut,
    is_pes: bool,
    random_access_indicator: Option<bool>,
}

/// Stream adapter that reassembles TS packets into complete PES packets and PSI sections.
///
/// Buffers payload data per-PID. When a new payload unit start indicator (PUSI) arrives,
/// the previously buffered data for that PID is flushed as a complete [`Unpacked`] item.
/// Continuation packets without a prior PUSI for their PID are discarded.
pub struct UnpackedDecoder<S> {
    inner: Pin<Box<S>>,
    buffers: HashMap<u16, PidBuffer>,
    pending: VecDeque<Unpacked>,
    done: bool,
}

impl<S> UnpackedDecoder<S>
where
    S: Stream<Item = std::result::Result<TsPacket, TsPacketError>>,
{
    pub fn new(inner: S) -> Self {
        Self {
            inner: Box::pin(inner),
            buffers: HashMap::new(),
            pending: VecDeque::new(),
            done: false,
        }
    }

    /// Remove the buffer for `pid` and push its contents as an [`Unpacked`] item to the
    /// pending queue. Does nothing if the buffer is empty or missing.
    fn flush_buffer(&mut self, pid: u16) {
        let Some(buf) = self.buffers.remove(&pid) else {
            return;
        };
        if buf.data.is_empty() {
            return;
        }
        let data = buf.data.freeze();
        let item = if buf.is_pes {
            if data.len() >= 4 {
                unpack_pes(pid, buf.random_access_indicator, data)
            } else {
                Unpacked::Private(data)
            }
        } else if !data.is_empty() {
            unpack_section(data)
        } else {
            return;
        };
        self.pending.push_back(item);
    }

    /// Flush all remaining PID buffers (called when the inner stream ends).
    fn flush_all(&mut self) {
        let pids: Vec<u16> = self.buffers.keys().copied().collect();
        for pid in pids {
            self.flush_buffer(pid);
        }
    }

    fn process_packet(&mut self, packet: TsPacket) {
        let pid = packet.header.pid();

        // Null packets
        if pid == NULL_PID {
            self.pending.push_back(Unpacked::Null);
            return;
        }

        // Skip packets without payload
        if !packet.header.payload() || packet.payload.is_empty() {
            return;
        }

        let pusi = packet.header.payload_unit_start_indicator();
        let payload = &packet.payload;

        if pusi {
            // Detect PES: payload starts with start-code prefix 0x00 0x00 0x01
            let is_pes = payload.len() >= 3
                && payload[0] == 0x00
                && payload[1] == 0x00
                && payload[2] == 0x01;

            if is_pes {
                // Flush any previously accumulated data for this PID
                self.flush_buffer(pid);
                let random_access_indicator = packet
                    .adaptation_field
                    .as_ref()
                    .map(|af| af.flags.random_access_indicator());
                self.buffers.insert(
                    pid,
                    PidBuffer {
                        data: BytesMut::from(payload.as_ref()),
                        is_pes: true,
                        random_access_indicator,
                    },
                );
            } else {
                // PSI section — first byte is the pointer field
                let pointer_field = payload[0] as usize;

                // Append trailing bytes of the previous section and flush it
                if let Some(buf) = self.buffers.get_mut(&pid) {
                    let end = (1 + pointer_field).min(payload.len());
                    buf.data.extend_from_slice(&payload[1..end]);
                }
                self.flush_buffer(pid);

                // Start new section buffer after the pointer field
                let start = 1 + pointer_field;
                if start < payload.len() {
                    self.buffers.insert(
                        pid,
                        PidBuffer {
                            data: BytesMut::from(&payload[start..]),
                            is_pes: false,
                            random_access_indicator: None,
                        },
                    );
                }
            }
        } else {
            // Continuation packet — append to existing buffer, or discard if no PUSI seen yet
            if let Some(buf) = self.buffers.get_mut(&pid) {
                buf.data.extend_from_slice(payload);
            }
        }
    }
}

impl<S> Stream for UnpackedDecoder<S>
where
    S: Stream<Item = std::result::Result<TsPacket, TsPacketError>>,
{
    type Item = std::result::Result<Unpacked, TsPacketError>;

    fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        let this = self.get_mut();
        loop {
            // Drain pending items first
            if let Some(item) = this.pending.pop_front() {
                return Poll::Ready(Some(Ok(item)));
            }

            if this.done {
                return Poll::Ready(None);
            }

            match this.inner.as_mut().poll_next(cx) {
                Poll::Ready(Some(Ok(packet))) => {
                    this.process_packet(packet);
                    // loop back to check pending
                }
                Poll::Ready(Some(Err(e))) => {
                    return Poll::Ready(Some(Err(e)));
                }
                Poll::Ready(None) => {
                    // Inner stream finished — flush all remaining buffers
                    this.done = true;
                    this.flush_all();
                    // loop back to drain pending
                }
                Poll::Pending => {
                    return Poll::Pending;
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio_stream::StreamExt;

    /// Build a TsPacket with the given PID, PUSI flag, and raw payload.
    fn make_ts_packet(pid: u16, pusi: bool, payload: &[u8]) -> TsPacket {
        let header = TransportStreamHeader::new()
            .with_payload_unit_start_indicator(pusi)
            .with_pid(pid)
            .with_payload(true);
        TsPacket {
            header,
            adaptation_field: None,
            payload: Bytes::copy_from_slice(payload),
        }
    }

    fn make_stream(
        packets: Vec<TsPacket>,
    ) -> impl Stream<Item = std::result::Result<TsPacket, TsPacketError>> {
        tokio_stream::iter(packets.into_iter().map(Ok))
    }

    // ---- basic tests ----

    #[tokio::test]
    async fn test_null_packet() {
        let stream = make_stream(vec![make_ts_packet(NULL_PID, false, &[])]);
        let mut decoder = UnpackedDecoder::new(stream);
        let item = decoder.next().await.unwrap().unwrap();
        assert!(matches!(item, Unpacked::Null));
        assert!(decoder.next().await.is_none());
    }

    #[tokio::test]
    async fn test_empty_stream() {
        let stream = make_stream(vec![]);
        let mut decoder = UnpackedDecoder::new(stream);
        assert!(decoder.next().await.is_none());
    }

    // ---- discard tests ----

    #[tokio::test]
    async fn test_discard_initial_non_pusi() {
        let stream = make_stream(vec![
            make_ts_packet(0x100, false, &[0xAA, 0xBB]),
            make_ts_packet(0x100, false, &[0xCC]),
        ]);
        let mut decoder = UnpackedDecoder::new(stream);
        // All packets discarded — no PUSI seen
        assert!(decoder.next().await.is_none());
    }

    #[tokio::test]
    async fn test_discard_then_accept_after_pusi() {
        let stream = make_stream(vec![
            make_ts_packet(0x100, false, &[0xAA]), // discarded
            make_ts_packet(0x100, false, &[0xBB]), // discarded
            make_ts_packet(0x100, true, &[0x00, 0x00, 0x01, 0xE0, 0xCC]),
        ]);
        let mut decoder = UnpackedDecoder::new(stream);
        let item = decoder.next().await.unwrap().unwrap();
        match item {
            Unpacked::PES { stream_id, data } => {
                assert_eq!(stream_id, 0xE0);
                assert_eq!(&data[..], &[0x00, 0x00, 0x01, 0xE0, 0xCC]);
            }
            other => panic!("Expected PES, got {other:?}"),
        }
    }

    // ---- PES tests ----

    #[tokio::test]
    async fn test_pes_single_packet() {
        let payload: &[u8] = &[0x00, 0x00, 0x01, 0xE0, 0x11, 0x22];
        let stream = make_stream(vec![make_ts_packet(0x100, true, payload)]);
        let mut decoder = UnpackedDecoder::new(stream);
        let item = decoder.next().await.unwrap().unwrap();
        match item {
            Unpacked::PES { stream_id, data } => {
                assert_eq!(stream_id, 0xE0);
                assert_eq!(&data[..], payload);
            }
            other => panic!("Expected PES, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn test_pes_multi_packet() {
        let stream = make_stream(vec![
            make_ts_packet(0x100, true, &[0x00, 0x00, 0x01, 0xC0, 0xAA]),
            make_ts_packet(0x100, false, &[0xBB, 0xCC]),
            make_ts_packet(0x100, false, &[0xDD]),
        ]);
        let mut decoder = UnpackedDecoder::new(stream);
        let item = decoder.next().await.unwrap().unwrap();
        match item {
            Unpacked::PES { stream_id, data } => {
                assert_eq!(stream_id, 0xC0);
                assert_eq!(&data[..], &[0x00, 0x00, 0x01, 0xC0, 0xAA, 0xBB, 0xCC, 0xDD]);
            }
            other => panic!("Expected PES, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn test_pes_flush_on_new_pusi() {
        let p1: &[u8] = &[0x00, 0x00, 0x01, 0xE0, 0x11];
        let p2: &[u8] = &[0x00, 0x00, 0x01, 0xE0, 0x22];
        let stream = make_stream(vec![
            make_ts_packet(0x100, true, p1),
            make_ts_packet(0x100, true, p2), // new PUSI flushes p1
        ]);
        let mut decoder = UnpackedDecoder::new(stream);

        // First PES flushed when second PUSI arrives
        let item = decoder.next().await.unwrap().unwrap();
        assert!(matches!(
            &item,
            Unpacked::PES {
                stream_id: 0xE0,
                ..
            }
        ));
        if let Unpacked::PES { data, .. } = &item {
            assert_eq!(&data[..], p1);
        }

        // Second PES flushed on stream end
        let item = decoder.next().await.unwrap().unwrap();
        if let Unpacked::PES { data, .. } = &item {
            assert_eq!(&data[..], p2);
        }
    }

    // ---- PSI section tests ----

    #[tokio::test]
    async fn test_section_single_packet() {
        // pointer_field=0, then section: table_id=0x42
        let payload: &[u8] = &[0x00, 0x42, 0xF0, 0x05, 0xAA, 0xBB];
        let stream = make_stream(vec![make_ts_packet(0x00, true, payload)]);
        let mut decoder = UnpackedDecoder::new(stream);
        let item = decoder.next().await.unwrap().unwrap();
        match item {
            Unpacked::Section { table_id, data } => {
                assert_eq!(table_id, 0x42);
                assert_eq!(&data[..], &[0x42, 0xF0, 0x05, 0xAA, 0xBB]);
            }
            other => panic!("Expected Section, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn test_section_multi_packet() {
        // pointer_field=0, section starts immediately
        let stream = make_stream(vec![
            make_ts_packet(0x00, true, &[0x00, 0x02, 0xB0, 0x0D]),
            make_ts_packet(0x00, false, &[0xAA, 0xBB]),
        ]);
        let mut decoder = UnpackedDecoder::new(stream);
        let item = decoder.next().await.unwrap().unwrap();
        match item {
            Unpacked::Section { table_id, data } => {
                assert_eq!(table_id, 0x02);
                assert_eq!(&data[..], &[0x02, 0xB0, 0x0D, 0xAA, 0xBB]);
            }
            other => panic!("Expected Section, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn test_section_with_pointer_field() {
        // First packet: section starts at pointer_field=0
        // Second packet: pointer_field=2, 2 bytes finish old section, rest starts new
        let stream = make_stream(vec![
            make_ts_packet(0x00, true, &[0x00, 0x42, 0xAA]),
            make_ts_packet(0x00, true, &[0x02, 0xBB, 0xCC, 0x43, 0xDD]),
        ]);
        let mut decoder = UnpackedDecoder::new(stream);

        // First section: table_id=0x42, data = [0x42, 0xAA, 0xBB, 0xCC]
        let item = decoder.next().await.unwrap().unwrap();
        match item {
            Unpacked::Section { table_id, data } => {
                assert_eq!(table_id, 0x42);
                assert_eq!(&data[..], &[0x42, 0xAA, 0xBB, 0xCC]);
            }
            other => panic!("Expected Section, got {other:?}"),
        }

        // Second section: table_id=0x43, data = [0x43, 0xDD]
        let item = decoder.next().await.unwrap().unwrap();
        match item {
            Unpacked::Section { table_id, data } => {
                assert_eq!(table_id, 0x43);
                assert_eq!(&data[..], &[0x43, 0xDD]);
            }
            other => panic!("Expected Section, got {other:?}"),
        }
    }

    // ---- multi-PID test ----

    #[tokio::test]
    async fn test_multiple_pids_interleaved() {
        let stream = make_stream(vec![
            make_ts_packet(0x100, true, &[0x00, 0x00, 0x01, 0xE0, 0x11]), // PES PID 0x100
            make_ts_packet(0x00, true, &[0x00, 0x00, 0xB0, 0x0D]),        // Section PID 0
            make_ts_packet(0x100, false, &[0x22, 0x33]),                  // continue PES
            make_ts_packet(0x00, false, &[0xAA]),                         // continue Section
        ]);
        let mut decoder = UnpackedDecoder::new(stream);

        let mut items = vec![];
        while let Some(Ok(item)) = decoder.next().await {
            items.push(item);
        }
        assert_eq!(items.len(), 2);

        // Find PES and Section regardless of order
        let pes_item = items
            .iter()
            .find(|i| matches!(i, Unpacked::PES { .. }))
            .expect("expected a PES item");
        let section_item = items
            .iter()
            .find(|i| matches!(i, Unpacked::Section { .. }))
            .expect("expected a Section item");

        // PES from PID 0x100
        match pes_item {
            Unpacked::PES { stream_id, data } => {
                assert_eq!(*stream_id, 0xE0);
                assert_eq!(&data[..], &[0x00, 0x00, 0x01, 0xE0, 0x11, 0x22, 0x33]);
            }
            other => panic!("Expected PES, got {other:?}"),
        }

        // Section from PID 0
        match section_item {
            Unpacked::Section { table_id, data } => {
                assert_eq!(*table_id, 0x00);
                assert_eq!(&data[..], &[0x00, 0xB0, 0x0D, 0xAA]);
            }
            other => panic!("Expected Section, got {other:?}"),
        }
    }

    // ---- parse_timestamp unit tests ----

    #[test]
    fn test_parse_timestamp_known_value() {
        // PTS = 90000 (= 1 second at 90 kHz)
        // bits 32..30 = 0, 29..22 = 0, 21..15 = 2, 14..7 = 0xBF, 6..0 = 0x10
        //   byte0: 0010_000_1 = 0x21
        //   byte1: 0x00
        //   byte2: 0000010_1 = 0x05
        //   byte3: 0xBF
        //   byte4: 0010000_1 = 0x21
        let ts_bytes = [0x21, 0x00, 0x05, 0xBF, 0x21];
        let ts = parse_timestamp(&ts_bytes).unwrap();
        assert_eq!(ts, 90000);
    }

    #[test]
    fn test_parse_timestamp_zero() {
        let ts_bytes = [0x21, 0x00, 0x01, 0x00, 0x01];
        let ts = parse_timestamp(&ts_bytes).unwrap();
        assert_eq!(ts, 0);
    }

    #[test]
    fn test_parse_timestamp_too_short() {
        assert!(parse_timestamp(&[0x21, 0x00, 0x01]).is_none());
    }

    // ---- Video PES tests ----

    #[tokio::test]
    async fn test_video_pes_with_pts() {
        // PES with stream_id=0xE0, PTS = 90000
        let pes: Vec<u8> = vec![
            0x00, 0x00, 0x01, 0xE0, // start code + stream_id
            0x00, 0x10, // PES packet length
            0x80, 0x80, // flags: PTS only
            0x05, // PES header data length = 5
            0x21, 0x00, 0x05, 0xBF, 0x21, // PTS = 90000
            0xDE, 0xAD, 0xBE, 0xEF, // ES payload
        ];
        let stream = make_stream(vec![make_ts_packet(0x100, true, &pes)]);
        let mut decoder = UnpackedDecoder::new(stream);
        let item = decoder.next().await.unwrap().unwrap();
        match item {
            Unpacked::Video {
                pid,
                pts,
                dts,
                payload,
                ..
            } => {
                assert_eq!(pid, 0x100);
                assert_eq!(pts, Some(90000));
                assert!(dts.is_none());
                assert_eq!(&payload[..], &[0xDE, 0xAD, 0xBE, 0xEF]);
            }
            other => panic!("Expected Video, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn test_video_pes_with_pts_and_dts() {
        // DTS = 45000 = 0xAFC8
        // bits 32..30=0, 29..22=0, 21..15=1, 14..7=0x5F, 6..0=0x48
        //   byte0: 0001_000_1 = 0x11
        //   byte1: 0x00
        //   byte2: 0000001_1 = 0x03
        //   byte3: 0x5F
        //   byte4: 1001000_1 = 0x91
        let pes: Vec<u8> = vec![
            0x00, 0x00, 0x01, 0xE1, // stream_id = 0xE1
            0x00, 0x15, // PES packet length
            0x80, 0xC0, // flags: PTS + DTS
            0x0A, // header data length = 10
            0x21, 0x00, 0x05, 0xBF, 0x21, // PTS = 90000
            0x11, 0x00, 0x03, 0x5F, 0x91, // DTS = 45000
            0xCA, 0xFE, // ES payload
        ];
        let stream = make_stream(vec![make_ts_packet(0x100, true, &pes)]);
        let mut decoder = UnpackedDecoder::new(stream);
        let item = decoder.next().await.unwrap().unwrap();
        match item {
            Unpacked::Video {
                pid,
                pts,
                dts,
                payload,
                ..
            } => {
                assert_eq!(pid, 0x100);
                assert_eq!(pts, Some(90000));
                assert_eq!(dts, Some(45000));
                assert_eq!(&payload[..], &[0xCA, 0xFE]);
            }
            other => panic!("Expected Video, got {other:?}"),
        }
    }

    // ---- Audio PES tests ----

    #[tokio::test]
    async fn test_audio_pes_with_pts() {
        let pes: Vec<u8> = vec![
            0x00, 0x00, 0x01, 0xC0, // stream_id = 0xC0
            0x00, 0x0E, // PES packet length
            0x80, 0x80, // flags: PTS only
            0x05, // header data length
            0x21, 0x00, 0x05, 0xBF, 0x21, // PTS = 90000
            0x01, 0x02, 0x03, // audio payload
        ];
        let stream = make_stream(vec![make_ts_packet(0x200, true, &pes)]);
        let mut decoder = UnpackedDecoder::new(stream);
        let item = decoder.next().await.unwrap().unwrap();
        match item {
            Unpacked::Audio {
                pid, pts, payload, ..
            } => {
                assert_eq!(pid, 0x200);
                assert_eq!(pts, Some(90000));
                assert_eq!(&payload[..], &[0x01, 0x02, 0x03]);
            }
            other => panic!("Expected Audio, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn test_audio_pes_no_pts() {
        let pes: Vec<u8> = vec![
            0x00, 0x00, 0x01, 0xDF, // stream_id = 0xDF
            0x00, 0x06, // PES packet length
            0x80, 0x00, // flags: no PTS, no DTS
            0x00, // header data length = 0
            0xAA, 0xBB, 0xCC, // audio payload
        ];
        let stream = make_stream(vec![make_ts_packet(0x200, true, &pes)]);
        let mut decoder = UnpackedDecoder::new(stream);
        let item = decoder.next().await.unwrap().unwrap();
        match item {
            Unpacked::Audio {
                pid, pts, payload, ..
            } => {
                assert_eq!(pid, 0x200);
                assert!(pts.is_none());
                assert_eq!(&payload[..], &[0xAA, 0xBB, 0xCC]);
            }
            other => panic!("Expected Audio, got {other:?}"),
        }
    }

    // ---- PAT section dispatch test ----

    #[tokio::test]
    async fn test_section_dispatches_to_pat() {
        let pat_section: Vec<u8> = vec![
            0x00, // table_id = 0x00 (PAT)
            0xB0, 0x0D, // section_syntax_indicator=1, section_length=13
            0x00, 0x01, // transport_stream_id = 1
            0xC1, // version=0, current_next=1
            0x00, 0x00, // section_number, last_section_number
            0x00, 0x01, // program_number = 1
            0xE1, 0x00, // reserved + PID = 0x100
            0x00, 0x00, 0x00, 0x00, // CRC32
        ];
        let mut payload = vec![0x00]; // pointer_field = 0
        payload.extend_from_slice(&pat_section);

        let stream = make_stream(vec![make_ts_packet(0x00, true, &payload)]);
        let mut decoder = UnpackedDecoder::new(stream);
        let item = decoder.next().await.unwrap().unwrap();
        match item {
            Unpacked::PAT(pat) => {
                assert_eq!(pat.transport_stream_id, 1);
                assert_eq!(pat.entries.len(), 1);
                assert_eq!(pat.entries[0].program_number, 1);
                assert_eq!(pat.entries[0].pid, 0x100);
            }
            other => panic!("Expected PAT, got {other:?}"),
        }
    }

    // ---- PMT section dispatch test ----

    #[tokio::test]
    async fn test_section_dispatches_to_pmt() {
        let pmt_section: Vec<u8> = vec![
            0x02, // table_id = 0x02 (PMT)
            0xB0, 0x12, // section_syntax_indicator=1, section_length=18
            0x00, 0x01, // program_number = 1
            0xC1, // version=0, current_next=1
            0x00, 0x00, // section_number, last_section_number
            0xE1, 0x00, // reserved + PCR_PID = 0x100
            0xF0, 0x00, // reserved + program_info_length = 0
            // H.264 video on PID 0x101
            0x1B, 0xE1, 0x01, 0xF0, 0x00, 0x00, 0x00, 0x00, 0x00, // CRC32
        ];
        let mut payload = vec![0x00]; // pointer_field
        payload.extend_from_slice(&pmt_section);

        let stream = make_stream(vec![make_ts_packet(0x100, true, &payload)]);
        let mut decoder = UnpackedDecoder::new(stream);
        let item = decoder.next().await.unwrap().unwrap();
        match item {
            Unpacked::PMT(pmt) => {
                assert_eq!(pmt.program_number, 1);
                assert_eq!(pmt.pcr_pid, 0x100);
                assert_eq!(pmt.entries.len(), 1);
                assert_eq!(pmt.entries[0].stream_type, StreamType::H264);
                assert_eq!(pmt.entries[0].elementary_pid, 0x101);
            }
            other => panic!("Expected PMT, got {other:?}"),
        }
    }
}
