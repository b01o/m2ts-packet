/// Unpacked Elementary Stream Item from a TS packet
///
/// Usage:
/// ```ignore
/// let packet_stream = tokio_util::codec::FramedRead::new(file, ts_packet::TsPacketDecoder::new(0));
/// let mut unpacked_stream = UnpackedDecoder::new(packet_stream);
/// while let Some(item) = unpacked_stream.next().await { ... }
/// ```
use crate::*;
use std::collections::{HashMap, VecDeque};
use std::pin::{Pin, pin};
use std::task::{Context, Poll};
use tokio_stream::Stream;

use pat::*;
mod pat;

use pmt::*;
mod pmt;

pub use stream::*;
mod stream;

const NULL_PID: u16 = 0x1FFF;

/// Unpacked Elementary Stream Item from TS packets
pub enum PesPacket {
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
impl std::fmt::Debug for PesPacket {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            PesPacket::Video {
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
            PesPacket::Audio {
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
            PesPacket::PMT(pmt) => write!(f, "PMT({pmt:?})"),
            PesPacket::PAT(pat) => write!(f, "PAT({pat:?})"),
            PesPacket::PES { stream_id, data } => f
                .debug_struct("PES")
                .field("stream_id", &format_args!("0x{stream_id:02X}"))
                .field("data_prefix", &&data[..data.len().min(16)])
                .field("data_len", &data.len())
                .finish(),
            PesPacket::Section { table_id, data } => f
                .debug_struct("Section")
                .field("table_id", &format_args!("0x{table_id:02X}"))
                .field("data_prefix", &&data[..data.len().min(16)])
                .field("data_len", &data.len())
                .finish(),
            PesPacket::Null => write!(f, "Null"),
            PesPacket::Private(data) => f
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

/// Try to parse a complete PES packet and produce the correct [`PesPacket`] variant.
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
fn parse_pes_packet(pid: u16, random_access_indicator: Option<bool>, data: Bytes) -> PesPacket {
    if data.len() < 9 {
        // Too short to be a valid PES — keep as raw PES
        let stream_id = if data.len() >= 4 { data[3] } else { 0 };
        return PesPacket::PES { stream_id, data };
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
        return PesPacket::Video {
            pid,
            random_access: random_access_indicator,
            pts,
            dts,
            payload,
        };
    }

    // Audio stream IDs: 0xC0 – 0xDF
    if (0xC0..=0xDF).contains(&stream_id) {
        return PesPacket::Audio {
            pid,
            random_access: random_access_indicator,
            pts,
            payload,
        };
    }

    // Other PES (e.g. private stream 1 = 0xBD, padding, etc.)
    PesPacket::PES { stream_id, data }
}

/// Try to parse a section and produce the correct [`PesPacket`] variant.
fn parse_section(data: Bytes) -> PesPacket {
    if data.is_empty() {
        return PesPacket::Private(data);
    }
    let table_id = data[0];
    match table_id {
        0x00 => {
            if let Some(pat) = ProgramAssociationTable::from_bytes(&data) {
                return PesPacket::PAT(pat);
            }
        }
        0x02 => {
            if let Some(pmt) = ProgramMapTable::from_bytes(&data) {
                return PesPacket::PMT(pmt);
            }
        }
        _ => {}
    }
    // Fallback: generic section
    PesPacket::Section { table_id, data }
}

#[derive(Debug)]
struct PidBuffer {
    data: BytesMut,
    is_pes: bool,
    random_access_indicator: Option<bool>,
}

/// Pull-based assembler that reassembles TS packets into complete PES packets and PSI sections.
///
/// Unlike [`UnpackedStream`], which wraps a `Stream`, `Assembler` does not own an input stream.
/// Instead, callers pass an async callback to [`Assembler::next_unpacked`] that fetches the next
/// `TsPacket` on demand.
///
/// ```ignore
/// let mut assembler = Assembler::new();
/// while let Some(unpacked) = assembler.next_unpacked(async || { get_next_packet().await }).await? {
///     println!("{unpacked:?}");
/// }
/// ```
#[derive(Debug, Default)]
pub struct Assembler {
    buffers: HashMap<u16, PidBuffer>,
    pending: VecDeque<PesPacket>,
    done: bool,
}

impl Assembler {
    pub fn new() -> Self {
        Self::default()
    }

    /// Return the next assembled [`Unpacked`] item.
    ///
    /// `next_ts_packet` is an async callback that should return:
    /// - `Ok(Some(packet))` — a new TS packet to process,
    /// - `Ok(None)` — end of stream,
    /// - `Err(e)` — an error (propagated immediately).
    ///
    /// The callback is invoked only when the assembler needs more data; buffered items
    /// are drained first.
    pub async fn next_unpacked(
        &mut self,
        mut next_ts_packet: impl AsyncFnMut() -> Result<Option<TsPacket>>,
    ) -> Result<Option<PesPacket>> {
        loop {
            // Drain pending items first
            if let Some(item) = self.pending.pop_front() {
                return Ok(Some(item));
            }

            if self.done {
                return Ok(None);
            }

            match next_ts_packet().await? {
                Some(packet) => {
                    self.process_packet(packet);
                    // loop back to check pending
                }
                None => {
                    // Input exhausted — flush all remaining buffers
                    self.done = true;
                    self.flush_all();
                    // loop back to drain pending
                }
            }
        }
    }

    /// Reset the assembler, discarding all buffered state.
    pub fn reset(&mut self) {
        self.buffers.clear();
        self.pending.clear();
        self.done = false;
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
                parse_pes_packet(pid, buf.random_access_indicator, data)
            } else {
                PesPacket::Private(data)
            }
        } else if !data.is_empty() {
            parse_section(data)
        } else {
            return;
        };
        self.pending.push_back(item);
    }

    /// Flush all remaining PID buffers (called when the input is exhausted).
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
            self.pending.push_back(PesPacket::Null);
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

#[cfg(test)]
mod assembler_tests {
    use super::*;

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

    #[tokio::test]
    async fn test_assembler_null_packet() {
        let mut asm = Assembler::new();
        let packets = vec![make_ts_packet(NULL_PID, false, &[])];
        let mut iter = packets.into_iter();
        let item = asm
            .next_unpacked(async || Ok(iter.next()))
            .await
            .unwrap()
            .unwrap();
        assert!(matches!(item, PesPacket::Null));
        assert!(
            asm.next_unpacked(async || Ok(iter.next()))
                .await
                .unwrap()
                .is_none()
        );
    }

    #[tokio::test]
    async fn test_assembler_empty() {
        let mut asm = Assembler::new();
        let result = asm.next_unpacked(async || Ok(None)).await.unwrap();
        assert!(result.is_none());
    }

    #[tokio::test]
    async fn test_assembler_pes_single() {
        let mut asm = Assembler::new();
        let payload: &[u8] = &[0x00, 0x00, 0x01, 0xE0, 0x11, 0x22];
        let packets = vec![make_ts_packet(0x100, true, payload)];
        let mut iter = packets.into_iter();
        let item = asm
            .next_unpacked(async || Ok(iter.next()))
            .await
            .unwrap()
            .unwrap();
        match item {
            PesPacket::PES { stream_id, data } => {
                assert_eq!(stream_id, 0xE0);
                assert_eq!(&data[..], payload);
            }
            other => panic!("Expected PES, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn test_assembler_pes_multi_packet() {
        let mut asm = Assembler::new();
        let packets = vec![
            make_ts_packet(0x100, true, &[0x00, 0x00, 0x01, 0xC0, 0xAA]),
            make_ts_packet(0x100, false, &[0xBB, 0xCC]),
            make_ts_packet(0x100, false, &[0xDD]),
        ];
        let mut iter = packets.into_iter();
        let item = asm
            .next_unpacked(async || Ok(iter.next()))
            .await
            .unwrap()
            .unwrap();
        match item {
            PesPacket::PES { stream_id, data } => {
                assert_eq!(stream_id, 0xC0);
                assert_eq!(&data[..], &[0x00, 0x00, 0x01, 0xC0, 0xAA, 0xBB, 0xCC, 0xDD]);
            }
            other => panic!("Expected PES, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn test_assembler_pes_flush_on_new_pusi() {
        let mut asm = Assembler::new();
        let p1: &[u8] = &[0x00, 0x00, 0x01, 0xE0, 0x11];
        let p2: &[u8] = &[0x00, 0x00, 0x01, 0xE0, 0x22];
        let packets = vec![
            make_ts_packet(0x100, true, p1),
            make_ts_packet(0x100, true, p2),
        ];
        let mut iter = packets.into_iter();
        let cb = async || Ok(iter.next());

        let item = asm.next_unpacked(cb).await.unwrap().unwrap();
        assert!(matches!(
            &item,
            PesPacket::PES {
                stream_id: 0xE0,
                ..
            }
        ));
        if let PesPacket::PES { data, .. } = &item {
            assert_eq!(&data[..], p1);
        }

        let cb2 = async || Ok(iter.next());
        let item = asm.next_unpacked(cb2).await.unwrap().unwrap();
        if let PesPacket::PES { data, .. } = &item {
            assert_eq!(&data[..], p2);
        }
    }

    #[tokio::test]
    async fn test_assembler_section_single() {
        let mut asm = Assembler::new();
        let payload: &[u8] = &[0x00, 0x42, 0xF0, 0x05, 0xAA, 0xBB];
        let packets = vec![make_ts_packet(0x00, true, payload)];
        let mut iter = packets.into_iter();
        let item = asm
            .next_unpacked(async || Ok(iter.next()))
            .await
            .unwrap()
            .unwrap();
        match item {
            PesPacket::Section { table_id, data } => {
                assert_eq!(table_id, 0x42);
                assert_eq!(&data[..], &[0x42, 0xF0, 0x05, 0xAA, 0xBB]);
            }
            other => panic!("Expected Section, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn test_assembler_discard_non_pusi() {
        let mut asm = Assembler::new();
        let packets = vec![
            make_ts_packet(0x100, false, &[0xAA, 0xBB]),
            make_ts_packet(0x100, false, &[0xCC]),
        ];
        let mut iter = packets.into_iter();
        let result = asm.next_unpacked(async || Ok(iter.next())).await.unwrap();
        assert!(result.is_none());
    }

    #[tokio::test]
    async fn test_assembler_multiple_pids() {
        let mut asm = Assembler::new();
        let packets = vec![
            make_ts_packet(0x100, true, &[0x00, 0x00, 0x01, 0xE0, 0x11]),
            make_ts_packet(0x00, true, &[0x00, 0x00, 0xB0, 0x0D]),
            make_ts_packet(0x100, false, &[0x22, 0x33]),
            make_ts_packet(0x00, false, &[0xAA]),
        ];
        let mut iter = packets.into_iter();
        let cb = async || Ok(iter.next());

        let mut items = vec![];
        let mut next_cb = cb;

        // We need to recreate closures for each call since they capture iter
        while let Some(item) = asm.next_unpacked(&mut next_cb).await.unwrap() {
            items.push(item)
        }
        assert_eq!(items.len(), 2);

        assert!(items.iter().any(|i| matches!(i, PesPacket::PES { .. })));
        assert!(items.iter().any(|i| matches!(i, PesPacket::Section { .. })));
    }

    #[tokio::test]
    async fn test_assembler_reset() {
        let mut asm = Assembler::new();
        // Feed one PES start
        let packets = vec![make_ts_packet(0x100, true, &[0x00, 0x00, 0x01, 0xE0, 0x11])];
        let mut iter = packets.into_iter();
        // Drain — flushed on stream end
        let item = asm
            .next_unpacked(async || Ok(iter.next()))
            .await
            .unwrap()
            .unwrap();
        assert!(matches!(item, PesPacket::PES { .. }));

        // Reset and verify clean state
        asm.reset();

        // After reset, feeding nothing returns None
        let result = asm.next_unpacked(async || Ok(None)).await.unwrap();
        assert!(result.is_none());
    }

    #[tokio::test]
    async fn test_assembler_video_with_pts() {
        let mut asm = Assembler::new();
        let pes: Vec<u8> = vec![
            0x00, 0x00, 0x01, 0xE0, // start code + stream_id
            0x00, 0x10, // PES packet length
            0x80, 0x80, // flags: PTS only
            0x05, // PES header data length = 5
            0x21, 0x00, 0x05, 0xBF, 0x21, // PTS = 90000
            0xDE, 0xAD, 0xBE, 0xEF, // ES payload
        ];
        let packets = vec![make_ts_packet(0x100, true, &pes)];
        let mut iter = packets.into_iter();
        let item = asm
            .next_unpacked(async || Ok(iter.next()))
            .await
            .unwrap()
            .unwrap();
        match item {
            PesPacket::Video {
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
    async fn test_assembler_pat_dispatch() {
        let mut asm = Assembler::new();
        let pat_section: Vec<u8> = vec![
            0x00, 0xB0, 0x0D, 0x00, 0x01, 0xC1, 0x00, 0x00, 0x00, 0x01, 0xE1, 0x00, 0x00, 0x00,
            0x00, 0x00,
        ];
        let mut payload = vec![0x00];
        payload.extend_from_slice(&pat_section);

        let packets = vec![make_ts_packet(0x00, true, &payload)];
        let mut iter = packets.into_iter();
        let item = asm
            .next_unpacked(async || Ok(iter.next()))
            .await
            .unwrap()
            .unwrap();
        match item {
            PesPacket::PAT(pat) => {
                assert_eq!(pat.transport_stream_id, 1);
                assert_eq!(pat.entries.len(), 1);
                assert_eq!(pat.entries[0].program_number, 1);
                assert_eq!(pat.entries[0].pid, 0x100);
            }
            other => panic!("Expected PAT, got {other:?}"),
        }
    }
}
