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

pub use assembler::*;
mod assembler;

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
