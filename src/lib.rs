//! A MPEG2 Transport Stream (TS) packet decoder.
//!
//! This crate provides low-level decoding of 188-byte MPEG-TS packets and
//! reassembly into PES (Packetized Elementary Stream) packets and PSI sections
//! (PAT / PMT).
//!
//! # Core types
//!
//! | Type | Description |
//! |------|-------------|
//! | [`TsPacket`] | A single 188-byte transport stream packet |
//! | [`TsPacketDecoder`] | A [`tokio_util::codec::Decoder`] that reads `TsPacket`s from a byte stream |
//! | [`PesPacket`] | A reassembled elementary stream item (video, audio, PAT, PMT, etc.) |
//! | [`PacketizedElementaryStream`] | A `Stream` adapter that reassembles `TsPacket`s into `PesPacket`s |
//! | [`PesAssembler`] | A pull-based assembler — same logic, but driven by an async callback |
//!
//! # Stream-based usage
//!
//! Wrap any `AsyncRead` source with [`TsPacketDecoder`] via `FramedRead`, then
//! feed the packet stream into [`PacketizedElementaryStream`]:
//!
#![doc = concat!("```no_run\n", include_str!("../examples/stream.rs"), "\n```")]
//!
//! # Pull-based usage
//!
//! If you don't have a `Stream` or need finer control, use [`PesAssembler`]
//! with an async callback that provides `TsPacket`s on demand:
//!
#![doc = concat!("```no_run\n", include_str!("../examples/assemble.rs"), "\n```")]

use bitfield_struct::{bitenum, bitfield};
use tokio_util::bytes::{Buf, Bytes, BytesMut};

mod error;
pub use error::*;

use ts_header::*;
mod ts_header;

pub use adaptation_field::*;
mod adaptation_field;

pub use ts_packet::{TsPacket, TsPacketDecoder};
mod ts_packet;

pub use pes_packet::*;
mod pes_packet;
