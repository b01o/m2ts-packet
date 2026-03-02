//! A MPEG2 Transport Stream (TS) packet decoder
//!
//! ``` ignore
//! #[tokio::main]
//! async fn main() {
//!     // replace with actual file
//!     let mut file = tokio::fs::File::open("path/to/your/file.ts").await.unwrap();
//!     let ts_packets = tokio_util::codec::FramedRead::new(&mut file, ts_packet::TsPacketDecoder::new(0));
//!     let mut unpack = ts_packet::UnpackedDecoder::new(ts_packets);
//!     let mut count = 0;
//!     while let Some(unpacked) = unpack.try_next().await.unwrap() {
//!         println!("Packet {count}: {:?}", unpacked);
//!         count += 1;
//!         if count >= 10 {
//!             break;
//!         }
//!     }
//! }
//! ``````

use bitfield_struct::{bitenum, bitfield};
use bytes::{Buf, Bytes, BytesMut};

mod error;
pub use error::*;

use ts_header::*;
mod ts_header;

pub use adaptation_field::*;
mod adaptation_field;

pub use ts_packet::{TsPacket, TsPacketDecoder};
mod ts_packet;

pub use unpacked::*;
mod unpacked;
