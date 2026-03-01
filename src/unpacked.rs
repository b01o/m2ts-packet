/// Unpacked Elementary Stream Item from a TS packet
///
/// Usage:
/// ```ignore
/// let packet_stream = tokio_util::codec::FramedRead::new(file, ts_packet::TsPacketDecoder);
/// let mut unpacked_stream = UnpackedDecoder::new(packet_stream);
/// while let Some(item) = unpacked_stream.next().await { ... }
/// ```

use std::collections::{HashMap, VecDeque};
use std::pin::Pin;
use std::task::{Context, Poll};

use tokio_stream::Stream;

use crate::*;

const NULL_PID: u16 = 0x1FFF;

/// Unpacked Elementary Stream Item from a TS packet
pub enum Unpacked {
    PES { stream_id: u8, data: Bytes },
    Section { table_id: u8, data: Bytes },
    Null,
    Private(Bytes),
}
impl std::fmt::Debug for Unpacked {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Unpacked::PES { stream_id, data } => f
                .debug_struct("PES")
                .field("stream_id", stream_id)
                .field("data_prefix", &&data[..data.len().min(16)])
                .field("data_len", &data.len())
                .finish(),
            Unpacked::Section { table_id, data } => f
                .debug_struct("Section")
                .field("table_id", table_id)
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

struct PidBuffer {
    data: BytesMut,
    is_pes: bool,
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
                Unpacked::PES {
                    stream_id: data[3],
                    data,
                }
            } else {
                Unpacked::Private(data)
            }
        } else if !data.is_empty() {
            Unpacked::Section {
                table_id: data[0],
                data,
            }
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
        let payload = packet.payload;

        if pusi {
            // Detect PES: payload starts with start-code prefix 0x00 0x00 0x01
            let is_pes = payload.len() >= 3
                && payload[0] == 0x00
                && payload[1] == 0x00
                && payload[2] == 0x01;

            if is_pes {
                // Flush any previously accumulated data for this PID
                self.flush_buffer(pid);
                self.buffers.insert(
                    pid,
                    PidBuffer {
                        data: BytesMut::from(payload.as_ref()),
                        is_pes: true,
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
                        },
                    );
                }
            }
        } else {
            // Continuation packet — append to existing buffer, or discard if no PUSI seen yet
            if let Some(buf) = self.buffers.get_mut(&pid) {
                buf.data.extend_from_slice(&payload);
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
            make_ts_packet(0x100, false, &[0xAA]),         // discarded
            make_ts_packet(0x100, false, &[0xBB]),         // discarded
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
        assert!(matches!(&item, Unpacked::PES { stream_id: 0xE0, .. }));
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
            make_ts_packet(0x100, false, &[0x22, 0x33]),                   // continue PES
            make_ts_packet(0x00, false, &[0xAA]),                          // continue Section
        ]);
        let mut decoder = UnpackedDecoder::new(stream);

        let mut items = vec![];
        while let Some(Ok(item)) = decoder.next().await {
            items.push(item);
        }
        assert_eq!(items.len(), 2);

        // PES from PID 0x100
        assert!(matches!(&items[0], Unpacked::PES { stream_id: 0xE0, .. }));
        if let Unpacked::PES { data, .. } = &items[0] {
            assert_eq!(&data[..], &[0x00, 0x00, 0x01, 0xE0, 0x11, 0x22, 0x33]);
        }

        // Section from PID 0
        assert!(matches!(&items[1], Unpacked::Section { table_id: 0x00, .. }));
        if let Unpacked::Section { data, .. } = &items[1] {
            assert_eq!(&data[..], &[0x00, 0xB0, 0x0D, 0xAA]);
        }
    }
}