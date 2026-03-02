//! Stream adapter that reassembles TS packets into complete PES packets and PSI sections.

use super::*;
/// Stream adapter that reassembles TS packets into complete PES packets and PSI sections.
///
/// Buffers payload data per-PID. When a new payload unit start indicator (PUSI) arrives,
/// the previously buffered data for that PID is flushed as a complete [`PesPacket`] item.
/// Continuation packets without a prior PUSI for their PID are discarded.
pub struct PacketizedElementaryStream<S> {
    inner: S,
    buffers: HashMap<u16, PidBuffer>,
    pending: VecDeque<PesPacket>,
    done: bool,
}

impl<S> PacketizedElementaryStream<S>
where
    S: Stream<Item = std::result::Result<(u64, TsPacket), TsPacketError>>,
    S: Unpin,
{
    pub fn from_ts_stream(inner: S) -> Self {
        Self {
            inner,
            buffers: HashMap::new(),
            pending: VecDeque::new(),
            done: false,
        }
    }

    /// Remove the buffer for `pid` and push its contents as a [`PesPacket`] item to the
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

    /// Consume the decoder and return the inner stream. Any pending buffered data is lost.
    pub fn into_inner(self) -> S {
        self.inner
    }
}

impl<S> Stream for PacketizedElementaryStream<S>
where
    S: Stream<Item = std::result::Result<(u64, TsPacket), TsPacketError>>,
    S: Unpin,
{
    type Item = std::result::Result<PesPacket, TsPacketError>;

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

            match pin!(&mut this.inner).poll_next(cx) {
                Poll::Ready(Some(Ok((_pos, packet)))) => {
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

pub trait TsPacketStreamAssemble: Sized {
    fn assemble(self) -> PacketizedElementaryStream<Self>;
}
impl<S> TsPacketStreamAssemble for S
where
    S: Stream<Item = std::result::Result<(u64, TsPacket), TsPacketError>>,
    S: Unpin,
{
    fn assemble(self) -> PacketizedElementaryStream<Self> {
        PacketizedElementaryStream::from_ts_stream(self)
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
    ) -> impl Stream<Item = std::result::Result<(u64, TsPacket), TsPacketError>> {
        tokio_stream::iter(
            packets
                .into_iter()
                .enumerate()
                .map(|(i, p)| Ok((i as u64 * 188, p))),
        )
    }

    // ---- basic tests ----

    #[tokio::test]
    async fn test_null_packet() {
        let stream = make_stream(vec![make_ts_packet(NULL_PID, false, &[])]);
        let mut decoder = PacketizedElementaryStream::from_ts_stream(stream);
        let item = decoder.next().await.unwrap().unwrap();
        assert!(matches!(item, PesPacket::Null));
        assert!(decoder.next().await.is_none());
    }

    #[tokio::test]
    async fn test_empty_stream() {
        let stream = make_stream(vec![]);
        let mut decoder = PacketizedElementaryStream::from_ts_stream(stream);
        assert!(decoder.next().await.is_none());
    }

    // ---- discard tests ----

    #[tokio::test]
    async fn test_discard_initial_non_pusi() {
        let stream = make_stream(vec![
            make_ts_packet(0x100, false, &[0xAA, 0xBB]),
            make_ts_packet(0x100, false, &[0xCC]),
        ]);
        let mut decoder = PacketizedElementaryStream::from_ts_stream(stream);
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
        let mut decoder = PacketizedElementaryStream::from_ts_stream(stream);
        let item = decoder.next().await.unwrap().unwrap();
        match item {
            PesPacket::PES { stream_id, data } => {
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
        let mut decoder = PacketizedElementaryStream::from_ts_stream(stream);
        let item = decoder.next().await.unwrap().unwrap();
        match item {
            PesPacket::PES { stream_id, data } => {
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
        let mut decoder = PacketizedElementaryStream::from_ts_stream(stream);
        let item = decoder.next().await.unwrap().unwrap();
        match item {
            PesPacket::PES { stream_id, data } => {
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
        let mut decoder = PacketizedElementaryStream::from_ts_stream(stream);

        // First PES flushed when second PUSI arrives
        let item = decoder.next().await.unwrap().unwrap();
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

        // Second PES flushed on stream end
        let item = decoder.next().await.unwrap().unwrap();
        if let PesPacket::PES { data, .. } = &item {
            assert_eq!(&data[..], p2);
        }
    }

    // ---- PSI section tests ----

    #[tokio::test]
    async fn test_section_single_packet() {
        // pointer_field=0, then section: table_id=0x42
        let payload: &[u8] = &[0x00, 0x42, 0xF0, 0x05, 0xAA, 0xBB];
        let stream = make_stream(vec![make_ts_packet(0x00, true, payload)]);
        let mut decoder = PacketizedElementaryStream::from_ts_stream(stream);
        let item = decoder.next().await.unwrap().unwrap();
        match item {
            PesPacket::Section { table_id, data } => {
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
        let mut decoder = PacketizedElementaryStream::from_ts_stream(stream);
        let item = decoder.next().await.unwrap().unwrap();
        match item {
            PesPacket::Section { table_id, data } => {
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
        let mut decoder = PacketizedElementaryStream::from_ts_stream(stream);

        // First section: table_id=0x42, data = [0x42, 0xAA, 0xBB, 0xCC]
        let item = decoder.next().await.unwrap().unwrap();
        match item {
            PesPacket::Section { table_id, data } => {
                assert_eq!(table_id, 0x42);
                assert_eq!(&data[..], &[0x42, 0xAA, 0xBB, 0xCC]);
            }
            other => panic!("Expected Section, got {other:?}"),
        }

        // Second section: table_id=0x43, data = [0x43, 0xDD]
        let item = decoder.next().await.unwrap().unwrap();
        match item {
            PesPacket::Section { table_id, data } => {
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
        let mut decoder = PacketizedElementaryStream::from_ts_stream(stream);

        let mut items = vec![];
        while let Some(Ok(item)) = decoder.next().await {
            items.push(item);
        }
        assert_eq!(items.len(), 2);

        // Find PES and Section regardless of order
        let pes_item = items
            .iter()
            .find(|i| matches!(i, PesPacket::PES { .. }))
            .expect("expected a PES item");
        let section_item = items
            .iter()
            .find(|i| matches!(i, PesPacket::Section { .. }))
            .expect("expected a Section item");

        // PES from PID 0x100
        match pes_item {
            PesPacket::PES { stream_id, data } => {
                assert_eq!(*stream_id, 0xE0);
                assert_eq!(&data[..], &[0x00, 0x00, 0x01, 0xE0, 0x11, 0x22, 0x33]);
            }
            other => panic!("Expected PES, got {other:?}"),
        }

        // Section from PID 0
        match section_item {
            PesPacket::Section { table_id, data } => {
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
        let mut decoder = PacketizedElementaryStream::from_ts_stream(stream);
        let item = decoder.next().await.unwrap().unwrap();
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
        let mut decoder = PacketizedElementaryStream::from_ts_stream(stream);
        let item = decoder.next().await.unwrap().unwrap();
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
        let mut decoder = PacketizedElementaryStream::from_ts_stream(stream);
        let item = decoder.next().await.unwrap().unwrap();
        match item {
            PesPacket::Audio {
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
        let mut decoder = PacketizedElementaryStream::from_ts_stream(stream);
        let item = decoder.next().await.unwrap().unwrap();
        match item {
            PesPacket::Audio {
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
        let mut decoder = PacketizedElementaryStream::from_ts_stream(stream);
        let item = decoder.next().await.unwrap().unwrap();
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
        let mut decoder = PacketizedElementaryStream::from_ts_stream(stream);
        let item = decoder.next().await.unwrap().unwrap();
        match item {
            PesPacket::PMT(pmt) => {
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
