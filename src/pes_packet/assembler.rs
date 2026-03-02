use super::*;

/// Pull-based assembler that reassembles TS packets into complete PES packets and PSI sections.
///
/// Unlike [`PacketizedElementaryStream`], which wraps a `Stream`, `PesAssembler` does not own an input stream.
/// Instead, callers pass an async callback to [`PesAssembler::next_packet`] that fetches the next
/// `TsPacket` on demand.
///
/// ```ignore
/// let mut assembler = PesAssembler::new();
/// while let Some(packet) = assembler.next_packet(async || { get_next_packet().await }).await? {
///     println!("{packet:?}");
/// }
/// ```
#[derive(Debug, Default)]
pub struct PesAssembler {
    buffers: HashMap<u16, PidBuffer>,
    pending: VecDeque<PesPacket>,
    done: bool,
}

impl PesAssembler {
    pub fn new() -> Self {
        Self::default()
    }

    /// Return the next assembled [`PesPacket`] item.
    ///
    /// `next_ts_packet` is an async callback that should return:
    /// - `Ok(Some(packet))` — a new TS packet to process,
    /// - `Ok(None)` — end of stream,
    /// - `Err(e)` — an error (propagated immediately).
    ///
    /// The callback is invoked only when the assembler needs more data; buffered items
    /// are drained first.
    pub async fn next_packet(
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

    /// Remove the buffer for `pid` and push its contents as an [`PesPacket`] item to the
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
        let mut asm = PesAssembler::new();
        let packets = vec![make_ts_packet(NULL_PID, false, &[])];
        let mut iter = packets.into_iter();
        let item = asm
            .next_packet(async || Ok(iter.next()))
            .await
            .unwrap()
            .unwrap();
        assert!(matches!(item, PesPacket::Null));
        assert!(
            asm.next_packet(async || Ok(iter.next()))
                .await
                .unwrap()
                .is_none()
        );
    }

    #[tokio::test]
    async fn test_assembler_empty() {
        let mut asm = PesAssembler::new();
        let result = asm.next_packet(async || Ok(None)).await.unwrap();
        assert!(result.is_none());
    }

    #[tokio::test]
    async fn test_assembler_pes_single() {
        let mut asm = PesAssembler::new();
        let payload: &[u8] = &[0x00, 0x00, 0x01, 0xE0, 0x11, 0x22];
        let packets = vec![make_ts_packet(0x100, true, payload)];
        let mut iter = packets.into_iter();
        let item = asm
            .next_packet(async || Ok(iter.next()))
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
        let mut asm = PesAssembler::new();
        let packets = vec![
            make_ts_packet(0x100, true, &[0x00, 0x00, 0x01, 0xC0, 0xAA]),
            make_ts_packet(0x100, false, &[0xBB, 0xCC]),
            make_ts_packet(0x100, false, &[0xDD]),
        ];
        let mut iter = packets.into_iter();
        let item = asm
            .next_packet(async || Ok(iter.next()))
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
        let mut asm = PesAssembler::new();
        let p1: &[u8] = &[0x00, 0x00, 0x01, 0xE0, 0x11];
        let p2: &[u8] = &[0x00, 0x00, 0x01, 0xE0, 0x22];
        let packets = vec![
            make_ts_packet(0x100, true, p1),
            make_ts_packet(0x100, true, p2),
        ];
        let mut iter = packets.into_iter();
        let cb = async || Ok(iter.next());

        let item = asm.next_packet(cb).await.unwrap().unwrap();
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
        let item = asm.next_packet(cb2).await.unwrap().unwrap();
        if let PesPacket::PES { data, .. } = &item {
            assert_eq!(&data[..], p2);
        }
    }

    #[tokio::test]
    async fn test_assembler_section_single() {
        let mut asm = PesAssembler::new();
        let payload: &[u8] = &[0x00, 0x42, 0xF0, 0x05, 0xAA, 0xBB];
        let packets = vec![make_ts_packet(0x00, true, payload)];
        let mut iter = packets.into_iter();
        let item = asm
            .next_packet(async || Ok(iter.next()))
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
        let mut asm = PesAssembler::new();
        let packets = vec![
            make_ts_packet(0x100, false, &[0xAA, 0xBB]),
            make_ts_packet(0x100, false, &[0xCC]),
        ];
        let mut iter = packets.into_iter();
        let result = asm.next_packet(async || Ok(iter.next())).await.unwrap();
        assert!(result.is_none());
    }

    #[tokio::test]
    async fn test_assembler_multiple_pids() {
        let mut asm = PesAssembler::new();
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
        while let Some(item) = asm.next_packet(&mut next_cb).await.unwrap() {
            items.push(item)
        }
        assert_eq!(items.len(), 2);

        assert!(items.iter().any(|i| matches!(i, PesPacket::PES { .. })));
        assert!(items.iter().any(|i| matches!(i, PesPacket::Section { .. })));
    }

    #[tokio::test]
    async fn test_assembler_reset() {
        let mut asm = PesAssembler::new();
        // Feed one PES start
        let packets = vec![make_ts_packet(0x100, true, &[0x00, 0x00, 0x01, 0xE0, 0x11])];
        let mut iter = packets.into_iter();
        // Drain — flushed on stream end
        let item = asm
            .next_packet(async || Ok(iter.next()))
            .await
            .unwrap()
            .unwrap();
        assert!(matches!(item, PesPacket::PES { .. }));

        // Reset and verify clean state
        asm.reset();

        // After reset, feeding nothing returns None
        let result = asm.next_packet(async || Ok(None)).await.unwrap();
        assert!(result.is_none());
    }

    #[tokio::test]
    async fn test_assembler_video_with_pts() {
        let mut asm = PesAssembler::new();
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
            .next_packet(async || Ok(iter.next()))
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
        let mut asm = PesAssembler::new();
        let pat_section: Vec<u8> = vec![
            0x00, 0xB0, 0x0D, 0x00, 0x01, 0xC1, 0x00, 0x00, 0x00, 0x01, 0xE1, 0x00, 0x00, 0x00,
            0x00, 0x00,
        ];
        let mut payload = vec![0x00];
        payload.extend_from_slice(&pat_section);

        let packets = vec![make_ts_packet(0x00, true, &payload)];
        let mut iter = packets.into_iter();
        let item = asm
            .next_packet(async || Ok(iter.next()))
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
