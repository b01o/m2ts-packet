/// Stream type constants for common elementary stream types.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum StreamType {
    Mpeg1Video = 0x01,
    Mpeg2Video = 0x02,
    Mpeg1Audio = 0x03,
    Mpeg2Audio = 0x04,
    H264 = 0x1B,
    H265 = 0x24,
    Aac = 0x0F,
    AacLatm = 0x11,
    Ac3 = 0x81,
    /// Catch-all for unrecognized stream types
    Other(u8),
}

impl From<u8> for StreamType {
    fn from(v: u8) -> Self {
        match v {
            0x01 => Self::Mpeg1Video,
            0x02 => Self::Mpeg2Video,
            0x03 => Self::Mpeg1Audio,
            0x04 => Self::Mpeg2Audio,
            0x0F => Self::Aac,
            0x11 => Self::AacLatm,
            0x1B => Self::H264,
            0x24 => Self::H265,
            0x81 => Self::Ac3,
            other => Self::Other(other),
        }
    }
}

impl StreamType {
    pub fn is_video(&self) -> bool {
        matches!(
            self,
            Self::Mpeg1Video | Self::Mpeg2Video | Self::H264 | Self::H265
        )
    }

    pub fn is_audio(&self) -> bool {
        matches!(
            self,
            Self::Mpeg1Audio | Self::Mpeg2Audio | Self::Aac | Self::AacLatm | Self::Ac3
        )
    }
}

/// A single elementary stream entry in the PMT.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PmtEntry {
    pub stream_type: StreamType,
    pub elementary_pid: u16,
    pub descriptors: Vec<u8>,
}

/// Program Map Table (table_id = 0x02).
///
/// Carried on the PID indicated by the PAT for a given program.
///
/// Section layout (after pointer_field):
/// ```text
/// table_id                 8  (0x02)
/// section_syntax_indicator 1
/// '0'                      1
/// reserved                 2
/// section_length           12
/// program_number           16
/// reserved                 2
/// version_number           5
/// current_next_indicator   1
/// section_number           8
/// last_section_number      8
/// reserved                 3
/// PCR_PID                  13
/// reserved                 4
/// program_info_length      12
/// ── program descriptors (program_info_length bytes) ──
/// ── repeating stream entries ──
///   stream_type             8
///   reserved                3
///   elementary_PID          13
///   reserved                4
///   ES_info_length          12
///   ── ES descriptors (ES_info_length bytes) ──
/// ── end ──
/// CRC_32                   32
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProgramMapTable {
    pub program_number: u16,
    pub version_number: u8,
    pub current_next_indicator: bool,
    pub section_number: u8,
    pub last_section_number: u8,
    pub pcr_pid: u16,
    pub program_info: Vec<u8>,
    pub entries: Vec<PmtEntry>,
}

impl ProgramMapTable {
    /// Parse a PMT from section data (starting from table_id byte).
    pub fn from_bytes(data: &[u8]) -> Option<Self> {
        if data.len() < 12 {
            return None;
        }
        let table_id = data[0];
        if table_id != 0x02 {
            return None;
        }
        let section_length = ((data[1] as usize & 0x0F) << 8) | data[2] as usize;
        let section_end = 3 + section_length;
        if data.len() < section_end {
            return None;
        }

        let program_number = (data[3] as u16) << 8 | data[4] as u16;
        let version_number = (data[5] >> 1) & 0x1F;
        let current_next_indicator = data[5] & 1 != 0;
        let section_number = data[6];
        let last_section_number = data[7];
        let pcr_pid = ((data[8] as u16) & 0x1F) << 8 | data[9] as u16;
        let program_info_length = ((data[10] as usize) & 0x0F) << 8 | data[11] as usize;

        let pi_start = 12;
        let pi_end = pi_start + program_info_length;
        if pi_end > section_end.saturating_sub(4) {
            return None;
        }
        let program_info = data[pi_start..pi_end].to_vec();

        // Parse stream entries
        let entries_end = section_end.saturating_sub(4); // before CRC
        let mut entries = Vec::new();
        let mut i = pi_end;
        while i + 5 <= entries_end {
            let stream_type = StreamType::from(data[i]);
            let elementary_pid = ((data[i + 1] as u16) & 0x1F) << 8 | data[i + 2] as u16;
            let es_info_length = ((data[i + 3] as usize) & 0x0F) << 8 | data[i + 4] as usize;
            i += 5;
            let desc_end = (i + es_info_length).min(entries_end);
            let descriptors = data[i..desc_end].to_vec();
            i = desc_end;
            entries.push(PmtEntry {
                stream_type,
                elementary_pid,
                descriptors,
            });
        }

        Some(Self {
            program_number,
            version_number,
            current_next_indicator,
            section_number,
            last_section_number,
            pcr_pid,
            program_info,
            entries,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a minimal PMT section.
    fn build_pmt_section(program_number: u16, pcr_pid: u16, streams: &[(u8, u16)]) -> Vec<u8> {
        let stream_bytes: usize = streams.len() * 5; // no descriptors
        let section_length = 9 + stream_bytes + 4; // 9 fixed after section_length + streams + CRC
        let mut data = vec![
            0x02, // table_id
        ];
        // section_syntax_indicator(1)=1, '0'(1), reserved(2)=0b11, section_length(12)
        data.push(0xB0 | ((section_length >> 8) as u8 & 0x0F));
        data.push(section_length as u8);
        // program_number
        data.push((program_number >> 8) as u8);
        data.push(program_number as u8);
        // reserved(2), version(5)=0, current_next(1)=1
        data.push(0xC1);
        // section_number, last_section_number
        data.push(0x00);
        data.push(0x00);
        // reserved(3), PCR_PID(13)
        data.push(0xE0 | ((pcr_pid >> 8) as u8 & 0x1F));
        data.push(pcr_pid as u8);
        // reserved(4), program_info_length(12)=0
        data.push(0xF0);
        data.push(0x00);
        // stream entries
        for &(st, pid) in streams {
            data.push(st);
            data.push(0xE0 | ((pid >> 8) as u8 & 0x1F));
            data.push(pid as u8);
            // ES_info_length = 0
            data.push(0xF0);
            data.push(0x00);
        }
        // dummy CRC32
        data.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]);
        data
    }

    #[test]
    fn test_pmt_basic() {
        let data = build_pmt_section(1, 0x100, &[(0x1B, 0x100), (0x0F, 0x101)]);
        let pmt = ProgramMapTable::from_bytes(&data).unwrap();
        assert_eq!(pmt.program_number, 1);
        assert_eq!(pmt.pcr_pid, 0x100);
        assert_eq!(pmt.entries.len(), 2);

        assert_eq!(pmt.entries[0].stream_type, StreamType::H264);
        assert!(pmt.entries[0].stream_type.is_video());
        assert_eq!(pmt.entries[0].elementary_pid, 0x100);

        assert_eq!(pmt.entries[1].stream_type, StreamType::Aac);
        assert!(pmt.entries[1].stream_type.is_audio());
        assert_eq!(pmt.entries[1].elementary_pid, 0x101);
    }

    #[test]
    fn test_pmt_empty_streams() {
        let data = build_pmt_section(5, 0x1FF, &[]);
        let pmt = ProgramMapTable::from_bytes(&data).unwrap();
        assert!(pmt.entries.is_empty());
        assert_eq!(pmt.pcr_pid, 0x1FF);
    }

    #[test]
    fn test_pmt_wrong_table_id() {
        let mut data = build_pmt_section(1, 0x100, &[]);
        data[0] = 0x00;
        assert!(ProgramMapTable::from_bytes(&data).is_none());
    }

    #[test]
    fn test_pmt_too_short() {
        assert!(ProgramMapTable::from_bytes(&[0x02; 5]).is_none());
    }

    #[test]
    fn test_stream_type_other() {
        let data = build_pmt_section(1, 0x100, &[(0xFF, 0x200)]);
        let pmt = ProgramMapTable::from_bytes(&data).unwrap();
        assert_eq!(pmt.entries[0].stream_type, StreamType::Other(0xFF));
        assert!(!pmt.entries[0].stream_type.is_video());
        assert!(!pmt.entries[0].stream_type.is_audio());
    }
}
