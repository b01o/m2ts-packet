/// A single entry in the PAT: maps a program number to a PID.
///
/// - program_number == 0 → the PID refers to the NIT (Network Information Table)
/// - program_number != 0 → the PID refers to the PMT for that program
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PatEntry {
    pub program_number: u16,
    pub pid: u16,
}

/// Program Association Table (table_id = 0x00).
///
/// Carried on PID 0x0000. Maps each program number to the PID that carries its PMT.
///
/// Section layout (after pointer_field):
/// ```text
/// table_id                 8  (0x00)
/// section_syntax_indicator 1
/// '0'                      1
/// reserved                 2
/// section_length           12
/// transport_stream_id      16
/// reserved                 2
/// version_number           5
/// current_next_indicator   1
/// section_number           8
/// last_section_number      8
/// ── repeating 4-byte entries ──
///   program_number          16
///   reserved                3
///   PID                     13
/// ── end ──
/// CRC_32                   32
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProgramAssociationTable {
    pub transport_stream_id: u16,
    pub version_number: u8,
    pub current_next_indicator: bool,
    pub section_number: u8,
    pub last_section_number: u8,
    pub entries: Vec<PatEntry>,
}

impl ProgramAssociationTable {
    /// Parse a PAT from section data (starting from table_id byte).
    pub fn from_bytes(data: &[u8]) -> Option<Self> {
        if data.len() < 8 {
            return None;
        }
        let table_id = data[0];
        if table_id != 0x00 {
            return None;
        }
        let section_length = ((data[1] as usize & 0x0F) << 8) | data[2] as usize;
        // section_length includes bytes from transport_stream_id to CRC inclusive
        // total section bytes = 3 (header) + section_length
        let section_end = 3 + section_length;
        if data.len() < section_end {
            return None;
        }

        let transport_stream_id = (data[3] as u16) << 8 | data[4] as u16;
        let version_number = (data[5] >> 1) & 0x1F;
        let current_next_indicator = data[5] & 1 != 0;
        let section_number = data[6];
        let last_section_number = data[7];

        // Entries start at offset 8, end 4 bytes before section_end (CRC32)
        let entries_end = section_end.saturating_sub(4);
        let mut entries = Vec::new();
        let mut i = 8;
        while i + 4 <= entries_end {
            let program_number = (data[i] as u16) << 8 | data[i + 1] as u16;
            let pid = ((data[i + 2] as u16) & 0x1F) << 8 | data[i + 3] as u16;
            entries.push(PatEntry {
                program_number,
                pid,
            });
            i += 4;
        }

        Some(Self {
            transport_stream_id,
            version_number,
            current_next_indicator,
            section_number,
            last_section_number,
            entries,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a minimal PAT section (no CRC check in parser, so we use dummy CRC).
    fn build_pat_section(ts_id: u16, entries: &[(u16, u16)]) -> Vec<u8> {
        let entry_bytes = entries.len() * 4;
        let section_length = 5 + entry_bytes + 4; // 5 fixed + entries + CRC
        let mut data = Vec::new();
        // table_id
        data.push(0x00);
        // section_syntax_indicator(1)=1, '0'(1), reserved(2)=0b11, section_length(12)
        data.push(0xB0 | ((section_length >> 8) as u8 & 0x0F));
        data.push(section_length as u8);
        // transport_stream_id
        data.push((ts_id >> 8) as u8);
        data.push(ts_id as u8);
        // reserved(2), version_number(5)=1, current_next(1)=1
        data.push(0xC3); // 11_00001_1
        // section_number, last_section_number
        data.push(0x00);
        data.push(0x00);
        // entries
        for &(pn, pid) in entries {
            data.push((pn >> 8) as u8);
            data.push(pn as u8);
            data.push(0xE0 | ((pid >> 8) as u8 & 0x1F));
            data.push(pid as u8);
        }
        // dummy CRC32
        data.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]);
        data
    }

    #[test]
    fn test_pat_single_program() {
        let data = build_pat_section(1, &[(1, 0x100)]);
        let pat = ProgramAssociationTable::from_bytes(&data).unwrap();
        assert_eq!(pat.transport_stream_id, 1);
        assert_eq!(pat.version_number, 1);
        assert!(pat.current_next_indicator);
        assert_eq!(pat.entries.len(), 1);
        assert_eq!(pat.entries[0].program_number, 1);
        assert_eq!(pat.entries[0].pid, 0x100);
    }

    #[test]
    fn test_pat_multiple_programs() {
        let data = build_pat_section(0x0A, &[(0, 0x10), (1, 0x100), (2, 0x200)]);
        let pat = ProgramAssociationTable::from_bytes(&data).unwrap();
        assert_eq!(pat.entries.len(), 3);
        assert_eq!(pat.entries[0].program_number, 0); // NIT
        assert_eq!(pat.entries[0].pid, 0x10);
        assert_eq!(pat.entries[1].program_number, 1);
        assert_eq!(pat.entries[1].pid, 0x100);
        assert_eq!(pat.entries[2].program_number, 2);
        assert_eq!(pat.entries[2].pid, 0x200);
    }

    #[test]
    fn test_pat_empty() {
        let data = build_pat_section(1, &[]);
        let pat = ProgramAssociationTable::from_bytes(&data).unwrap();
        assert!(pat.entries.is_empty());
    }

    #[test]
    fn test_pat_wrong_table_id() {
        let mut data = build_pat_section(1, &[(1, 0x100)]);
        data[0] = 0x02; // wrong table_id
        assert!(ProgramAssociationTable::from_bytes(&data).is_none());
    }

    #[test]
    fn test_pat_too_short() {
        assert!(ProgramAssociationTable::from_bytes(&[0x00, 0xB0]).is_none());
    }
}
