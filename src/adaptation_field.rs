use bytes::Bytes;
use bitfield_struct::bitfield;

#[bitfield(u8, order = Msb)]
pub struct AdaptationFieldFlags {
    pub discontinuity_indicator: bool,
    pub random_access_indicator: bool,
    pub elementary_stream_priority_indicator: bool,
    pub pcr_flag: bool,
    pub opcr_flag: bool,
    pub splicing_point_flag: bool,
    pub transport_private_data_flag: bool,
    pub adaptation_field_extension_flag: bool,
}

#[derive(Debug)]
pub struct AdaptationField {
    pub adaptation_field_length: u8,
    pub flags: AdaptationFieldFlags,
    /// 48 bit, Program clock reference, stored as 33 bits base, 6 bits reserved, 9 bits extension.  The value is calculated as base * 300 + extension.
    pub program_clock_reference: Option<u64>, // u48
    /// 	48 bit, Original program clock reference, Helps when one TS is copied into another
    pub original_program_clock_reference: Option<u64>, // u48
    pub splice_countdown: Option<u8>,
    // transport private data len: u8
    pub transport_private_data: Bytes,
    // Adaptation extension length: u8
    pub adaptation_field_extension: Bytes,
    // pub stuffing_bytes: Vec<u8>,
}

impl AdaptationField {
    // data excludes the adaptation_field_length byte
    pub fn from_bytes(data: Bytes) -> Option<Self> {
        let adaption_field_length = data.len();
        let mut index = 0;
        let flags = AdaptationFieldFlags::from_bits(*data.get(index)?);
        index += 1;

        let program_clock_reference = if flags.pcr_flag() {
            let pcr_bytes = data.get(index..index + 6)?;
            let pcr_base = (u32::from_be_bytes(pcr_bytes[0..4].try_into().unwrap()) as u64) << 1
                | (pcr_bytes[4] >> 7) as u64; // 33 bits
            let pcr_extension = ((pcr_bytes[4] as u64) & 1) << 8 | pcr_bytes[5] as u64; // 9 bits
            index += 6;
            Some(pcr_base * 300 + pcr_extension)
        } else {
            None
        };
        let original_program_clock_reference = if flags.opcr_flag() {
            let opcr_bytes = data.get(index..index + 6)?;
            let opcr_base = (u32::from_be_bytes(opcr_bytes[0..4].try_into().unwrap()) as u64) << 1
                | (opcr_bytes[4] >> 7) as u64; // 33 bits
            let opcr_extension = ((opcr_bytes[4] as u64) & 1) << 8 | opcr_bytes[5] as u64; // 9 bits
            index += 6;
            Some(opcr_base * 300 + opcr_extension)
        } else {
            None
        };
        let splice_countdown = if flags.splicing_point_flag() {
            let countdown = *data.get(index)?;
            index += 1;
            Some(countdown)
        } else {
            None
        };
        let transport_private_data = if flags.transport_private_data_flag() {
            let len = *data.get(index)? as usize;
            index += 1;
            if index + len > data.len() {
                return None;
            }
            let slice = data.slice(index..index + len);
            index += len;
            slice
        } else {
            Bytes::new()
        };
        let adaptation_field_extension = if flags.adaptation_field_extension_flag() {
            let len = *data.get(index)? as usize;
            index += 1;
            if index + len > data.len() {
                return None;
            }
            let slice = data.slice(index..index + len);
            // index += len;
            slice
        } else {
            Bytes::new()
        };
        Some(Self {
            adaptation_field_length: adaption_field_length as u8,
            flags,
            program_clock_reference,
            original_program_clock_reference,
            splice_countdown,
            transport_private_data,
            adaptation_field_extension,
        })
    }
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut data = Vec::with_capacity(self.adaptation_field_length as usize);
        data.push(self.flags.into_bits());
        if self.flags.pcr_flag() {
            let pcr_base = self.program_clock_reference.unwrap() / 300;
            let pcr_extension = self.program_clock_reference.unwrap() % 300;
            let pcr_bytes = [
                (pcr_base >> 25) as u8,
                (pcr_base >> 17) as u8,
                (pcr_base >> 9) as u8,
                (pcr_base >> 1) as u8,
                ((pcr_base & 1) << 7) as u8 | 0x7E | (pcr_extension >> 8) as u8,
                (pcr_extension & 0xFF) as u8,
            ];
            data.extend_from_slice(&pcr_bytes);
        }
        if self.flags.opcr_flag() {
            let opcr_base = self.original_program_clock_reference.unwrap() / 300;
            let opcr_extension = self.original_program_clock_reference.unwrap() % 300;
            let opcr_bytes = [
                (opcr_base >> 25) as u8,
                (opcr_base >> 17) as u8,
                (opcr_base >> 9) as u8,
                (opcr_base >> 1) as u8,
                ((opcr_base & 1) << 7) as u8 | 0x7E | (opcr_extension >> 8) as u8,
                (opcr_extension & 0xFF) as u8,
            ];
            data.extend_from_slice(&opcr_bytes);
        }
        if self.flags.splicing_point_flag() {
            data.push(self.splice_countdown.unwrap_or_default());
        }
        if self.flags.transport_private_data_flag() {
            data.push(self.transport_private_data.len() as u8);
            data.extend_from_slice(&self.transport_private_data);
        }
        if self.flags.adaptation_field_extension_flag() {
            data.push(self.adaptation_field_extension.len() as u8);
            data.extend_from_slice(&self.adaptation_field_extension);
        }

        // add stuffing bytes if needed
        while data.len() < self.adaptation_field_length as usize {
            data.push(0xFF);
        }
        data
    }
}


#[cfg(test)]
mod tests {
    use super::*;

    /// Helper: build a flags byte from individual bits (MSB order).
    fn make_flags(
        discontinuity: bool,
        random_access: bool,
        es_priority: bool,
        pcr: bool,
        opcr: bool,
        splicing: bool,
        private_data: bool,
        extension: bool,
    ) -> u8 {
        (discontinuity as u8) << 7
            | (random_access as u8) << 6
            | (es_priority as u8) << 5
            | (pcr as u8) << 4
            | (opcr as u8) << 3
            | (splicing as u8) << 2
            | (private_data as u8) << 1
            | extension as u8
    }

    /// Encode a PCR value (base, extension) into 6 bytes.
    fn encode_pcr(base: u64, extension: u64) -> [u8; 6] {
        [
            (base >> 25) as u8,
            (base >> 17) as u8,
            (base >> 9) as u8,
            (base >> 1) as u8,
            ((base & 1) << 7) as u8 | 0x7E | (extension >> 8) as u8,
            (extension & 0xFF) as u8,
        ]
    }

    // ---------------------------------------------------------------
    // from_bytes tests
    // ---------------------------------------------------------------

    #[test]
    fn test_flags_only_no_optional_fields() {
        // flags = 0x00 → nothing set
        let data = Bytes::from_static(&[0x00]);
        let af = AdaptationField::from_bytes(data).unwrap();
        assert_eq!(af.adaptation_field_length, 1);
        assert!(af.program_clock_reference.is_none());
        assert!(af.original_program_clock_reference.is_none());
        assert!(af.splice_countdown.is_none());
        assert!(af.transport_private_data.is_empty());
        assert!(af.adaptation_field_extension.is_empty());
    }

    #[test]
    fn test_pcr_decode_zero() {
        // PCR with base=0, extension=0 → value=0
        let flags = make_flags(false, false, false, true, false, false, false, false);
        let pcr = encode_pcr(0, 0);
        let mut data = vec![flags];
        data.extend_from_slice(&pcr);
        let af = AdaptationField::from_bytes(Bytes::from(data)).unwrap();
        assert_eq!(af.program_clock_reference, Some(0));
    }

    #[test]
    fn test_pcr_decode_known_value() {
        // base=1000, extension=150 → value = 1000*300 + 150 = 300150
        let flags = make_flags(false, false, false, true, false, false, false, false);
        let pcr = encode_pcr(1000, 150);
        let mut data = vec![flags];
        data.extend_from_slice(&pcr);
        let af = AdaptationField::from_bytes(Bytes::from(data)).unwrap();
        assert_eq!(af.program_clock_reference, Some(300_150));
    }

    #[test]
    fn test_pcr_decode_max_base() {
        // max 33-bit base = 2^33 - 1 = 8589934591, extension=299
        let base: u64 = (1 << 33) - 1;
        let ext: u64 = 299;
        let flags = make_flags(false, false, false, true, false, false, false, false);
        let pcr = encode_pcr(base, ext);
        let mut data = vec![flags];
        data.extend_from_slice(&pcr);
        let af = AdaptationField::from_bytes(Bytes::from(data)).unwrap();
        assert_eq!(af.program_clock_reference, Some(base * 300 + ext));
    }

    #[test]
    fn test_pcr_decode_extension_bit8_set() {
        // extension = 256 (bit 8 set) to verify low bit of byte 4
        let base: u64 = 42;
        let ext: u64 = 256;
        let flags = make_flags(false, false, false, true, false, false, false, false);
        let pcr = encode_pcr(base, ext);
        let mut data = vec![flags];
        data.extend_from_slice(&pcr);
        let af = AdaptationField::from_bytes(Bytes::from(data)).unwrap();
        assert_eq!(af.program_clock_reference, Some(base * 300 + ext));
    }

    #[test]
    fn test_opcr_decode() {
        let base: u64 = 5000;
        let ext: u64 = 100;
        let flags = make_flags(false, false, false, false, true, false, false, false);
        let pcr = encode_pcr(base, ext);
        let mut data = vec![flags];
        data.extend_from_slice(&pcr);
        let af = AdaptationField::from_bytes(Bytes::from(data)).unwrap();
        assert_eq!(af.original_program_clock_reference, Some(base * 300 + ext));
    }

    #[test]
    fn test_pcr_and_opcr_together() {
        let flags = make_flags(false, false, false, true, true, false, false, false);
        let pcr = encode_pcr(100, 50);
        let opcr = encode_pcr(200, 99);
        let mut data = vec![flags];
        data.extend_from_slice(&pcr);
        data.extend_from_slice(&opcr);
        let af = AdaptationField::from_bytes(Bytes::from(data)).unwrap();
        assert_eq!(af.program_clock_reference, Some(100 * 300 + 50));
        assert_eq!(af.original_program_clock_reference, Some(200 * 300 + 99));
    }

    #[test]
    fn test_splice_countdown() {
        let flags = make_flags(false, false, false, false, false, true, false, false);
        let data = Bytes::from(vec![flags, 42]);
        let af = AdaptationField::from_bytes(data).unwrap();
        assert_eq!(af.splice_countdown, Some(42));
    }

    #[test]
    fn test_transport_private_data() {
        let flags = make_flags(false, false, false, false, false, false, true, false);
        let data = Bytes::from(vec![flags, 3, 0xAA, 0xBB, 0xCC]);
        let af = AdaptationField::from_bytes(data).unwrap();
        assert_eq!(af.transport_private_data, Bytes::from_static(&[0xAA, 0xBB, 0xCC]));
    }

    #[test]
    fn test_adaptation_field_extension() {
        let flags = make_flags(false, false, false, false, false, false, false, true);
        let data = Bytes::from(vec![flags, 2, 0x01, 0x02]);
        let af = AdaptationField::from_bytes(data).unwrap();
        assert_eq!(af.adaptation_field_extension, Bytes::from_static(&[0x01, 0x02]));
    }

    #[test]
    fn test_all_optional_fields() {
        let flags = make_flags(true, true, true, true, true, true, true, true);
        let pcr = encode_pcr(999, 123);
        let opcr = encode_pcr(888, 77);
        let splice: u8 = 10;
        let private = [0xDE, 0xAD];
        let ext = [0xBE, 0xEF];

        let mut data = vec![flags];
        data.extend_from_slice(&pcr);
        data.extend_from_slice(&opcr);
        data.push(splice);
        data.push(private.len() as u8);
        data.extend_from_slice(&private);
        data.push(ext.len() as u8);
        data.extend_from_slice(&ext);

        let af = AdaptationField::from_bytes(Bytes::from(data)).unwrap();
        assert_eq!(af.program_clock_reference, Some(999 * 300 + 123));
        assert_eq!(af.original_program_clock_reference, Some(888 * 300 + 77));
        assert_eq!(af.splice_countdown, Some(10));
        assert_eq!(af.transport_private_data, Bytes::from_static(&[0xDE, 0xAD]));
        assert_eq!(af.adaptation_field_extension, Bytes::from_static(&[0xBE, 0xEF]));
        assert!(af.flags.discontinuity_indicator());
        assert!(af.flags.random_access_indicator());
        assert!(af.flags.elementary_stream_priority_indicator());
    }

    #[test]
    fn test_empty_data_returns_none() {
        assert!(AdaptationField::from_bytes(Bytes::new()).is_none());
    }

    #[test]
    fn test_truncated_pcr_returns_none() {
        let flags = make_flags(false, false, false, true, false, false, false, false);
        // Only 3 bytes of PCR instead of 6
        let data = Bytes::from(vec![flags, 0x00, 0x00, 0x00]);
        assert!(AdaptationField::from_bytes(data).is_none());
    }

    // ---------------------------------------------------------------
    // to_bytes tests
    // ---------------------------------------------------------------

    #[test]
    fn test_to_bytes_flags_only() {
        let af = AdaptationField {
            adaptation_field_length: 1,
            flags: AdaptationFieldFlags::new().with_random_access_indicator(true),
            program_clock_reference: None,
            original_program_clock_reference: None,
            splice_countdown: None,
            transport_private_data: Default::default(),
            adaptation_field_extension: Default::default(),
        };
        let bytes = af.to_bytes();
        assert_eq!(bytes.len(), 1);
        assert_eq!(bytes[0], 0b0100_0000); // random_access_indicator set
    }

    #[test]
    fn test_to_bytes_pcr_reserved_bits() {
        // Verify 6 reserved bits in PCR byte 4 are all 1
        let af = AdaptationField {
            adaptation_field_length: 7,
            flags: AdaptationFieldFlags::new().with_pcr_flag(true),
            program_clock_reference: Some(0), // base=0, ext=0
            original_program_clock_reference: None,
            splice_countdown: None,
            transport_private_data: Default::default(),
            adaptation_field_extension: Default::default(),
        };
        let bytes = af.to_bytes();
        // byte 0 = flags, bytes 1-6 = PCR
        // byte 5 (PCR byte 4): base[0]=0, reserved=0b111111, ext[8]=0 → 0x7E
        assert_eq!(bytes[5] & 0x7E, 0x7E);
    }

    #[test]
    fn test_to_bytes_stuffing() {
        // adaptation_field_length=10 but only flags(1) → 9 stuffing bytes of 0xFF
        let af = AdaptationField {
            adaptation_field_length: 10,
            flags: AdaptationFieldFlags::new(),
            program_clock_reference: None,
            original_program_clock_reference: None,
            splice_countdown: None,
            transport_private_data: Default::default(),
            adaptation_field_extension: Default::default(),
        };
        let bytes = af.to_bytes();
        assert_eq!(bytes.len(), 10);
        assert!(bytes[1..].iter().all(|&b| b == 0xFF));
    }

    // ---------------------------------------------------------------
    // roundtrip tests
    // ---------------------------------------------------------------

    #[test]
    fn test_roundtrip_pcr() {
        for &(base, ext) in &[
            (0u64, 0u64),
            (1, 0),
            (0, 1),
            (0, 299),
            (1000, 150),
            ((1u64 << 33) - 1, 299),
            (123456789, 42),
        ] {
            let pcr_value = base * 300 + ext;
            let flags = AdaptationFieldFlags::new().with_pcr_flag(true);
            let af = AdaptationField {
                adaptation_field_length: 7,
                flags,
                program_clock_reference: Some(pcr_value),
                original_program_clock_reference: None,
                splice_countdown: None,
                transport_private_data: Default::default(),
                adaptation_field_extension: Default::default(),
            };
            let bytes = af.to_bytes();
            let af2 = AdaptationField::from_bytes(Bytes::from(bytes)).unwrap();
            assert_eq!(
                af2.program_clock_reference,
                Some(pcr_value),
                "roundtrip failed for base={base}, ext={ext}"
            );
        }
    }

    #[test]
    fn test_roundtrip_all_fields() {
        let flags = AdaptationFieldFlags::new()
            .with_discontinuity_indicator(true)
            .with_pcr_flag(true)
            .with_opcr_flag(true)
            .with_splicing_point_flag(true)
            .with_transport_private_data_flag(true)
            .with_adaptation_field_extension_flag(true);
        let af = AdaptationField {
            adaptation_field_length: 24,
            flags,
            program_clock_reference: Some(12345 * 300 + 67),
            original_program_clock_reference: Some(99999 * 300 + 200),
            splice_countdown: Some(5),
            transport_private_data: Bytes::from_static(&[0x01, 0x02, 0x03]),
            adaptation_field_extension: Bytes::from_static(&[0xAA]),
        };
        let bytes = af.to_bytes();
        let af2 = AdaptationField::from_bytes(Bytes::from(bytes)).unwrap();
        assert_eq!(af2.program_clock_reference, af.program_clock_reference);
        assert_eq!(
            af2.original_program_clock_reference,
            af.original_program_clock_reference
        );
        assert_eq!(af2.splice_countdown, af.splice_countdown);
        assert_eq!(af2.transport_private_data, af.transport_private_data);
        assert_eq!(
            af2.adaptation_field_extension,
            af.adaptation_field_extension
        );
    }
}
