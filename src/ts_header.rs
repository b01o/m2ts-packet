use crate::*;

#[bitfield(u32, order = Msb)]
pub struct TransportStreamHeader {
    #[bits(8, default = 0x47, access = RO)]
    pub sync_byte: u8,
    #[bits(1)]
    pub transport_error_indicator: bool,
    #[bits(1)]
    pub payload_unit_start_indicator: bool,
    #[bits(1)]
    pub transport_priority: bool,
    #[bits(13)]
    pub pid: u16,
    #[bits(2)]
    pub transport_scrambling_control: ScramblingControl,
    /// from adaptation_field_control, 10 or 11
    pub adaptation_field: bool,
    /// from adaptation_field_control, 01 or 11
    pub payload: bool,
    #[bits(4)]
    pub continuity_counter: u8,
}


#[derive(Debug, PartialEq, Eq)]
#[repr(u8)]
#[bitenum]
pub enum ScramblingControl {
    #[fallback]
    NotScrambled = 0,
    Reserved = 1,
    ScrambledWithEvenKey = 2,
    ScrambledWithOddKey = 3,
}
