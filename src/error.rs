
pub type Result<T> = std::result::Result<T, TsPacketError>;

#[derive(Debug, thiserror::Error)]
pub enum TsPacketError {
    #[error("Invalid Adaption Field")]
    InvalidAdaptationField,
    #[error("Invalid TS Packet")]
    InvalidPacket,
    #[error(transparent)]
    Io(#[from] std::io::Error),
}
