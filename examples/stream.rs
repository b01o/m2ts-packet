use m2ts_packet::{TsPacketDecoder, TsPacketStreamAssemble};
use remote_file::HttpFile;
use tokio_stream::StreamExt;
use tokio_util::codec::FramedRead;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // streaming some sample file from internet, https://tsduck.io/streams/
    // or replace with your own local file by using tokio::fs::File
    let mut file = HttpFile::new(
        reqwest::Client::new(),
        "https://tsduck.io/streams/australia-dttv/Ten.ts",
    )
    .await
    .unwrap();

    let mut pes = FramedRead::new(&mut file, TsPacketDecoder::new(0))
        .assemble()
        .take(10);
    while let Some(packet) = pes.try_next().await? {
        println!("PES Packet: {:?}", packet);
    }
    Ok(())
}
