use remote_file::HttpFile;
use tokio_stream::StreamExt;
use tokio_util::codec::FramedRead;

#[tokio::main]
async fn main() {
    // streaming some sample file from internet, https://tsduck.io/streams/
    // or replace with your own local file by using tokio::fs::File
    let mut file = HttpFile::new(
        reqwest::Client::new(),
        "https://tsduck.io/streams/australia-dttv/Ten.ts",
    )
    .await
    .unwrap();
    let mut ts_packets = FramedRead::new(&mut file, m2ts_packet::TsPacketDecoder::new(0));
    let mut assembler = m2ts_packet::Assembler::new();

    for _ in 0..10 {
        let next_packet = assembler
            .next_unpacked(async || Ok(ts_packets.try_next().await?.map(|(_, pkt)| pkt)))
            .await
            .unwrap();
        println!("Packet: {:?}", next_packet);
    }
}
