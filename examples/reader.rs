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
    let ts_packets = FramedRead::new(&mut file, ts_packet::TsPacketDecoder);
    let mut unpack = ts_packet::UnpackedDecoder::new(ts_packets);
    let mut count = 0;
    while let Some(unpacked) = unpack.try_next().await.unwrap() {
        println!("Packet {count}: {:?}", unpacked);
        count += 1;
        if count >= 10 {
            break;
        }
    }
    println!("---");

    // take another 5 packets
    let unpackeds: Vec<_> = unpack.take(5).collect().await;
    for (i, unpacked) in unpackeds.into_iter().enumerate() {
        println!("Packet {}: {:?}", count + i, unpacked.unwrap());
    }
}
