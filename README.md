# m2ts-packet

(WIP) A MPEG2 Transport Stream (TS) packet encoder and decoder in Rust.

``` rust
#[tokio::main]
async fn main() {
    // replace with actual file
    let mut file = tokio::fs::File::open("path/to/your/file.ts").await.unwrap();
    let ts_packets = tokio_util::codec::FramedRead::new(&mut file, ts_packet::TsPacketDecoder);
    let mut unpack = ts_packet::UnpackedDecoder::new(ts_packets);
    let mut count = 0;
    while let Some(unpacked) = unpack.try_next().await.unwrap() {
        println!("Packet {count}: {:?}", unpacked);
        count += 1;
        if count >= 10 {
            break;
        }
    }
}
```