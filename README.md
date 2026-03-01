# m2ts-packet

[![crates.io](https://img.shields.io/crates/v/mkv-element)](https://crates.io/crates/m2ts-packet)
[![docs.rs](https://img.shields.io/docsrs/mkv-element)](https://docs.rs/m2ts-packet)
[![MIT License](https://img.shields.io/badge/license-MIT-blue.svg)](./LICENSE)

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
