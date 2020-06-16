extern crate base64;
extern crate hex;
use base64::encode;
use hex::decode;

fn hex2base64(hex: &str) -> String {
    let bytes = decode(hex)
        .expect("Invalid hex string");
    encode(bytes)
}

fn main() {
    let hex = "49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d";
    let base64 = hex2base64(hex);
    println!("hex: {}", hex);
    println!("base64 {}", base64);
}
