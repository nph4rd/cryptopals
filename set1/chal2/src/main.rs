extern crate hex;
use hex::{encode, decode};

fn xor(x: Vec<u8>, y: Vec<u8>) -> Vec<u8> {
    assert_eq!(x.len(), y.len());
    let mut xor: Vec<u8> = Vec::new();
    for i in 0..x.len() {
        xor.push(x[i] ^ y[i])
    }
    xor
}

fn main() {
    let hex1 = "1c0111001f010100061a024b53535009181c";
    let hex2 = "686974207468652062756c6c277320657965";
    let decoded_hex1 = decode(hex1)
        .expect("Invalid hex string");
    let decoded_hex2 = decode(hex2)
        .expect("Invalid hex string");
    let xor = encode(
        xor(decoded_hex1, decoded_hex2)
    );
    assert_eq!(
        xor,
        "746865206b696420646f6e277420706c6179"
    );
    println!("input1: {}", hex1);
    println!("input2: {}", hex2);
    println!("xor: {}", xor);
}
