extern crate hex;
use hex::{encode, decode};
use std::str;

fn byte_xor(buffer: &Vec<u8>, byte: &u8) -> String {
    let mut xor: Vec<u8> = Vec::new();
    for b in buffer.iter() {
        xor.push(b ^ byte);
    }
    let result_string = str::from_utf8(&xor);
    match result_string {
        Ok(s) => return s.to_string(),
        _ => return String::from(""),
    }
}

fn brute_force(hex: &str) -> String {
    let decoded_hex = decode(hex).
        expect("Invalid hex string");
    let mut candidate = String::new();
    for b in 0..=255 {
        candidate = byte_xor(&decoded_hex, &b);
    }
    candidate
}

fn main() {
    let ciphertext = "1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736";
    let plaintext = brute_force(ciphertext);
    println!("ciphertext: {}", ciphertext);
    println!("plaintext: {}", plaintext);
}
