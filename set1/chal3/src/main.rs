extern crate hex;
use hex::decode;
use std::str;
use std::collections::HashMap;

const CHARS: [char; 3] = ['a', 'b', 'c'];

struct Candidate {
    plaintext: String,
    score: f32,
    distribution: HashMap<char, f32>,
}

impl Candidate {
    fn new(plaintext: String) -> Candidate {
        Candidate {
            plaintext,
            score: std::f32::MAX,
            distribution: HashMap::new(),
        }
    }
    fn get_distribution(&mut self) {
        for &c in CHARS.iter() {
            let freq: f32 = get_frequency(&self.plaintext, c);
            &self.distribution.insert(c, freq);
        }
    }
    fn get_score(&mut self) {
        self.get_distribution();
        let mut score = 0_f32;
        for (_c, f) in self.distribution.iter() {
            score += f;
        }
        self.score = -score;
    }
}

fn get_frequency(s: &String, c: char) -> f32 {
    let mut count = 0_f32;
    let mut total = 0_f32;
    for s in s.chars() {
        if s == c { count += 1_f32; }
        total += 1_f32;
    }
    count / total
}

fn byte_xor(buffer: &Vec<u8>, byte: &u8) -> Candidate {
    let mut xor: Vec<u8> = Vec::new();
    for b in buffer.iter() {
        xor.push(b ^ byte);
    }
    let result_string = str::from_utf8(&xor);
    match result_string {
        Ok(s) => {
            let mut candidate = Candidate::new(s.to_string());
            candidate.get_score();
            return candidate
        },
        _ => return Candidate::new(String::from("")),
    }
}

fn brute_force(hex: &str) -> String {
    let decoded_hex = decode(hex).
        expect("Invalid hex string");
    let mut plaintext = String::new();
    let mut best_score = std::f32::MAX;
    for b in 0..=255 {
        let candidate = byte_xor(&decoded_hex, &b);
        if candidate.score < best_score {
            best_score = candidate.score;
            plaintext = candidate.plaintext;
        }
    }
    plaintext
}

fn main() {
    let ciphertext = "1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736";
    let plaintext = brute_force(ciphertext);
    println!("ciphertext: {}", ciphertext);
    println!("plaintext: {}", plaintext);
}
