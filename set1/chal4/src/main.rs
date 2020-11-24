use std::error::Error;
extern crate hex;
use hex::decode;
use std::collections::HashMap;
use std::str;

const CHARS: [char; 27] = [
    'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n', 'o', 'p', 'q', 'r', 's',
    't', 'u', 'v', 'w', 'x', 'y', 'z', ' ',
];

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
        if s == c {
            count += 1_f32;
        }
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
            return candidate;
        }
        _ => return Candidate::new(String::from("")),
    }
}

fn brute_force(hex: &str) -> Candidate {
    let decoded_hex = decode(hex).expect("Invalid hex string");
    let mut best_candidate = Candidate::new(String::from(""));
    let mut best_score = std::f32::MAX;
    for b in 0..=255 {
        let candidate = byte_xor(&decoded_hex, &b);
        if candidate.score < best_score {
            best_score = candidate.score;
            best_candidate = candidate;
        }
    }
    best_candidate
}

fn read_csv(filepath: &str) -> Result<Vec<String>, Box<dyn Error>> {
    let file = std::fs::File::open(filepath).expect("No such file or directory");
    let mut rdr = csv::ReaderBuilder::new()
        .has_headers(false)
        .from_reader(file);
    let mut ciphertexts: Vec<String> = Vec::new();
    for result in rdr.records() {
        let record = result?;
        ciphertexts.push(record[0].to_string());
    }
    Ok(ciphertexts)
}

fn main() {
    let ciphertexts = read_csv("data/hex_vals.csv");
    match ciphertexts {
        Ok(cs) => {
            let mut best_candidate = Candidate::new(String::from(""));
            let mut best_score = std::f32::MAX;
            let mut best_ciphertext = String::new();
            for c in cs.iter() {
                let candidate = brute_force(c);
                if candidate.score < best_score {
                    best_ciphertext = c.to_string();
                    best_score = candidate.score;
                    best_candidate = candidate;
                }
            }
            println!("ciphertext: {}", best_ciphertext);
            println!("plaintext: {}", best_candidate.plaintext);
        }
        Err(_) => panic!("Error while reading csv"),
    }
}
