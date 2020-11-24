extern crate base64;
use base64::decode;
use std::collections::HashMap;
use std::fs::File;
use std::io::prelude::*;
use std::str;
use std::string::FromUtf8Error;

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

fn brute_force(cipherbytes: &Vec<u8>) -> Vec<u8> {
    let mut plaintext = String::new();
    let mut best_score = std::f32::MAX;
    for b in 0..=255 {
        let candidate = byte_xor(&cipherbytes, &b);
        if candidate.score < best_score {
            best_score = candidate.score;
            plaintext = candidate.plaintext;
        }
    }
    plaintext.into_bytes()
}

struct Blocks {
    matrix: Vec<Vec<u8>>,
    vec_size: usize,
    key_size: usize,
}

impl Blocks {
    fn new(v: Vec<u8>, key_size: usize) -> Blocks {
        let vec_size = v.len();
        let block_len = vec_size / key_size + 1;
        let mut matrix: Vec<Vec<u8>> = Vec::with_capacity(key_size);
        for i in 0..key_size {
            let mut block: Vec<u8> = Vec::with_capacity(block_len);
            for j in 0..block_len {
                let index = key_size * j + i;
                if index < vec_size {
                    block.push(v[index]);
                }
            }
            matrix.push(block)
        }
        Blocks {
            matrix,
            vec_size,
            key_size,
        }
    }
    fn solve(&self) -> Result<String, FromUtf8Error> {
        let mut plaintext_bytes = vec![0; self.vec_size];
        for block_num in 0..self.matrix.len() {
            let solved_block = brute_force(&self.matrix[block_num]);
            for i in 0..solved_block.len() {
                let index = block_num + self.key_size * i;
                if index < self.vec_size {
                    plaintext_bytes[index] = solved_block[i];
                }
            }
        }
        String::from_utf8(plaintext_bytes)
    }
}

fn hamming(x: &[u8], y: &[u8]) -> Result<u64, String> {
    // Based on:
    // https://docs.rs/hamming/0.1.3/hamming/fn.distance.html
    if x.len() != y.len() {
        return Err("String slices must be of same length".to_string());
    } else {
        let d = x
            .iter()
            .zip(y)
            .fold(0, |a, (b, c)| a + (*b ^ *c).count_ones() as u64);
        Ok(d)
    }
}

fn read_file(filepath: &str) -> String {
    let mut file = File::open(filepath).unwrap();
    let mut contents = String::new();
    file.read_to_string(&mut contents).unwrap();
    contents
}

fn average_distance(v: &Vec<u8>, n: usize) -> f64 {
    // get normalized average hamming distance
    // between blocks of length n in vector v
    let num_blocks = v.len() / n;
    let mut sum_distance = 0_f64;
    for i in 0..num_blocks - 1 {
        sum_distance +=
            hamming(&v[n * i..n * (i + 1)], &v[n * (i + 1)..n * (i + 2)]).unwrap() as f64;
    }
    sum_distance / num_blocks as f64 / n as f64
}

fn decrypt(cipherbytes: Vec<u8>) -> Result<String, FromUtf8Error> {
    let mut best_distance: f64 = std::f64::MAX;
    let mut best_keysize: usize = 2;
    for key_size in 2..41 {
        let d = average_distance(&cipherbytes, key_size);
        if d < best_distance {
            best_distance = d;
            best_keysize = key_size;
        }
    }
    let blocks = Blocks::new(cipherbytes, best_keysize);
    blocks.solve()
}

fn main() {
    let base64 = read_file("data/ciphertext.txt");
    let bytes = decode(base64);
    match bytes {
        Ok(v) => {
            let plaintext = decrypt(v);
            match plaintext {
                Ok(s) => println!("plaintext: {}", s),
                Err(e) => println!("Conversion error: {}", e),
            }
        }
        Err(e) => println!("Invalid base64 input: {}", e),
    };
    let d = hamming("this is a test".as_bytes(), "wokka wokka!!!".as_bytes()).unwrap();
    assert_eq!(d, 37_u64);
}
