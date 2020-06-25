extern crate hex;
extern crate openssl;
use hex::{decode, encode};
use openssl::symm::Cipher;
use std::collections::HashSet;
use std::hash::Hash;
use std::fs::File;
use std::io::BufRead;
use std::io::BufReader;
use std::path::Path;

fn has_unique_elements<T>(iter: T) -> bool
where
    T: IntoIterator,
    T::Item: Eq + Hash,
{
    let mut uniq = HashSet::new();
    iter.into_iter().all(move |x| uniq.insert(x))
}

fn repeated_blocks(
    ciphertext: &[u8],
    blocksize: usize
) -> Result<bool, String> {
    let c_len = ciphertext.len();
    if c_len % blocksize != 0 {
        return Err(
            "The length of the ciphertext must be a multiple of the blocksize".to_string()
        )
    }
    let num_blocks = ciphertext.len() / blocksize;
    let mut blocks: Vec<&[u8]> = Vec::with_capacity(num_blocks);
    for i in 0..num_blocks {
        blocks.push(
            &ciphertext[(i * blocksize)..((i + 1) * blocksize)]
        );
    }
    match !has_unique_elements(blocks) {
        false => Ok(false),
        true => Ok(true),
    }
}

fn main() {
    let path = Path::new("data/hex_values.txt");
    let file = File::open(&path).unwrap();
    let reader = BufReader::new(file);
    let blocksize: usize = Cipher::aes_128_ecb().block_size();
    let result = reader
        .lines()
        .map(|line| decode(line.unwrap()).unwrap())
        .find(|line| repeated_blocks(line, blocksize).unwrap())
        .map(|line| encode(line));
    match result {
        Some(s) => println!("{}", s),
        None => println!("Did not find any results.")
    }
}
