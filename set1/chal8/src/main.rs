extern crate hex;
extern crate openssl;
use hex::decode;
use std::error::Error;
use openssl::symm::Cipher;
use std::collections::HashSet;
use std::hash::Hash;

fn read_csv(
    filepath: &str
) -> Result<Vec<String>, Box<dyn Error>> {
    let file = std::fs::File::open(filepath)
        .expect("No such file or directory");
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
    match has_unique_elements(blocks) {
        false => Ok(true),
        true => Ok(false),
    }
}

fn main() {
    let blocksize: usize = Cipher::aes_128_ecb().block_size();
    let ciphertexts = read_csv("data/hex_values.csv");
    match ciphertexts {
        Ok(cs) => {
            for c in cs.iter() {
                let decoded_hex = decode(c)
                    .expect("Invalid hex string");
                if repeated_blocks(&decoded_hex, blocksize)
                    .unwrap() {
                        println!("{}", c);
                }
            }
        },
        Err(_) => panic!("Error while reading csv"),
    }
}
