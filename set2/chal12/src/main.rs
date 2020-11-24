extern crate base64;
use base64::decode;
use openssl::symm::{Cipher, Crypter, Mode};
use std::collections::{HashMap, HashSet};
use std::hash::Hash;

const BLOCK_SIZE: usize = 16;
const KEY: &[u8] = &[0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
const PAD_STRING: &str = "Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkgaGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBqdXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUgYnkK";

/// Pad a message, given a blocksize
fn pkcs7(message: &[u8], block_size: usize) -> Vec<u8> {
    let mut message = message.to_vec();
    let mut padding_len = block_size - (message.len() % block_size);
    if padding_len == 0 {
        padding_len = block_size
    };
    let pad = vec![padding_len as u8; padding_len as usize];
    message.extend(pad.iter());
    message
}

/// Ecnrypt a byte slice with AES-128 in ECB mode
fn encrypt_aes_128_ecb(plaintext: &[u8], key: &[u8]) -> Vec<u8> {
    let mut encrypter = Crypter::new(Cipher::aes_128_ecb(), Mode::Encrypt, key, None).unwrap();
    encrypter.pad(false);
    let data_len = plaintext.len();
    let mut ciphertext = vec![0; data_len + BLOCK_SIZE];
    let mut count = encrypter
        .update(&plaintext[..data_len], &mut ciphertext)
        .unwrap();
    count += encrypter.finalize(&mut ciphertext[count..]).unwrap();
    ciphertext.truncate(count);
    ciphertext
}

/// Encryption oracle returns an ecnrypted message
/// with AES-128 in ECB mode
fn encryption_oracle_ecb(mes: &mut Vec<u8>, key: &[u8]) -> Vec<u8> {
    let mut decoded_pad = decode(&PAD_STRING).unwrap();
    mes.append(&mut decoded_pad);
    let padded_mes = pkcs7(&mes, BLOCK_SIZE);
    return encrypt_aes_128_ecb(&padded_mes, &key);
}

/// Check if an iter type has unique elements
fn has_unique_elements<T>(iter: T) -> bool
where
    T: IntoIterator,
    T::Item: Eq + Hash,
{
    let mut uniq = HashSet::new();
    iter.into_iter().all(move |x| uniq.insert(x))
}

/// Check whether a given byte slice has repeated
/// blocks of size blocksize
fn repeated_blocks(ciphertext: &[u8], blocksize: usize) -> Result<bool, String> {
    let c_len = ciphertext.len();
    if c_len % blocksize != 0 {
        return Err("The length of the ciphertext must be a multiple of the blocksize".to_string());
    }
    let num_blocks = ciphertext.len() / blocksize;
    let mut blocks: Vec<&[u8]> = Vec::with_capacity(num_blocks);
    for i in 0..num_blocks {
        blocks.push(&ciphertext[(i * blocksize)..((i + 1) * blocksize)]);
    }
    match !has_unique_elements(blocks) {
        false => Ok(false),
        true => Ok(true),
    }
}

/// Detect the blocksize used in the ECB
/// encryption oracle.
/// This doesn't make much sense, but it's
/// what the challenge asks for
fn detect_blocksize() -> usize {
    let mut blocksize = 0_usize;
    for bs in 2..100 {
        let mut mes = vec![42; bs * 2];
        mes.push(3);
        let ciphertext = encryption_oracle_ecb(&mut mes, &KEY);
        match repeated_blocks(&ciphertext, bs) {
            Ok(true) => {
                blocksize = bs;
                break;
            }
            _ => (),
        }
    }
    blocksize
}

/// Builds a hash-map from the known
/// plaintext
fn build_dict(known_plaintext: &Vec<u8>, blocksize: usize) -> HashMap<Vec<u8>, u8> {
    let mut dict: HashMap<Vec<u8>, u8> = HashMap::new();
    for b in 0..=255 {
        let mut mes = vec![42; blocksize * (known_plaintext.len() / blocksize + 1) - 1];
        mes.drain(mes.len() - known_plaintext.len()..);
        mes.extend(known_plaintext);
        mes.push(b);
        let step = known_plaintext.len() / blocksize * blocksize;
        dict.insert(
            encryption_oracle_ecb(&mut mes, &KEY)[step..step + blocksize].to_vec(),
            b,
        );
    }
    dict
}

/// Recover the full plaintext given an
/// AES-128 ECB ecnrypted cipher
fn get_plaintext(blocksize: usize) -> String {
    let mut plaintext: Vec<u8> = Vec::new();
    let oracle_length = encryption_oracle_ecb(&mut vec![], &KEY).len();
    for i in 0..oracle_length {
        let dict = build_dict(&plaintext, blocksize);
        let mut mes = vec![42; blocksize - i % blocksize - 1];
        let step = i / blocksize * blocksize;
        let target_cipher = encryption_oracle_ecb(&mut mes, &KEY)[step..step + blocksize].to_vec();
        if dict.contains_key(&target_cipher) {
            let byte = dict[&target_cipher];
            plaintext.push(byte);
        } else {
            break;
        }
    }
    String::from_utf8(plaintext).unwrap()
}

/// Break the ECB
fn break_ecb() -> Result<String, String> {
    let blocksize = detect_blocksize();
    if blocksize == 0 {
        Err("ECB or blocksize could not be detected".to_owned())
    } else {
        println!("Detected blocksize: {}", blocksize);
        println!("Recovering plaintext...");
        let plaintext = get_plaintext(blocksize);
        Ok(plaintext)
    }
}

#[test]
fn test_detect_blocksize() {
    let bs = detect_blocksize();
    assert_eq!(bs, 16);
}

fn main() {
    let result = break_ecb();
    match result {
        Ok(plaintext) => println!("Plaintext is: \n{}", plaintext),
        Err(e) => println!("Error: {}", e),
    }
}
