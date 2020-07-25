extern crate base64;
extern crate openssl;
use openssl::symm::{Cipher, Mode, Crypter};
use base64::decode;
use std::fs::read_to_string;

const BLOCK_SIZE: usize = 16;

fn decrypt_aes_128_ecb(
    ciphertext: Vec<u8>,
    key: &[u8],
) -> Vec<u8> {
    let mut decrypter = Crypter::new(
        Cipher::aes_128_ecb(),
        Mode::Decrypt,
        key,
        None).unwrap();
    let data_len = ciphertext.len();
    let mut plaintext = vec![0; data_len + BLOCK_SIZE];
    let mut count = decrypter
        .update(&ciphertext[..data_len], &mut plaintext)
        .unwrap();
    count += decrypter
        .finalize(&mut plaintext[count..])
        .unwrap();
    plaintext.truncate(count);
    plaintext
}

fn split_blocks<'a>(
    ciphertext: &'a [u8],
    blocksize: usize,
) -> Vec<&[u8]> {
    let mut result: Vec<&[u8]> = Vec::with_capacity(blocksize);
    for i in 0..blocksize {
        result.push(&ciphertext[i..(blocksize * (i + 1))]);
    }
    result
}

fn decrypt_aes_128_cbc(
    ciphertext: &[u8],
    iv: Vec<u8>,
    key: &[u8],
) -> String {
    let mut plaintext: Vec<u8> = Vec::with_capacity(ciphertext.len());
    let split_ciphertext = split_blocks(ciphertext, BLOCK_SIZE);
    for i in 0..split_ciphertext.len(){
        let plaintext_block = decrypt_aes_128_ecb(
            split_ciphertext[i].to_vec(),
            key,
        );
       plaintext.extend(plaintext_block);
    }
    String::from_utf8(plaintext).unwrap()
}

fn main() {
    let base64 = read_to_string("data/ciphertext.txt")
        .expect("Something went wrong reading the file");
    let ciphertext = decode(base64)
        .expect("Invalid base64 input");
    let key = b"YELLOW SUBMARINE";
    let iv = vec![0; BLOCK_SIZE];
    let plaintext = decrypt_aes_128_cbc(&ciphertext[..], iv, key);
    println!("{}", plaintext);
}

#[test]
fn test_chal10() {
    assert!(true);
}
