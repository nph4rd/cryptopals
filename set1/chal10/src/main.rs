extern crate base64;
extern crate openssl;
use openssl::symm::{Cipher, Mode, Crypter};
use base64::decode;
use std::fs::read_to_string;

const BLOCK_SIZE: usize = 16;

fn xor(x: &Vec<u8>, y: &Vec<u8>) -> Vec<u8> {
    assert_eq!(x.len(), y.len());
    let mut xor: Vec<u8> = Vec::new();
    for i in 0..x.len() {
        xor.push(x[i] ^ y[i])
    }
    xor
}

fn decrypt_aes_128_ecb(
    ciphertext: &[u8],
    key: &[u8],
) -> Vec<u8> {
    let mut decrypter = Crypter::new(
        Cipher::aes_128_ecb(),
        Mode::Decrypt,
        key,
        None).unwrap();
    decrypter.pad(false);
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

fn split_blocks(
    ciphertext: Vec<u8>,
    blocksize: usize,
) -> Vec<Vec<u8>> {
    let num_blocks = ciphertext.len() / blocksize;
    let mut result: Vec<Vec<u8>> = Vec::with_capacity(num_blocks);
    for i in 0..num_blocks {
        result.push(ciphertext[(blocksize * i)..(blocksize * (i + 1))].to_vec());
    }
    result
}

fn decrypt_aes_128_cbc(
    ciphertext: Vec<u8>,
    iv: Vec<u8>,
    key: &[u8],
) -> String {
    let ciphertext_len = ciphertext.len();
    let mut plaintext: Vec<u8> = Vec::with_capacity(ciphertext_len);
    let split_ciphertext = split_blocks(ciphertext, BLOCK_SIZE);
    let mut prev_block_ciphertxt = iv;
    for i in 0..split_ciphertext.len(){
        let current_block = decrypt_aes_128_ecb(
            &split_ciphertext[i],
            &key,
        );
        let plaintext_block = xor(&current_block, &prev_block_ciphertxt);
        plaintext.extend(plaintext_block);
        prev_block_ciphertxt = split_ciphertext[i].to_vec();
    }
    plaintext.truncate(ciphertext_len);
    String::from_utf8(plaintext).unwrap()
}

fn main() {
    let base64 = read_to_string("data/ciphertext.txt")
        .expect("Something went wrong reading the file");
    let ciphertext = decode(base64)
        .expect("Invalid base64 input");
    let key = b"YELLOW SUBMARINE";
    let iv = vec![0; BLOCK_SIZE];
    let plaintext = decrypt_aes_128_cbc(ciphertext, iv, key);
    println!("{}", plaintext);
}
