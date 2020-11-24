extern crate base64;
extern crate openssl;
use base64::decode;
use openssl::symm::{Cipher, Crypter, Mode};
use std::fs::read_to_string;

const BLOCK_SIZE: usize = 16;

fn xor(x: &[u8], y: &[u8]) -> Vec<u8> {
    assert_eq!(x.len(), y.len());
    let mut xor: Vec<u8> = Vec::with_capacity(x.len());
    for i in 0..x.len() {
        xor.push(x[i] ^ y[i])
    }
    xor
}

fn decrypt_aes_128_ecb(ciphertext: &[u8], key: &[u8]) -> Vec<u8> {
    let mut decrypter = Crypter::new(Cipher::aes_128_ecb(), Mode::Decrypt, key, None).unwrap();
    decrypter.pad(false);
    let data_len = ciphertext.len();
    let mut plaintext = vec![0; data_len + BLOCK_SIZE];
    let mut count = decrypter
        .update(&ciphertext[..data_len], &mut plaintext)
        .unwrap();
    count += decrypter.finalize(&mut plaintext[count..]).unwrap();
    plaintext.truncate(count);
    plaintext
}

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

fn split_blocks<'a>(ciphertext: &'a [u8], blocksize: usize) -> Vec<&'a [u8]> {
    let num_blocks = ciphertext.len() / blocksize;
    let mut result: Vec<&[u8]> = Vec::with_capacity(num_blocks);
    for i in 0..num_blocks {
        result.push(&ciphertext[(blocksize * i)..(blocksize * (i + 1))]);
    }
    result
}

fn decrypt_aes_128_cbc(ciphertext: &[u8], iv: &[u8], key: &[u8]) -> Vec<u8> {
    let ciphertext_len = ciphertext.len();
    let mut plaintext: Vec<u8> = Vec::with_capacity(ciphertext_len);
    let split_ciphertext = split_blocks(&ciphertext, BLOCK_SIZE);
    let mut prev_block_ciphertxt = iv;
    for i in 0..split_ciphertext.len() {
        let current_block = decrypt_aes_128_ecb(&split_ciphertext[i], &key);
        let plaintext_block = xor(&current_block, &prev_block_ciphertxt);
        plaintext.extend(plaintext_block);
        prev_block_ciphertxt = split_ciphertext[i];
    }
    plaintext.truncate(ciphertext_len);
    plaintext
}

#[allow(dead_code)]
fn encrypt_aes_128_cbc(plaintext: &[u8], iv: &[u8], key: &[u8]) -> Vec<u8> {
    let plaintext_len = plaintext.len();
    let mut ciphertext: Vec<u8> = Vec::with_capacity(plaintext_len);
    let split_plaintext = split_blocks(&plaintext, BLOCK_SIZE);
    let mut prev_block_plaintxt = iv;
    for i in 0..split_plaintext.len() {
        let cipher_input = xor(&split_plaintext[i], &prev_block_plaintxt);
        let current_block = encrypt_aes_128_ecb(&cipher_input[..], &key);
        ciphertext.extend(current_block);
        prev_block_plaintxt = &ciphertext[(BLOCK_SIZE * i)..(BLOCK_SIZE * (i + 1))];
    }
    ciphertext
}

fn main() {
    let base64 =
        read_to_string("data/ciphertext.txt").expect("Something went wrong reading the file");
    let ciphertext = decode(base64).expect("Invalid base64 input");
    let key = b"YELLOW SUBMARINE";
    let iv = vec![0; BLOCK_SIZE];
    let plaintext_vec = decrypt_aes_128_cbc(&ciphertext[..], &iv[..], key);
    let plaintext = String::from_utf8(plaintext_vec).unwrap();
    println!("{}", plaintext);
}

#[test]
fn test_cbc_encrypt_decrypt() {
    let msg = b"YELLOW SUBMARINEYELLOW SUBMARINE";
    let key = b"YELLOW SUBMARINE";
    let iv = vec![0; BLOCK_SIZE];
    assert_eq!(
        msg,
        decrypt_aes_128_cbc(
            encrypt_aes_128_cbc(msg, &iv[..], key).as_slice(),
            &iv[..],
            key,
        )
        .as_slice()
    );
    assert!(true);
}
