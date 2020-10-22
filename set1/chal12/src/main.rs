extern crate base64;
use base64::decode;
use openssl::symm::{Cipher, Mode, Crypter};
use std::collections::HashSet;
use std::hash::Hash;

const BLOCK_SIZE: usize = 16;
const KEY: &[u8] = &[0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,];
const PAD_STRING: &str = "Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkgaGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBqdXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUgYnkK";

fn pkcs7(message: &[u8], block_size: usize) -> Vec<u8> {
    let mut message = message.to_vec();
    let mut padding_len = block_size - (message.len() % block_size);
    if padding_len == 0 { padding_len = block_size};
    let pad = vec![padding_len as u8; padding_len as usize];
    message.extend(pad.iter());
    message
}

fn encrypt_aes_128_ecb(
    plaintext: &[u8],
    key: &[u8],
) -> Vec<u8> {
    let mut encrypter = Crypter::new(
        Cipher::aes_128_ecb(),
        Mode::Encrypt,
        key,
        None).unwrap();
    encrypter.pad(false);
    let data_len = plaintext.len();
    let mut ciphertext = vec![0; data_len + BLOCK_SIZE];
    let mut count = encrypter
        .update(&plaintext[..data_len], &mut ciphertext)
        .unwrap();
    count += encrypter
        .finalize(&mut ciphertext[count..])
        .unwrap();
    ciphertext.truncate(count);
    ciphertext
}


fn encryption_oracle_ecb(mut mes: Vec<u8>, key: &[u8]) -> Vec<u8> {
    let mut decoded_pad = decode(&PAD_STRING).unwrap();
    mes.append(&mut decoded_pad);
    mes = pkcs7(&mes, BLOCK_SIZE);
    return encrypt_aes_128_ecb(&mes, &key);
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
    match !has_unique_elements(blocks) {
        false => Ok(false),
        true => Ok(true),
    }
}


fn detect_blocksize() -> usize {
    let mut blocksize = 0_usize;
    for bs in 2..100 {
        let mut mes = vec![42; bs * 2];
        mes.push(3);
        let ciphertext = encryption_oracle_ecb(mes, &KEY);
        match repeated_blocks(&ciphertext, bs) {
            Ok(true) => {
                blocksize = bs;
                break
            },
            _ => (),
        }
    }
    blocksize
}

#[test]
fn test_detect_blocksize() {
    let bs = detect_blocksize();
    assert_eq!(bs, 16);
}

fn main() {
    let blocksize = detect_blocksize();
    println!("Blocksize is {}", blocksize);
}
