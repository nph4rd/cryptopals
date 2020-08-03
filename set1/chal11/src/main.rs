extern crate openssl;
use rand::Rng;
use openssl::symm::{Cipher, Mode, Crypter};

const BLOCK_SIZE: usize = 16;

#[derive(Debug, PartialEq)]
#[allow(dead_code)]
enum CipherMode {
    ECB,
    CBC,
}

fn xor(x: &[u8], y: &[u8]) -> Vec<u8> {
    assert_eq!(x.len(), y.len());
    let mut xor: Vec<u8> = Vec::with_capacity(x.len());
    for i in 0..x.len() {
        xor.push(x[i] ^ y[i])
    }
    xor
}

fn split_blocks<'a>(
    ciphertext: &'a [u8],
    blocksize: usize,
) -> Vec<&'a [u8]> {
    let num_blocks = ciphertext.len() / blocksize;
    let mut result: Vec<&[u8]> = Vec::with_capacity(num_blocks);
    for i in 0..num_blocks {
        result.push(&ciphertext[(blocksize * i)..(blocksize * (i + 1))]);
    }
    result
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

fn encrypt_aes_128_cbc(
    plaintext: &[u8],
    iv: &[u8],
    key: &[u8],
) -> Vec<u8> {
    let plaintext_len = plaintext.len();
    let mut ciphertext: Vec<u8> = Vec::with_capacity(plaintext_len);
    let split_plaintext = split_blocks(&plaintext, BLOCK_SIZE);
    let mut prev_block_plaintxt = iv;
    for i in 0..split_plaintext.len(){
        let cipher_input = xor(&split_plaintext[i], &prev_block_plaintxt);
        let current_block = encrypt_aes_128_ecb(
            &cipher_input[..],
            &key,
        );
        ciphertext.extend(current_block);
        prev_block_plaintxt = &ciphertext[..BLOCK_SIZE];
    }
    ciphertext
}

fn encryption_oracle(mes: &[u8], mode: CipherMode) -> Vec<u8> {
    let key = rand::thread_rng().gen::<[u8; BLOCK_SIZE]>();
    match mode {
        CipherMode::ECB => {
            return encrypt_aes_128_ecb(&mes, &key)
        },
        CipherMode::CBC => {
        let iv = rand::thread_rng().gen::<[u8; BLOCK_SIZE]>();
        return encrypt_aes_128_cbc(&mes, &iv, &key);
        }
    }
}

fn main() {
    let e = encryption_oracle(b"YELLOW SUBMARINEYELLOW SUBMARINE", CipherMode::ECB);
    println!("{:?}", e);
}
