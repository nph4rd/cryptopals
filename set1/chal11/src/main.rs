extern crate openssl;
use rand::Rng;
use openssl::symm::{Cipher, Mode, Crypter};
use std::collections::HashSet;
use std::hash::Hash;

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

fn append_random_bytes(mes: Vec<u8>) -> Vec<u8> {
    let mut rng = rand::thread_rng();
    let mut result: Vec<u8> = Vec::new();
    let prefix_len = rng.gen_range(1, 6);
    let suffix_len = rng.gen_range(1, 6);
    for _ in 0..prefix_len {
        result.push(rng.gen());
    }
    result.extend(mes);
    for _ in 0..suffix_len {
        result.push(rng.gen());
    }
    result
}

fn pkcs7(message: &[u8], block_size: usize) -> Vec<u8> {
    let mut message = message.to_vec();
    let mut padding_len = block_size - (message.len() % block_size);
    if padding_len == 0 { padding_len = block_size};
    let pad = vec![padding_len as u8; padding_len as usize];
    message.extend(pad.iter());
    message
}

fn encryption_oracle(mut mes: Vec<u8>, mode: CipherMode) -> Vec<u8> {
    mes = append_random_bytes(mes);
    mes = pkcs7(&mes, BLOCK_SIZE);
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
    let mes = b"YELLOW SUBMARINEYELLOW SUBMARINE".to_vec();
    let prob = rand::thread_rng().gen::<f64>();
    let mut mode = CipherMode::CBC;
    if prob < 0.5 {
        mode = CipherMode::ECB;
    }
    println!("{:?}", mode);
    let e = encryption_oracle(mes, mode);
    if repeated_blocks(&e, BLOCK_SIZE).unwrap() {
        println!("{:?}", CipherMode::ECB);
    } else {
        println!("{:?}", CipherMode::CBC);
    }
}
