use hex::encode;

fn vigenere(plaintext: &str, key: &str) -> String {
    let p_bytes = plaintext.as_bytes();
    let n = p_bytes.len();
    let k_bytes = key.as_bytes();
    let mut xor: Vec<u8> = Vec::with_capacity(n);
    for i in 0..n {
        let key_index = i % 3;
        xor.push(p_bytes[i] ^ k_bytes[key_index]);
    }
    encode(xor)
}

fn main() {
    let plaintext = "Burning 'em, if you ain't quick and nimble
I go crazy when I hear a cymbal";
    let key = "ICE";
    let ciphertext = vigenere(plaintext, key);
    assert_eq!(ciphertext, "0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765272a282b2f20430a652e2c652a3124333a653e2b2027630c692b20283165286326302e27282f");
    println!("plaintext: {}", plaintext);
    println!("ciphertext: {}", ciphertext);
}
