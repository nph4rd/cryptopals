use openssl::symm::{Cipher, Crypter, Mode};
use std::collections::HashMap;
use std::error::Error;
use url::{ParseError, Url};

const KEY: &[u8] = &[0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
const BLOCK_SIZE: usize = 16;

// Parse parameters from URL
fn parse(parameters: &str) -> Result<HashMap<String, String>, ParseError> {
    let mut url: String = "https://base.com/?".to_owned();
    url.push_str(parameters);
    let parsed_url = Url::parse(&url[..])?;
    let output_object: HashMap<String, String> = parsed_url.query_pairs().into_owned().collect();
    Ok(output_object)
}

/// Create profile for a given email address
fn profile_for(email_address: &str) -> String {
    let email_address = &email_address.replace("&", "");
    let email_address = &email_address.replace("=", "");
    let mut result: String = "email=".to_owned();
    result += email_address;
    result += "&uid=10&role=user";
    result
}

/// Ecnrypt a byte slice with AES-128 in ECB mode
fn encrypt_aes_128_ecb(plaintext: &[u8], key: &[u8]) -> Vec<u8> {
    let mut encrypter = Crypter::new(Cipher::aes_128_ecb(), Mode::Encrypt, key, None).unwrap();
    let data_len = plaintext.len();
    let mut ciphertext = vec![0; data_len + BLOCK_SIZE];
    let mut count = encrypter
        .update(&plaintext[..data_len], &mut ciphertext)
        .unwrap();
    count += encrypter.finalize(&mut ciphertext[count..]).unwrap();
    ciphertext.truncate(count);
    ciphertext
}

/// Decrypt a byte vec with AES-128 in ECB mode
fn decrypt_aes_128_ecb(ciphertext: &[u8], key: &[u8]) -> Vec<u8> {
    let mut decrypter = Crypter::new(Cipher::aes_128_ecb(), Mode::Decrypt, key, None).unwrap();
    let data_len = ciphertext.len();
    let mut plaintext = vec![0; data_len + BLOCK_SIZE];
    let mut count = decrypter
        .update(&ciphertext[..data_len], &mut plaintext)
        .unwrap();
    count += decrypter.finalize(&mut plaintext[count..]).unwrap();
    plaintext.truncate(count);
    plaintext
}

fn encrypt_profile(email_address: &str, key: &[u8]) -> Vec<u8> {
    let profile = profile_for(email_address);
    encrypt_aes_128_ecb(profile.as_bytes(), key)
}

fn decrypt_and_parse_profile(
    ciphertext: &[u8],
    key: &[u8],
) -> Result<HashMap<String, String>, Box<dyn Error>> {
    let plaintext = decrypt_aes_128_ecb(ciphertext, key);
    let plaintext = String::from_utf8(plaintext)?;
    let profile = parse(&plaintext)?;
    Ok(profile)
}

#[test]
fn test_url_parsing() -> Result<(), ParseError> {
    let test_object = parse("foo=bar&baz=qux&zap=zazzle")?;
    assert_eq!(test_object.get("foo").unwrap().to_owned(), "bar".to_owned());
    assert_eq!(test_object.get("baz").unwrap().to_owned(), "qux".to_owned());
    assert_eq!(
        test_object.get("zap").unwrap().to_owned(),
        "zazzle".to_owned()
    );
    Ok(())
}

#[test]
fn test_profile_for() {
    let test_object = profile_for("foo@bar.com");
    assert_eq!(test_object, "email=foo@bar.com&uid=10&role=user".to_owned());
    let test_object = profile_for("foo@bar.com&role=admin");
    assert_eq!(
        test_object,
        "email=foo@bar.comroleadmin&uid=10&role=user".to_owned()
    );
}

#[test]
fn test_encrypt_decrypt_profile() -> Result<(), Box<dyn Error>> {
    let test_object = decrypt_and_parse_profile(&encrypt_profile("foo@bar.com", &KEY), &KEY)?;
    assert_eq!(
        test_object.get("email").unwrap().to_owned(),
        "foo@bar.com".to_owned()
    );
    assert_eq!(test_object.get("uid").unwrap().to_owned(), "10".to_owned());
    assert_eq!(
        test_object.get("role").unwrap().to_owned(),
        "user".to_owned()
    );
    Ok(())
}

fn main() {
    println!("Hello, world!");
}
