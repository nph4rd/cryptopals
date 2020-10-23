fn pkcs7(message: &[u8], block_size: usize) -> Vec<u8> {
    let mut message = message.to_vec();
    let mut padding_len = block_size - (message.len() % block_size);
    if padding_len == 0 { padding_len = block_size};
    let pad = vec![padding_len as u8; padding_len as usize];
    message.extend(pad.iter());
    message
}

fn main() {
    let message = b"YELLOW SUBMARINE";
    let padded_message = pkcs7(message, 20);
    println!("{}", String::from_utf8(padded_message).unwrap());
}

#[test]
fn test_padkcs7() {
    let message = b"YELLOW SUBMARINE";
    let padded_message = pkcs7(message, 20);
    assert_eq!(padded_message.as_slice(), b"YELLOW SUBMARINE\x04\x04\x04\x04");
}
