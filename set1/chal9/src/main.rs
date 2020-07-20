fn pkcs7(message: &[u8], block_size: usize) -> Vec<u8> {
    let mut message = message.to_vec();
    let mut pading_len = block_size - (message.len() % block_size);
    if pading_len == 0 { pading_len = block_size};
    let pad = vec![pading_len as u8; pading_len as usize];
    message.extend(pad.iter());
    message
}

fn main() {
    let message = b"YELLOW SUBMARINE";
    let padded_message = pkcs7(message, 20);
    assert_eq!(padded_message.as_slice(), b"YELLOW SUBMARINE\x04\x04\x04\x04");
}
