use std::fs::File;
use std::io::prelude::*;

fn hamming(str1: &str, str2: &str) -> Result<u64, String>{
    // Based on:
    // https://docs.rs/hamming/0.1.3/hamming/fn.distance.html
    let x = str1.as_bytes();
    let y = str2.as_bytes();
    if x.len() != y.len() {
        return Err(
            "String slices must be of same length"
            .to_string()
        );
    } else {
        let d = x
            .iter()
            .zip(y)
            .fold(
                0,
                |a, (b, c)| a + (*b ^ *c).
                count_ones() as u64
            );
        Ok(d)
    }

}

fn read_file(filepath: &str) -> String {
    let mut file = File::open(filepath)
        .unwrap();
    let mut contents = String::new();
    file.read_to_string(&mut contents)
        .unwrap();
    contents
}

fn main() {
    let _ciphertext = read_file("data/ciphertext.txt");
    let d = hamming("this is a test", "wokka wokka!!!")
        .unwrap();
    assert_eq!(d, 37_u64);
}
