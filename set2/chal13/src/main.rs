use url::{Url, ParseError};
use std::collections::HashMap;

fn parse(parameters: &str) -> Result<HashMap<String, String>, ParseError> {
    let mut url: String = "https://base.com/?".to_owned();
    url.push_str(parameters);
    let parsed_url = Url::parse(&url[..])?;
    let output_object: HashMap<String, String> = parsed_url.query_pairs().into_owned().collect();
    Ok(output_object)

}

#[test]
fn test_url_parsing() -> Result<(), ParseError> {
    let test_object = parse("foo=bar&baz=qux&zap=zazzle")?;
    assert_eq!(test_object.get("foo").unwrap().to_owned(), "bar".to_owned());
    assert_eq!(test_object.get("baz").unwrap().to_owned(), "qux".to_owned());
    assert_eq!(test_object.get("zap").unwrap().to_owned(), "zazzle".to_owned());
    Ok(())
}

fn main() {
    println!("Hello, world!");
}
