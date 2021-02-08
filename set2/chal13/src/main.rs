use std::collections::HashMap;
use url::{ParseError, Url};

fn parse(parameters: &str) -> Result<HashMap<String, String>, ParseError> {
    let mut url: String = "https://base.com/?".to_owned();
    url.push_str(parameters);
    let parsed_url = Url::parse(&url[..])?;
    let output_object: HashMap<String, String> = parsed_url.query_pairs().into_owned().collect();
    Ok(output_object)
}

fn profile_for(email_address: &str) -> String {
    let email_address = &email_address.replace("&", "");
    let email_address = &email_address.replace("=", "");
    let mut result: String = "email=".to_owned();
    result += email_address;
    result += "&uid=10&role=user";
    result
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

fn main() {
    println!("Hello, world!");
}
