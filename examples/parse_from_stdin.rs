use fluent_uri::UriRef;
use std::io;

fn main() {
    for line in io::stdin().lines() {
        let line = line.expect("failed to read line");
        match UriRef::parse(line) {
            Ok(r) => println!("{r:#?}"),
            Err(e) => println!("Error: {e}"),
        };
    }
}
