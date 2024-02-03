use std::io;

use fluent_uri::Uri;

fn main() {
    for line in io::stdin().lines() {
        let line = line.expect("failed to read line");
        match Uri::parse(line) {
            Ok(uri) => println!("{uri:#?}"),
            Err(e) => println!("Error: {e}"),
        };
    }
}
