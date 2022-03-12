use std::io;

use fluent_uri::UriRef;

fn main() {
    let mut buf = String::new();
    loop {
        buf.clear();
        io::stdin()
            .read_line(&mut buf)
            .expect("failed to read line");
        if buf.ends_with('\n') {
            buf.pop();
            if buf.ends_with('\r') {
                buf.pop();
            }
        }

        match UriRef::parse(&buf) {
            Ok(u) => println!("{u:#?}"),
            Err(e) => println!("Error: {e}"),
        };
    }
}
