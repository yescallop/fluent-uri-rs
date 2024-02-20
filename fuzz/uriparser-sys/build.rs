use std::env;
use std::path::PathBuf;

fn main() {
    println!("cargo:rerun-if-changed=uriparser");

    let dst = cmake::Config::new("uriparser")
        .define("BUILD_SHARED_LIBS", "OFF")
        .define("URIPARSER_BUILD_DOCS", "OFF")
        .define("URIPARSER_BUILD_TESTS", "OFF")
        .define("URIPARSER_BUILD_TOOLS", "OFF")
        .define("CMAKE_C_COMPILER", "/usr/bin/clang")
        .cflag("-fsanitize=fuzzer-no-link,address")
        .build();

    println!("cargo:rustc-link-search=native={}/lib", dst.display());
    println!("cargo:rustc-link-lib=static=uriparser");

    let bindings = bindgen::Builder::default()
        .header("uriparser/include/uriparser/Uri.h")
        .parse_callbacks(Box::new(bindgen::CargoCallbacks::new()))
        .generate()
        .expect("Unable to generate bindings");

    let out_path = PathBuf::from(env::var("OUT_DIR").unwrap());
    bindings
        .write_to_file(out_path.join("bindings.rs"))
        .expect("Couldn't write bindings!");
}
