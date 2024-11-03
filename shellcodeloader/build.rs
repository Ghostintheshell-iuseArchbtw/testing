use std::env;
use std::fs;
use std::path::Path;

fn main() {
    // Get output directory from cargo
    let out_dir = env::var("OUT_DIR").unwrap();
    let dest_path = Path::new(&out_dir).join("shellcode.bin");

    // Create an empty shellcode file if it doesn't exist
    if !dest_path.exists() {
        fs::write(&dest_path, &[0u8; 0]).unwrap();
    }

    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rerun-if-changed=src/shellcode.bin");
}