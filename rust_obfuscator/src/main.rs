use clap::Parser;
use crossterm::{
    cursor,
    terminal::{self, ClearType},
    ExecutableCommand,
};
use goblin::{Object, pe::{PE, section_table::SectionTable}};
use log::{error, info, warn};
use rand::{Rng, SeedableRng, distributions::Alphanumeric};
use rand::rngs::StdRng;
use regex::Regex;
use rsa::{traits::PublicKeyParts, RsaPrivateKey, RsaPublicKey, pkcs8::{EncodePublicKey, LineEnding}};
use rsa::traits::PaddingScheme;
use aes::{Aes256, cipher::{BlockEncrypt, KeyInit, generic_array::GenericArray}};
use sha2::{Sha256, Digest};
use std::fs::{self, File};
use std::io::{self, Write, Read, Seek, SeekFrom, BufReader, BufWriter};
use std::path::{Path, PathBuf};
use std::process::{Command, exit};
use std::sync::{Arc, Mutex};
use std::thread;
use walkdir::WalkDir;
use zip::write::{FileOptions, ZipWriter};
use std::time::{SystemTime, UNIX_EPOCH, Duration};
use rand::rngs::ThreadRng;

#[derive(Parser, Debug)]
#[clap(name = "Code Metamorphic Engine", version = "2.0")]
struct Cli {
    #[clap(short, long, default_value = "info")]
    log_level: String,

    #[clap(short = 'i', long, value_name = "INPUT", help = "Input file/directory to process")]
    input: PathBuf,

    #[clap(short = 'o', long, value_name = "OUTPUT", help = "Output directory")]
    output: Option<PathBuf>,

    #[clap(short = 'p', long, value_name = "PACK_NAME", help = "Pack processed files into archive")]
    pack: Option<String>,

    #[clap(short = 't', long, help = "Number of threads for parallel processing")]
    threads: Option<usize>,

    #[clap(short = 'e', long, help = "Encrypt output files")]
    encrypt: bool,

    #[clap(short = 'b', long, help = "Create backup before processing")]
    backup: bool,
}

fn init_logger(log_level: &str) {
    env_logger::Builder::from_default_env()
        .parse_filters(log_level)
        .format_timestamp_millis()
        .init();
}

fn create_backup(path: &Path) -> io::Result<PathBuf> {
    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let backup_path = path.with_extension(format!("backup_{}", timestamp));
    
    if path.is_dir() {
        let mut options = fs_extra::dir::CopyOptions::new();
        options.copy_inside = true;
        fs_extra::dir::copy(path, &backup_path, &options)
            .map_err(|e| io::Error::new(io::ErrorKind::Other, e))?;
    } else {
        fs::copy(path, &backup_path)?;
    }
    
    info!("Created backup at {:?}", backup_path);
    Ok(backup_path)
}

fn mutate_pe_file(data: &[u8], rng: &mut StdRng) -> Vec<u8> {
    let mut mutated = data.to_vec();
    
    if let Ok(Object::PE(pe)) = Object::parse(&data) {
        // Mutate code sections
        for section in pe.sections {
            if section.characteristics & 0x20 != 0 { // Check if executable
                let start = section.pointer_to_raw_data as usize;
                let size = section.size_of_raw_data as usize;
                
                // Enhanced mutations
                for i in start..start+size {
                    if i < mutated.len() {
                        match rng.gen_range(0..10) {
                            0..=2 => mutated[i] = 0x90, // NOP
                            3 => if i+1 < mutated.len() { mutated.swap(i, i+1) }, // Swap
                            4 => mutated[i] = rng.gen(), // Random byte
                            5 => if i+3 < mutated.len() { // Jump instruction
                                mutated[i] = 0xE9;
                                let offset = rng.gen::<u32>() % (size as u32);
                                mutated[i+1..i+4].copy_from_slice(&offset.to_le_bytes()[..3]);
                            },
                            _ => {} // No mutation
                        }
                    }
                }
            }
        }
    }
    
    mutated
}

fn obfuscate_rust_code(source: &str) -> String {
    let chars: Arc<Vec<char>> = Arc::new(
        "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ_"
            .chars()
            .collect()
    );

    // Create a struct to hold the RNG and generate names
    struct NameGenerator {
        rng: ThreadRng,
        chars: Arc<Vec<char>>,
    }

    impl NameGenerator {
        fn generate(&mut self, len: usize) -> String {
            (0..len)
                .map(|_| self.chars[self.rng.gen_range(0..self.chars.len())])
                .collect()
        }
    }

    let mut name_gen = NameGenerator {
        rng: rand::thread_rng(),
        chars: chars.clone(),
    };

    // Enhanced regex patterns
    let patterns = [
        (r"\bfn (\w+)", "fn"),
        (r"\blet (\w+)", "let"),
        (r"\bstruct (\w+)", "struct"),
        (r"\benum (\w+)", "enum"),
        (r"\bimpl (\w+)", "impl"),
        (r"\bconst (\w+)", "const"),
        (r"\bstatic (\w+)", "static"),
        (r"\btrait (\w+)", "trait"),
        (r"\btype (\w+)", "type"),
        (r"\bmod (\w+)", "mod"),
        (r"\buse (\w+)", "use"),
        (r"\bcrate::(\w+)", "crate::"),
    ].iter()
        .map(|(pattern, prefix)| (Regex::new(pattern).unwrap(), prefix))
        .collect::<Vec<_>>();

    let mut obfuscated = source.to_string();
    let mut junk_rng = rand::thread_rng();

    // Apply obfuscations
    for (pattern, prefix) in patterns {
        obfuscated = pattern.replace_all(&obfuscated, |_caps: &regex::Captures| {
            format!("{}{}", prefix, name_gen.generate(junk_rng.gen_range(15..40)))
        }).to_string();
    }

    // Add complex junk code
    let mut lines: Vec<String> = obfuscated.lines().map(String::from).collect();
    let mut i = 0;
    while i < lines.len() {
        if junk_rng.gen_bool(0.25) {
            let junk = match junk_rng.gen_range(0..8) {
                0 => format!("    let _ = {{ let x = {}; x.wrapping_mul(x.wrapping_add(1)) }};", junk_rng.gen::<u32>()),
                1 => format!("    #[cfg(any())] const _: [u8; {}] = [0; {}];", junk_rng.gen::<u8>(), junk_rng.gen::<u8>()),
                2 => "    #[cfg(never)] unsafe fn _dummy() { std::ptr::null_mut::<u8>(); }".to_string(),
                3 => format!("    const _: Option<fn() -> u32> = Some(|| {});", junk_rng.gen::<u32>()),
                4 => format!("    #[allow(dead_code)] static _BYTES: &[u8] = &[{}];", 
                           (0..junk_rng.gen_range(3..8)).map(|_| junk_rng.gen::<u8>().to_string()).collect::<Vec<_>>().join(",")),
                5 => "    #[cfg(any())] type _T = Box<dyn Fn() -> bool>;".to_string(),
                6 => format!("    if false {{ panic!(\"{}\"); }}", name_gen.generate(12)),
                _ => format!("    let _ = [{}];", (0..junk_rng.gen_range(2..5))
                           .map(|_| format!("\"{}\"", name_gen.generate(8)))
                           .collect::<Vec<_>>()
                           .join(", "))
            };
            lines.insert(i, junk);
        }
        
        // Add random attributes and comments
        if junk_rng.gen_bool(0.15) {
            lines.insert(i, format!("    #[cfg(not(any()))] // {}", name_gen.generate(20)));
        }
        
        // Add random whitespace
        if junk_rng.gen_bool(0.3) {
            lines[i] = format!("{}{}", " ".repeat(junk_rng.gen_range(0..12)), lines[i]);
        }
        
        i += 1;
    }

    lines.join("\n")
}

fn process_directory(path: &Path, output: Option<&Path>, threads: Option<usize>, encrypt: bool) -> io::Result<Vec<PathBuf>> {
    let processed_files = Arc::new(Mutex::new(Vec::new()));
    let entries: Vec<_> = WalkDir::new(path)
        .into_iter()
        .filter_map(Result::ok)
        .filter(|e| e.file_type().is_file())
        .collect();

    let thread_count = threads.unwrap_or_else(|| num_cpus::get());
    let chunk_size = (entries.len() + thread_count - 1) / thread_count;
    
    let mut handles = vec![];
    
    for chunk in entries.chunks(chunk_size) {
        let chunk = chunk.to_vec();
        let processed_files = Arc::clone(&processed_files);
        let path = path.to_path_buf();
        let output = output.map(|p| p.to_path_buf());
        
        let handle = thread::spawn(move || {
            let mut rng = StdRng::from_entropy();
            
            for entry in chunk {
                let file_path = entry.path();
                
                let output_path = match &output {
                    Some(out_dir) => {
                        let rel_path = file_path.strip_prefix(&path).unwrap();
                        let out_path = out_dir.join(rel_path);
                        fs::create_dir_all(out_path.parent().unwrap())?;
                        out_path
                    },
                    None => file_path.to_path_buf()
                };

                let mut content = fs::read(file_path)?;
                
                if file_path.extension().map_or(false, |ext| ext == "rs") {
                    info!("Obfuscating Rust file: {:?}", file_path);
                    let source = String::from_utf8_lossy(&content);
                    let obfuscated = obfuscate_rust_code(&source);
                    content = obfuscated.into_bytes();
                } else if file_path.extension().map_or(false, |ext| ext == "exe") {
                    info!("Mutating PE file: {:?}", file_path);
                    content = mutate_pe_file(&content, &mut rng);
                }

                if encrypt {
                    // Create a new RNG for encryption to avoid ownership issues
                    let mut enc_rng = StdRng::from_entropy();
                    let key = enc_rng.sample_iter(&Alphanumeric)
                        .take(32)
                        .collect::<Vec<u8>>();
                    let _cipher = Aes256::new(GenericArray::from_slice(&key));
                    // Implement encryption here
                }

                fs::write(&output_path, content)?;
                processed_files.lock().unwrap().push(output_path);
            }
            Ok::<_, io::Error>(())
        });
        
        handles.push(handle);
    }

    for handle in handles {
        handle.join().unwrap()?;
    }

    Ok(Arc::try_unwrap(processed_files).unwrap().into_inner().unwrap())
}

fn pack_files(files: &[PathBuf], pack_name: &str) -> io::Result<()> {
    let file = BufWriter::new(File::create(pack_name)?);
    let mut zip = ZipWriter::new(file);
    let options = FileOptions::default()
        .compression_method(zip::CompressionMethod::Deflated)
        .unix_permissions(0o644) as FileOptions<'_, ()>;

    let start = SystemTime::now();
    let total_files = files.len();
    let mut processed = 0;

    for file_path in files {
        let name = file_path.file_name().unwrap();
        zip.start_file(name.to_string_lossy(), options)?;
        
        let mut content = Vec::new();
        let mut file = BufReader::new(File::open(file_path)?);
        file.read_to_end(&mut content)?;
        
        zip.write_all(&content)?;
        
        processed += 1;
        if processed % 10 == 0 || processed == total_files {
            info!("Packed {}/{} files...", processed, total_files);
        }
    }

    zip.finish()?;
    let duration = start.elapsed().unwrap();
    info!("Packing completed in {:.2}s", duration.as_secs_f32());
    Ok(())
}

fn draw_ui(files: &[String]) -> io::Result<()> {
    let mut stdout = io::stdout();
    stdout.execute(terminal::Clear(ClearType::All))?;
    stdout.execute(cursor::MoveTo(0, 0))?;

    writeln!(stdout, "Code Metamorphic Engine v2.0")?;
    writeln!(stdout, "==========================")?;
    writeln!(stdout, "\nProcessed {} files:", files.len())?;

    for (i, file) in files.iter().enumerate() {
        writeln!(stdout, "{:3}. {}", i + 1, file)?;
    }

    writeln!(stdout, "\nPress Ctrl+C to exit...")?;
    stdout.flush()?;
    Ok(())
}

fn main() -> io::Result<()> {
    let cli = Cli::parse();
    init_logger(&cli.log_level);

    info!("Starting Code Metamorphic Engine v2.0");
    
    if cli.backup {
        create_backup(&cli.input)?;
    }

    terminal::enable_raw_mode()?;
    
    let start = SystemTime::now();
    
    let processed_files = process_directory(
        &cli.input, 
        cli.output.as_deref(),
        cli.threads,
        cli.encrypt
    )?;
    
    let processed_file_names: Vec<_> = processed_files
        .iter()
        .map(|p| p.display().to_string())
        .collect();

    if let Some(pack_name) = cli.pack {
        pack_files(&processed_files, &pack_name)?;
    }

    let duration = start.elapsed().unwrap();
    info!("Processing completed in {:.2}s", duration.as_secs_f32());

    draw_ui(&processed_file_names)?;

    terminal::disable_raw_mode()?;
    Ok(())
}
