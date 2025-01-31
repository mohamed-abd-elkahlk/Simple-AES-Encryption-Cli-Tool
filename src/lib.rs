pub const MAGIC_NUMBER_256: &[u8] = b"AES256ENC"; //*
pub const MAGIC_NUMBER_128: &[u8] = b"AES128ENC"; //*  Unique identifier for encrypted files
pub const MAGIC_NUMBER_192: &[u8] = b"AES192ENC"; //*

use aes::cipher::{generic_array::GenericArray, BlockDecrypt, BlockEncrypt};
use colored::Colorize;
use rayon::prelude::*;
use serde::{Deserialize, Serialize};
use spinners::{Spinner, Spinners};
use std::{
    error::Error,
    fs::{self, File},
    io::{self, BufWriter, Write},
    path::{Path, PathBuf},
    sync::Arc,
    usize,
};
#[derive(Serialize, Deserialize)]
pub struct EncryptedFilesPath {
    pub path: Vec<PathBuf>,
}

pub fn check_if_encrypted(data: &[u8]) -> bool {
    data.starts_with(MAGIC_NUMBER_256)
        || data.starts_with(MAGIC_NUMBER_192)
        || data.starts_with(MAGIC_NUMBER_128)
}

#[macro_export]
macro_rules! generate_key {
    ($size:expr) => {{
        use rand::Rng;
        let result: Result<Vec<u8>, Box<dyn std::error::Error>> = match $size {
            128 => Ok(rand::thread_rng().gen::<[u8; 16]>().to_vec()),
            192 => Ok(rand::thread_rng().gen::<[u8; 24]>().to_vec()),
            256 => Ok(rand::thread_rng().gen::<[u8; 32]>().to_vec()),
            _ => Err("Invalid key size. Must be 128, 192, or 256".into()),
        };
        result
    }};
}

pub fn save_key_to_file(key: &[u8]) -> Result<(), io::Error> {
    let key_type = match key.len() {
        32 => "256",
        24 => "192",
        16 => "128",
        _ => {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "Invalid key length",
            ))
        }
    };
    let filename = format!("AES{}.key", key_type);
    fs::write(&filename, hex::encode(key))
}

pub fn read_key_from_file(size: usize) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let filename = match size {
        256 => "AES256.key",
        192 => "AES192.key",
        128 => "AES128.key",
        _ => {
            return Err(format!("Unsupported key size: {}. Must be 128, 192, or 256", size).into())
        }
    };

    let hex_key = fs::read_to_string(filename)?;
    Ok(hex::decode(hex_key)?)
}

use memmap2::MmapMut;

// Function to encrypt a single file
pub fn encrypt_file(
    file_path: &Path,
    magic_number: &[u8],
    cipher: &impl BlockEncrypt,
) -> Result<(), Box<dyn Error + Send + Sync>> {
    // Open file in read/write mode
    let file = File::options().read(true).write(true).open(file_path)?;

    // Step 1: Get file size and calculate padding
    let file_size = file.metadata()?.len() as usize;
    let padding = 16 - (file_size % 16);
    let new_size = file_size + padding;

    // Step 2: Resize file to accommodate padding
    file.set_len(new_size as u64)?;

    // Step 3: Memory-map the file for fast access
    let mut mmap = unsafe { MmapMut::map_mut(&file)? };

    // Step 4: Apply PKCS7 padding directly into memory
    for i in 0..padding {
        mmap[file_size + i] = padding as u8;
    }

    // Step 5: Encrypt sequentially
    for chunk in mmap.chunks_mut(16) {
        cipher.encrypt_block(GenericArray::from_mut_slice(chunk));
    }

    // Step 6: Write encrypted content to a new file
    let temp_file_path = file_path.with_extension("enc.tmp");
    let temp_file = File::create(&temp_file_path)?;
    let mut writer = BufWriter::new(temp_file);

    writer.write_all(magic_number)?;
    writer.write_all(&mmap)?;
    writer.flush()?;

    // Step 7: Replace the original file
    fs::rename(temp_file_path, file_path)?;

    Ok(())
}

// Function to encrypt all files in a directory
pub fn encrypt_directory(
    root_path: PathBuf,
    magic_number: &[u8],
    cipher: Arc<impl BlockEncrypt + Send + Sync>,
) -> Result<(), Box<dyn Error + Send + Sync>> {
    let files = files_dir_explorer(root_path.clone())?;
    let mut sp = Spinner::new(Spinners::Line, "Waiting for decryption...".into());

    if files.is_empty() {
        return Err("No files found".into());
    }

    let encrypted_files: Vec<PathBuf> = files
        .par_iter()
        .filter_map(|file| match encrypt_file(file, magic_number, &*cipher) {
            Ok(_) => Some(file.clone()),
            Err(e) => {
                eprintln!("Failed to encrypt {}: {}", file.display(), e);
                None
            }
        })
        .collect();

    // Save encrypted file paths to JSON
    let json_file_path = root_path.join("encrypted_files.json");
    let json_file = File::create(&json_file_path)?;
    serde_json::to_writer_pretty(
        json_file,
        &EncryptedFilesPath {
            path: encrypted_files,
        },
    )?;
    sp.stop_with_newline();
    println!("Encrypted file paths saved to {}", json_file_path.display());
    Ok(())
}
pub fn decrypt_file(
    file_path: &Path,
    magic_number: &[u8],
    cipher: impl BlockDecrypt,
) -> Result<(), Box<dyn Error + Send + Sync>> {
    let path = file_path;
    let mut data = fs::read(path).map_err(|e| format!("Failed to read file: {}", e))?;

    if !data.starts_with(magic_number) {
        return Err("File is not encrypted or uses an unsupported format".into());
    }
    data.drain(0..magic_number.len());

    for chunk in data.chunks_mut(16) {
        cipher.decrypt_block(GenericArray::from_mut_slice(chunk));
    }

    if let Some(&padding_len) = data.last() {
        if padding_len == 0
            || padding_len > 16
            || !data[data.len() - padding_len as usize..]
                .iter()
                .all(|&b| b == padding_len)
        {
            return Err("Invalid padding".into());
        }
        data.truncate(data.len() - padding_len as usize);
    } else {
        return Err("File is too short to contain valid padding".into());
    }

    fs::write(path, &data).map_err(|e| format!("Failed to write decrypted file: {}", e))?;
    Ok(())
}

pub fn files_dir_explorer(
    root_path: PathBuf,
) -> Result<Vec<PathBuf>, Box<dyn Error + Send + Sync>> {
    let mut files = Vec::new();
    let mut dirs = vec![root_path];

    while let Some(dir) = dirs.pop() {
        let entries: Vec<_> = match fs::read_dir(&dir) {
            Ok(entries) => entries.filter_map(Result::ok).collect(),
            Err(_) => continue,
        };

        let (sub_dirs, file_paths): (Vec<_>, Vec<_>) = entries
            .into_par_iter()
            .partition(|entry| entry.path().is_dir());

        dirs.extend(sub_dirs.into_iter().map(|entry| entry.path()));
        files.extend(file_paths.into_iter().map(|entry| entry.path()));
    }

    Ok(files)
}
pub fn decrypt_directory(
    root_path: PathBuf,
    magic_number: &[u8],
    cipher: Arc<impl BlockDecrypt + Send + Sync>,
) -> Result<(), Box<dyn Error + Send + Sync>> {
    let json_file_path = root_path.join("encrypted_files.json");
    let mut sp = Spinner::new(Spinners::Line, "Waiting for decryption...".into());

    let encrypted_files = if json_file_path.exists() {
        // Read encrypted files from JSON
        let files: EncryptedFilesPath = serde_json::from_reader(File::open(&json_file_path)?)?;
        fs::remove_file(&json_file_path)?; // Remove JSON after reading
        files.path
    } else {
        // If JSON does not exist, scan directory
        files_dir_explorer(root_path)?
    };

    if encrypted_files.is_empty() {
        sp.stop_with_newline();
        return Err("No encrypted files found!".into());
    }

    // Decrypt each file in parallel
    encrypted_files
        .par_iter()
        .try_for_each(|file| decrypt_file(file, magic_number, &*cipher))?;

    sp.stop_with_newline();
    println!("{}", "All files decrypted successfully.".green().bold());
    Ok(())
}
