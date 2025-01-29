pub const MAGIC_NUMBER_256: &[u8] = b"AES256ENC"; //*
pub const MAGIC_NUMBER_128: &[u8] = b"AES128ENC"; //*  Unique identifier for encrypted files
pub const MAGIC_NUMBER_192: &[u8] = b"AES192ENC"; //*

use aes::cipher::{generic_array::GenericArray, BlockDecrypt, BlockEncrypt};
use colored::Colorize;
use rayon::prelude::*;
use std::{
    error::Error,
    fs::{self, File},
    io::{self, Write},
    iter,
    path::{Path, PathBuf},
    usize,
};

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

pub fn encrypt_file(
    file_path: &str,
    magic_number: &[u8],
    cipher: impl BlockEncrypt,
) -> Result<(), Box<dyn std::error::Error>> {
    let path = Path::new(file_path);

    // Step 1: Read the original file content
    let mut data = fs::read(path).map_err(|e| format!("Failed to read file: {}", e))?;

    // Check if the file is already encrypted
    if check_if_encrypted(&data) {
        return Err("File is already encrypted".into());
    }

    // Step 2: Create a temporary file for encryption
    let temp_file_path = format!("{}.tmp", file_path);
    let mut temp_file = File::create(&temp_file_path)
        .map_err(|e| format!("Failed to create temporary file: {}", e))?;

    // Step 3: Add padding to the file content (PKCS7-like padding)
    let padding = 16 - (data.len() % 16);
    data.extend(iter::repeat(padding as u8).take(padding));

    // Encrypt each 16-byte chunk
    for chunk in data.chunks_mut(16) {
        cipher.encrypt_block(GenericArray::from_mut_slice(chunk));
    }

    // Step 4: Write the encrypted content (including the magic number) to the temporary file
    temp_file.write_all(magic_number)?;
    temp_file.write_all(&data)?;
    temp_file.flush()?;

    // Step 5: Replace the original file with the temporary file
    fs::rename(&temp_file_path, file_path)
        .map_err(|e| format!("Failed to replace original file with encrypted file: {}", e))?;

    // Step 6: Success message
    println!("{}", "File encrypted successfully.".red().bold());
    Ok(())
}

pub fn decrypt_file(
    file_path: &str,
    magic_number: &[u8],
    cipher: impl BlockDecrypt,
) -> Result<(), Box<dyn Error>> {
    let path = Path::new(file_path);
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
    println!("File decrypted successfully.");
    Ok(())
}

pub fn files_dir_explorer(root_path: PathBuf) -> Result<Vec<PathBuf>, Box<dyn Error>> {
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
