pub const MAGIC_NUMBER_256: &[u8] = b"AES256ENC"; //*
pub const MAGIC_NUMBER_128: &[u8] = b"AES128ENC"; //*  Unique identifier for encrypted files
pub const MAGIC_NUMBER_192: &[u8] = b"AES192ENC"; //*

use aes::cipher::{generic_array::GenericArray, BlockDecrypt, BlockEncrypt};
use std::{error::Error, fs, io, iter, path::Path};
fn check_if_encrypted(data: &[u8]) -> bool {
    data.starts_with(MAGIC_NUMBER_256)
        || data.starts_with(MAGIC_NUMBER_192)
        || data.starts_with(MAGIC_NUMBER_128)
}
fn check_encrypt_format(data: &[u8]) -> Option<&str> {
    if data.starts_with(MAGIC_NUMBER_256) {
        Some("AES-256")
    } else if data.starts_with(MAGIC_NUMBER_192) {
        Some("AES-192")
    } else if data.starts_with(MAGIC_NUMBER_128) {
        Some("AES-128")
    } else {
        None
    }
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
) -> Result<(), Box<dyn Error>> {
    let path = Path::new(file_path);
    let mut data = fs::read(path).map_err(|e| format!("Failed to read file: {}", e))?;

    // Check if the file is already encrypted
    if check_if_encrypted(&data) {
        if let Some(format) = check_encrypt_format(&data) {
            return Err(format!("File is already encrypted with {}", format).into());
        }
    }

    // Padding (PKCS7-like manual padding for block size 16)
    let padding = 16 - (data.len() % 16);
    data.extend(iter::repeat(padding as u8).take(padding));

    // Encrypt each 16-byte chunk
    for chunk in data.chunks_mut(16) {
        cipher.encrypt_block(GenericArray::from_mut_slice(chunk));
    }

    // Prepend magic number to indicate encryption
    let mut encrypted_data = magic_number.to_vec();
    encrypted_data.extend_from_slice(&data);

    // Write the encrypted content back to the file
    fs::write(path, &encrypted_data)
        .map_err(|e| format!("Failed to write encrypted file: {}", e))?;

    Ok(())
}

// Generic decryption function
pub fn decrypt_file(
    file_path: &str,
    magic_number: &[u8],
    cipher: impl BlockDecrypt,
) -> Result<(), Box<dyn Error>> {
    let path = Path::new(file_path);
    let mut data = fs::read(path).map_err(|e| format!("Failed to read file: {}", e))?;

    // Check if the file is already encrypted
    if check_if_encrypted(&data) {
        if let Some(format) = check_encrypt_format(&data) {
            // Validate magic number
            if !data.starts_with(magic_number) {
                return Err("Invalid or unsupported encryption format".into());
            }
            return Err(format!("File encrypted with {}", format).into());
        }
    } else {
        return Err("File is not encrypted".into());
    }

    // Remove the magic number
    data.drain(0..magic_number.len());

    // Decrypt each 16-byte chunk
    for chunk in data.chunks_mut(16) {
        cipher.decrypt_block(GenericArray::from_mut_slice(chunk));
    }

    // Remove PKCS7 padding
    let padding_len = data.last().cloned().unwrap_or(0) as usize;
    if padding_len > 16 || padding_len == 0 {
        return Err("Invalid padding".into());
    }
    for i in 1..=padding_len {
        if data[data.len() - i] != padding_len as u8 {
            return Err("Invalid padding".into());
        }
    }
    data.truncate(data.len() - padding_len);

    // Write the decrypted content back to the file
    fs::write(path, &data).map_err(|e| format!("Failed to write decrypted file: {}", e))?;

    Ok(())
}
