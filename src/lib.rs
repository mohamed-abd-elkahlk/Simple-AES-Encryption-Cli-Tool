use std::{fs, io};

use aes::cipher::{generic_array::GenericArray, BlockDecrypt, BlockEncrypt, KeyInit};
use rand::RngCore;
pub const MAGIC_NUMBER: &[u8] = b"AES256ENC"; // Unique identifier for encrypted files

pub fn encrypt(file_path: &str, key: &[u8]) -> Result<(), Box<dyn std::error::Error>> {
    let mut data = fs::read(file_path)?;
    if data.starts_with(MAGIC_NUMBER) {
        return Err("File is already encrypted".into());
    }
    while data.len() % 16 != 0 {
        data.push(0);
    }

    let cipher = aes::Aes256::new(GenericArray::from_slice(&key));
    for chunk in data.chunks_mut(16) {
        cipher.encrypt_block(chunk.into());
    }
    // Prepend the magic number to the encrypted data
    let mut encrypted_data = MAGIC_NUMBER.to_vec();
    encrypted_data.extend_from_slice(&data);

    fs::write(file_path, &encrypted_data)?;
    Ok(())
}

pub fn decrypt(file_path: &str, key: &[u8]) -> Result<(), Box<dyn std::error::Error>> {
    let mut data = fs::read(file_path)?;
    // Check if the file starts with the magic number
    if data.starts_with(MAGIC_NUMBER) {
        // Remove the magic number
        data.drain(0..MAGIC_NUMBER.len());
        let cipher = aes::Aes256::new(GenericArray::from_slice(&key));

        for chunk in data.chunks_mut(16) {
            let mut block = GenericArray::clone_from_slice(chunk);
            cipher.decrypt_block(&mut block);
            chunk.copy_from_slice(&block);
        }
        while data.last() == Some(&0) {
            data.pop();
        }
        fs::write(file_path, &data)?;
        Ok(())
    } else {
        Err("File is not encrypted".into())
    }
}

pub fn generate_key() -> [u8; 32] {
    let mut key = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut key);
    key
}

pub fn save_key_to_file(key: &[u8]) -> Result<(), io::Error> {
    fs::write("aes.key", hex::encode(key))
}
pub fn read_key_from_file() -> String {
    if let Ok(key) = fs::read_to_string("aes.key") {
        key
    } else {
        panic!("Key file not found");
    }
}
