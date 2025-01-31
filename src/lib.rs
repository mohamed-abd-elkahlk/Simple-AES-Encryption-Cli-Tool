pub const MAGIC_NUMBER_256: &[u8] = b"AES256ENC";
pub const MAGIC_NUMBER_192: &[u8] = b"AES192ENC";
pub const MAGIC_NUMBER_128: &[u8] = b"AES128ENC";

use rayon::iter::{IntoParallelIterator, ParallelIterator};
use serde::{Deserialize, Serialize};
use std::{error::Error, fs, io, path::PathBuf};
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
// Struct to store encrypted file paths
#[derive(Serialize, Deserialize)]
pub struct EncryptedFilesPath {
    pub path: Vec<PathBuf>,
}

// List all files in a directory and its subdirectories
pub fn files_dir_explorer(
    root_path: &PathBuf,
) -> Result<Vec<PathBuf>, Box<dyn Error + Send + Sync>> {
    let mut files = Vec::new();
    let mut dirs = vec![root_path.clone()];

    while let Some(dir) = dirs.pop() {
        let entries: Vec<_> = fs::read_dir(&dir)?.filter_map(Result::ok).collect();

        let (sub_dirs, file_paths): (Vec<_>, Vec<_>) = entries
            .into_par_iter()
            .partition(|entry| entry.path().is_dir());

        dirs.extend(sub_dirs.into_iter().map(|entry| entry.path()));
        files.extend(file_paths.into_iter().map(|entry| entry.path()));
    }

    Ok(files)
}
