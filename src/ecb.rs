use std::{
    error::Error,
    fs::{self, File},
    io::{BufWriter, Write},
    path::{Path, PathBuf},
    sync::Arc,
};

use aes::cipher::{generic_array::GenericArray, BlockDecrypt, BlockEncrypt};
use cipher_cli::{files_dir_explorer, EncryptedFilesPath};
use colored::Colorize;
use memmap2::MmapMut;
use rayon::iter::{IntoParallelRefIterator, ParallelIterator};
use spinners::{Spinner, Spinners};

// Encrypt a single file efficiently
pub fn encrypt_file(
    file_path: &Path,
    magic_number: &[u8],
    cipher: &impl BlockEncrypt,
) -> Result<(), Box<dyn Error + Send + Sync>> {
    let file = File::options().read(true).write(true).open(file_path)?;
    let file_size = file.metadata()?.len() as usize;

    let padding = 16 - (file_size % 16);
    let new_size = file_size + padding;

    // Resize file for padding
    file.set_len(new_size as u64)?;

    // Memory-map the file for fast processing
    let mut mmap = unsafe { MmapMut::map_mut(&file)? };

    // Apply PKCS7 padding
    for i in 0..padding {
        mmap[file_size + i] = padding as u8;
    }

    // Encrypt file in-place
    mmap.chunks_exact_mut(16)
        .for_each(|chunk| cipher.encrypt_block(GenericArray::from_mut_slice(chunk)));

    // Write encrypted content to a temporary file
    let temp_path = file_path.with_extension("enc.tmp");
    let temp_file = File::create(&temp_path)?;
    let mut writer = BufWriter::with_capacity(64 * 1024, temp_file); // 64KB buffer

    writer.write_all(magic_number)?;
    writer.write_all(&mmap)?;
    writer.flush()?;

    // Replace original file with encrypted one
    fs::rename(temp_path, file_path)?;

    Ok(())
}

// Encrypt all files in a directory using Rayon for parallelism
pub fn encrypt_directory(
    root_path: PathBuf,
    magic_number: &[u8],
    cipher: Arc<impl BlockEncrypt + Send + Sync>,
) -> Result<(), Box<dyn Error + Send + Sync>> {
    let files = files_dir_explorer(&root_path)?;
    if files.is_empty() {
        return Err("No files found".into());
    }

    let mut sp = Spinner::new(Spinners::Line, "Encrypting files...".into());

    let encrypted_files: Vec<PathBuf> = files
        .par_iter()
        .filter_map(|file| {
            encrypt_file(file, magic_number, &*cipher)
                .ok()
                .map(|_| file.clone())
        })
        .collect();

    // Save encrypted file paths to JSON
    let json_path = root_path.join("encrypted_files.json");
    let json_file = File::create(&json_path)?;
    serde_json::to_writer_pretty(
        json_file,
        &EncryptedFilesPath {
            path: encrypted_files,
        },
    )?;

    sp.stop_with_newline();
    println!("Encrypted file paths saved to {}", json_path.display());
    Ok(())
}

// Decrypt a single file efficiently
pub fn decrypt_file(
    file_path: &Path,
    magic_number: &[u8],
    cipher: &impl BlockDecrypt,
) -> Result<(), Box<dyn Error + Send + Sync>> {
    let mut data = fs::read(file_path)?;

    if !data.starts_with(magic_number) {
        return Err("File is not encrypted or uses an unsupported format".into());
    }
    data.drain(0..magic_number.len()); // Remove magic number

    // Decrypt in-place
    data.chunks_mut(16)
        .for_each(|chunk| cipher.decrypt_block(GenericArray::from_mut_slice(chunk)));

    // Remove padding
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
        return Err("File too short for valid padding".into());
    }

    // Overwrite original file with decrypted data
    fs::write(file_path, &data)?;

    Ok(())
}

// Decrypt all files in a directory using Rayon for parallelism
pub fn decrypt_directory(
    root_path: PathBuf,
    magic_number: &[u8],
    cipher: Arc<impl BlockDecrypt + Send + Sync>,
) -> Result<(), Box<dyn Error + Send + Sync>> {
    let json_path = root_path.join("encrypted_files.json");
    let mut sp = Spinner::new(Spinners::Line, "Decrypting files...".into());

    let encrypted_files = if json_path.exists() {
        let files: EncryptedFilesPath = serde_json::from_reader(File::open(&json_path)?)?;
        fs::remove_file(&json_path)?;
        files.path
    } else {
        files_dir_explorer(&root_path)?
    };

    if encrypted_files.is_empty() {
        sp.stop_with_newline();
        return Err("No encrypted files found!".into());
    }

    encrypted_files
        .par_iter()
        .try_for_each(|file| decrypt_file(file, magic_number, &*cipher))?;

    sp.stop_with_newline();
    println!("{}", "All files decrypted successfully.".green().bold());
    Ok(())
}
