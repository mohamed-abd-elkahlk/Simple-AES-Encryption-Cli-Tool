use aes::{
    cipher::{generic_array::GenericArray, KeyInit},
    Aes128, Aes192, Aes256,
};
use cipher_cli::*;
use colored::*;
use dialoguer::{Confirm, Input, Select};

use std::{error::Error, fs, path::PathBuf, sync::Arc};
fn main() -> Result<(), Box<dyn Error + Send + Sync>> {
    let operation = Select::new()
        .with_prompt("What do you want to do?".green().bold().to_string())
        .items(&["Encrypt", "Decrypt"])
        .default(0)
        .interact()?;

    let algo_type = Select::new()
        .with_prompt("Select encryption algorithm".green().bold().to_string())
        .items(&["AES-128", "AES-192", "AES-256"])
        .default(0)
        .interact()?;

    let dir_input: String = Input::new()
        .with_prompt("Enter the directory path".blue().bold().to_string())
        .interact_text()?;

    let key_size = match algo_type {
        0 => 128,
        1 => 192,
        2 => 256,
        _ => unreachable!(),
    };

    let use_key_from_file = if fs::metadata(format!("AES{}.key", key_size)).is_ok() {
        Confirm::new()
            .with_prompt(
                "Do you want to use the existing key from file?"
                    .yellow()
                    .bold()
                    .to_string(),
            )
            .interact()?
    } else {
        false
    };

    let key = if use_key_from_file {
        read_key_from_file(key_size).unwrap_or_else(|e| {
            eprintln!("{}", e);
            std::process::exit(1);
        })
    } else {
        let new_key = generate_key!(key_size).unwrap_or_else(|e| {
            eprintln!("{}", e);
            std::process::exit(1);
        });
        save_key_to_file(&new_key)?;
        new_key
    };

    match operation {
        0 => match key_size {
            128 => encrypt_directory(
                PathBuf::from(&dir_input),
                MAGIC_NUMBER_128,
                Arc::new(Aes128::new(GenericArray::from_slice(&key))),
            )?,
            192 => encrypt_directory(
                PathBuf::from(&dir_input),
                MAGIC_NUMBER_192,
                Arc::new(Aes192::new(GenericArray::from_slice(&key))),
            )?,
            256 => encrypt_directory(
                PathBuf::from(&dir_input),
                MAGIC_NUMBER_256,
                Arc::new(Aes256::new(GenericArray::from_slice(&key))),
            )?,
            _ => unreachable!(),
        },
        1 => {
            let file_input: String = Input::new()
                .with_prompt("Enter the file path to decrypt".blue().bold().to_string())
                .interact_text()?;

            match key_size {
                128 => decrypt_directory(
                    file_input.into(),
                    MAGIC_NUMBER_128,
                    Arc::new(Aes128::new(GenericArray::from_slice(&key))),
                )?,
                192 => decrypt_directory(
                    file_input.into(),
                    MAGIC_NUMBER_192,
                    Arc::new(Aes192::new(GenericArray::from_slice(&key))),
                )?,
                256 => decrypt_directory(
                    file_input.into(),
                    MAGIC_NUMBER_256,
                    Arc::new(Aes256::new(GenericArray::from_slice(&key))),
                )?,
                _ => unreachable!(),
            }
        }
        _ => unreachable!(),
    }
    Ok(())
}
