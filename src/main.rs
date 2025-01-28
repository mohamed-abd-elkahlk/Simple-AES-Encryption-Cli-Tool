use aes::{
    cipher::{generic_array::GenericArray, KeyInit},
    Aes128, Aes192, Aes256,
};
use aes_example::{
    decrypt_file, encrypt_file, generate_key, read_key_from_file, save_key_to_file,
    MAGIC_NUMBER_128, MAGIC_NUMBER_192, MAGIC_NUMBER_256,
};
use colored::*;
use dialoguer::{Confirm, Input, Select};
use std::{error::Error, fs};

fn main() -> Result<(), Box<dyn Error>> {
    // 1 --> which operation ["Encrypt", "Decrypt"]
    let operation = Select::new()
        .with_prompt("What do you want to do?".green().bold().to_string())
        .items(&["Encrypt", "Decrypt"])
        .default(0)
        .interact()?;

    // 2 --> which algorithm ["AES-128", "AES-192", "AES-256"]
    let algo_type = Select::new()
        .with_prompt("Select encryption algorithm".green().bold().to_string())
        .items(&["AES-128", "AES-192", "AES-256"])
        .default(0)
        .interact()?;

    // 3 --> get file path
    let file_input: String = Input::new()
        .with_prompt("Enter the file path".blue().bold().to_string())
        .interact_text()?;

    // Determine key size
    let key_size = match algo_type {
        0 => 128,
        1 => 192,
        2 => 256,
        _ => unreachable!(),
    };

    // Check if key file exists
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

    // Get or generate key
    let key = if use_key_from_file {
        read_key_from_file(key_size)?
    } else {
        let new_key = generate_key!(key_size)?;
        save_key_to_file(&new_key)?;
        new_key
    };

    // Perform encryption or decryption
    match operation {
        0 => match key_size {
            128 => encrypt_file(
                &file_input,
                MAGIC_NUMBER_128,
                Aes128::new(GenericArray::from_slice(&key)),
            )?,
            192 => encrypt_file(
                &file_input,
                MAGIC_NUMBER_192,
                Aes192::new(GenericArray::from_slice(&key)),
            )?,
            256 => encrypt_file(
                &file_input,
                MAGIC_NUMBER_256,
                Aes256::new(GenericArray::from_slice(&key)),
            )?,
            _ => unreachable!(),
        },
        1 => match key_size {
            128 => decrypt_file(
                &file_input,
                MAGIC_NUMBER_128,
                Aes128::new(GenericArray::from_slice(&key)),
            )?,
            192 => decrypt_file(
                &file_input,
                MAGIC_NUMBER_192,
                Aes192::new(GenericArray::from_slice(&key)),
            )?,
            256 => decrypt_file(
                &file_input,
                MAGIC_NUMBER_256,
                Aes256::new(GenericArray::from_slice(&key)),
            )?,
            _ => unreachable!(),
        },
        _ => unreachable!(),
    }

    Ok(())
}
