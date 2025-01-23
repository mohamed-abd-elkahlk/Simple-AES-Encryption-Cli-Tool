use aes_example::{decrypt, encrypt, generate_key, read_key_from_file, save_key_to_file};
use colored::*;
use dialoguer::{Confirm, Input, Select};
use std::{error::Error, fs};

fn main() -> Result<(), Box<dyn Error>> {
    let opration = Select::new()
        .with_prompt("What do you want to do?".green().bold().to_string())
        .items(&["Encrypt", "Decrypt"])
        .default(0)
        .interact()?;

    let file_input: String = Input::new()
        .with_prompt("Enter the file path".blue().bold().to_string())
        .interact_text()?;

    let key_opration_items = vec!["Generate", "Use my own"];
    let use_key_from_file = if fs::metadata("AES.key").is_ok() {
        Confirm::new()
            .with_prompt(
                "Do you want to use the key from the file [type Enter For Yes]?"
                    .yellow()
                    .bold()
                    .to_string(),
            )
            .default(true)
            .interact()?
    } else {
        false
    };

    let key = if use_key_from_file {
        read_key_from_file()
    } else {
        let key_opration = Select::new()
            .with_prompt(
                "Do you want to generate a key or use your own?"
                    .yellow()
                    .bold()
                    .to_string(),
            )
            .items(&key_opration_items)
            .default(0)
            .interact()?;

        match key_opration {
            0 => {
                // Generate a key
                let key = generate_key();
                println!("{}: {}", "Generated Key".green().bold(), hex::encode(&key));
                save_key_to_file(&key)?;
                println!("{}", "Key saved to file!".green().bold());
                hex::encode(&key)
            }
            1 => {
                // Ask the user for a key
                let key: String = Input::new()
                    .with_prompt(
                        "Enter the encryption key (32-byte hex, 64 characters)"
                            .yellow()
                            .bold()
                            .to_string(),
                    )
                    .interact_text()?;
                if key.len() != 64 {
                    return Err("Key must be 64 hex characters (32 bytes) long".into());
                }
                key
            }
            _ => unreachable!(),
        }
    };

    let key = hex::decode(&key)?; // Decode the hex string to get the original 32-byte key
    match opration {
        0 => match encrypt(&file_input, &key) {
            Ok(_) => println!("{}", "File encrypted successfully!".green().bold()),
            Err(e) => eprintln!("{}: {}", "Encryption failed".red().bold(), e),
        },
        1 => match decrypt(&file_input, &key) {
            Ok(_) => println!("{}", "File decrypted successfully!".green().bold()),
            Err(e) => eprintln!("{}: {}", "Decryption failed".red().bold(), e),
        },
        _ => unreachable!(),
    }

    Ok(())
}
