#[cfg(test)]
mod tests {
    use aes::{
        cipher::{generic_array::GenericArray, KeyInit},
        Aes128,
    };
    use aes_example::{
        decrypt_file, encrypt_file, generate_key, read_key_from_file, save_key_to_file,
        MAGIC_NUMBER_128, MAGIC_NUMBER_192, MAGIC_NUMBER_256,
    };
    use std::fs;

    fn create_temp_file(content: &str) -> String {
        let file_path = format!("test_file_{}.txt", uuid::Uuid::new_v4());
        fs::write(&file_path, content).unwrap();
        file_path
    }

    // Test magic numbers
    #[test]
    fn test_magic_numbers() {
        assert_eq!(MAGIC_NUMBER_128, b"AES128ENC");
        assert_eq!(MAGIC_NUMBER_192, b"AES192ENC");
        assert_eq!(MAGIC_NUMBER_256, b"AES256ENC");
    }

    // Test key generation
    #[test]
    fn test_generate_key() {
        let key_128 = generate_key!(128).unwrap();
        assert_eq!(key_128.len(), 16);

        let key_192 = generate_key!(192).unwrap();
        assert_eq!(key_192.len(), 24);

        let key_256 = generate_key!(256).unwrap();
        assert_eq!(key_256.len(), 32);

        // Test invalid key size
        assert!(generate_key!(64).is_err());
    }

    // Test saving and reading keys
    #[test]
    fn test_save_and_read_key() {
        let key: Vec<u8> = generate_key!(128).unwrap();
        save_key_to_file(&key).unwrap();

        let loaded_key = read_key_from_file(128).unwrap();
        assert_eq!(key, loaded_key);
        fs::remove_file("AES128.key").unwrap();
    }

    // Test encryption and decryption with AES-128
    #[test]
    fn encrypt_decrypt() {
        let file_path = create_temp_file("Hello, AES-128!");
        let key = generate_key!(128).unwrap();
        // Encrypt the file
        encrypt_file(
            &file_path,
            MAGIC_NUMBER_128,
            Aes128::new(GenericArray::from_slice(&key)),
        )
        .unwrap();
        // Check if the file is encrypted
        let encrypted_data = fs::read(&file_path).unwrap();
        assert!(encrypted_data.starts_with(MAGIC_NUMBER_128));

        // Decrypt the file
        decrypt_file(
            &file_path,
            MAGIC_NUMBER_128,
            Aes128::new(GenericArray::from_slice(&key)),
        )
        .unwrap();
        // Check if the file is decrypted correctly
        let decrypted_data = fs::read_to_string(&file_path).unwrap();
        assert_eq!(decrypted_data, "Hello, AES-128!");
        // Clean up
        fs::remove_file(&file_path).unwrap_or_else(|e| eprintln!("{e}"));
    }

    // Test decryption of a non-encrypted file
    #[test]
    fn test_decrypt_non_encrypted_file() {
        let file_path = create_temp_file("This file is not encrypted!");
        let key = generate_key!(128).unwrap();

        // Attempt to decrypt the file
        let result = decrypt_file(
            &file_path,
            MAGIC_NUMBER_128,
            Aes128::new(GenericArray::from_slice(&key)),
        );
        assert!(result.is_err());
        assert_eq!(
            result.unwrap_err().to_string(),
            "File is not encrypted or uses an unsupported format"
        );

        // Clean up
        fs::remove_file(&file_path).unwrap();
    }

    // Test encryption of an already encrypted file
    #[test]
    fn test_encrypt_already_encrypted_file() {
        let file_path = create_temp_file("Hello, already encrypted!");
        let key = generate_key!(128).unwrap();

        // Encrypt the file
        encrypt_file(
            &file_path,
            MAGIC_NUMBER_128,
            Aes128::new(GenericArray::from_slice(&key)),
        )
        .unwrap();

        // Attempt to encrypt the file again
        let result = encrypt_file(
            &file_path,
            MAGIC_NUMBER_128,
            Aes128::new(GenericArray::from_slice(&key)),
        );
        assert!(result.is_err());
        assert_eq!(result.unwrap_err().to_string(), "File is already encrypted");

        // Clean up
        fs::remove_file(&file_path).unwrap();
    }
}