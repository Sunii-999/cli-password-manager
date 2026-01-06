mod handlers;
use handlers::Entry;
use std::io::{self, Read, Write};
use std::fs::{self, OpenOptions};
use std::error::Error;


use aes_gcm::{aead::{Aead, AeadCore, KeyInit}, Aes256Gcm, Key, Nonce};
use rand::rngs::OsRng;
use base64::{Engine as _, engine::general_purpose};
use serde_json;

fn main() {
    let master_key_bytes = [0u8; 32]; // 32 bytes = 256 bits
    let choices = ["Add new", "List passwords", "Search", "Quit"];
    clr();
    loop {
        println!("\n--- Password asdsa ---");
        for (i, v) in choices.iter().enumerate() {
            println!("{}. {}", i + 1, v);
        }

        print!("\nAwaiting input: ");
        io::stdout().flush().unwrap();

        let mut selection = String::new();
        io::stdin().read_line(&mut selection).unwrap();

        match selection.trim().parse::<u32>() {
            Ok(1) => {
                clr();
                println!("Service:");
                let service = read_line();

                println!("Username:");
                let username = read_line();

                println!("Password:");
                let password = read_line();

                let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(&master_key_bytes));
                let nonce = Aes256Gcm::generate_nonce(&mut OsRng);

                let ciphertext = cipher.encrypt(&nonce, password.as_bytes())
                    .expect("Encryption failed");

                let mut encrypted_packet = nonce.to_vec();
                encrypted_packet.extend_from_slice(&ciphertext);

                let encrypted_string = general_purpose::STANDARD.encode(encrypted_packet);

                println!("Is this correct?:");
                println!("service: {}", service);
                println!("username: {}", username);
                println!("password: {}", password);

                verify_input();

                if confirm_action() {
                    let entry = Entry {
                        service,
                        username,
                        password_hash: encrypted_string,
                    };
                    save_entry(entry);
                    println!("Saved encrypted credential.");
                }
            },
            Ok(2) => {
                clr();
                if !std::path::Path::new("passwords.json").exists() {
                    println!("No passwords found. Try adding one first.");
                    continue;
                }

                let contents = fs::read_to_string("passwords.json")
                    .expect("Something went wrong reading the file");

                let entries: Vec<Entry> = serde_json::from_str(&contents)
                    .unwrap_or_else(|_| Vec::new()); 

                println!("Stored Credentials:");
                println!("-------------------");
                for (index, entry) in entries.iter().enumerate() {
                    
                    let cleartext = decrypt_value(&entry.password_hash, &master_key_bytes);
                    
                    println!("{}. {} | User: {} | Pass: {}", 
                        index + 1, 
                        entry.service, 
                        entry.username, 
                        cleartext
                    );
                }
                println!("-------------------");
            }
            Ok(3) => {
                clr();

                println!("Search query:");
                let query = read_line();

                let file_path = "passwords.json".to_string();

                let config = Config {
                    query,
                    file_path,
                    ignore_case: true, // or false, your choice
                };

                if let Err(e) = run(config, &master_key_bytes) {
                    eprintln!("Application error: {e}");
                }
            }

            Ok(4) => {
                println!("Goodbye!");
                break;
            }
            Ok(_) => println!("Please enter 1–4."),
            Err(_) => println!("Invalid input."),
        }
    }
}

fn read_line() -> String {
    let mut s = String::new();
    io::stdin().read_line(&mut s).unwrap();
    s.trim().to_string()
}

fn confirm_action() -> bool {
    loop {
        println!("\nDo you wish to proceed? (y/n)");
        let mut input = String::new();
        io::stdin().read_line(&mut input).unwrap();
        let clean = input.trim().to_lowercase();

        if clean == "y" || clean == "yes" {
            return true;
        } else if clean == "n" || clean == "no" {
            return false;
        } else {
            println!("Invalid input.");
        }
    }
}

fn verify_input() -> bool {
    loop {
        println!("\nDouble check, is this correct?? (y/n)");
        let mut input = String::new();
        io::stdin().read_line(&mut input).unwrap();
        let clean = input.trim().to_lowercase();

        if clean == "y" || clean == "yes" {
            return true;
        } else if clean == "n" || clean == "no" {
            return false;
        } else {
            println!("Invalid input.");
        }
    }
}

fn clr() {
    print!("{}[2J", 27 as char);
}

fn save_entry(entry: Entry) {
    let path = "passwords.json";

    // 1. Load existing
    let mut entries: Vec<Entry> = if let Ok(mut file) = OpenOptions::new().read(true).open(path) {
        let mut contents = String::new();
        file.read_to_string(&mut contents).unwrap();
        serde_json::from_str(&contents).unwrap_or_default()
    } else {
        Vec::new()
    };

    entries.push(entry);

    let json = serde_json::to_string_pretty(&entries).unwrap();
    let mut file = OpenOptions::new()
        .create(true)
        .write(true)
        .truncate(true)
        .open(path)
        .unwrap();

    file.write_all(json.as_bytes()).unwrap();
}

fn decrypt_value(encrypted_base64: &str, key: &[u8; 32]) -> String {
    let encrypted_bytes = general_purpose::STANDARD
        .decode(encrypted_base64)
        .unwrap_or_else(|_| Vec::new());

    if encrypted_bytes.len() < 12 {
        return "Invalid Data".to_string();
    }

    let (nonce_bytes, ciphertext) = encrypted_bytes.split_at(12);
    
    let nonce = Nonce::from_slice(nonce_bytes);
    
    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(key));

    match cipher.decrypt(nonce, ciphertext) {
        Ok(plaintext) => String::from_utf8(plaintext).unwrap_or("Bad UTF-8".to_string()),
        Err(_) => "WRONG KEY / CORRUPT DATA".to_string()
    }
}

fn run(config: Config, master_key: &[u8; 32]) -> Result<(), Box<dyn Error>> {
    let contents = fs::read_to_string(config.file_path)?;
    let entries: Vec<Entry> = serde_json::from_str(&contents)?;

    let query = if config.ignore_case {
        config.query.to_lowercase()
    } else {
        config.query.clone()
    };

    let mut found = false;

    for entry in entries {
        let service = if config.ignore_case {
            entry.service.to_lowercase()
        } else {
            entry.service.clone()
        };

        let username = if config.ignore_case {
            entry.username.to_lowercase()
        } else {
            entry.username.clone()
        };

        if service.contains(&query) || username.contains(&query) {
            let password = decrypt_value(&entry.password_hash, master_key);

            println!("-------------------");
            println!("Service : {}", entry.service);
            println!("Username: {}", entry.username);
            println!("Password: {}", password);
            found = true;
        }
    }

    if !found {
        println!("No matching entries found.");
    }

    Ok(())
}

pub struct Config {
    pub query: String,
    pub file_path: String,
    pub ignore_case: bool,
}