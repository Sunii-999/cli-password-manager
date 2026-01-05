mod handlers;

use argon2::password_hash::SaltString;
use handlers::Entry;
use std::io::{self, Read, Write};
use std::fs::{self, OpenOptions};
use argon2::{Argon2, PasswordHasher, password_hash::Salt};
use rand::rngs::OsRng;


use serde_json;

fn main() {
    let choices = ["Add new", "List passwords", "Search", "Quit"];

    loop {
        println!("\nPassword manager:");
        for (i, v) in choices.iter().enumerate() {
            println!("{}. {}", i + 1, v);
        }

        print!("\nAwaiting input... ");
        io::stdout().flush().unwrap();

        let mut selection = String::new();
        io::stdin().read_line(&mut selection).unwrap();

        match selection.trim().parse::<u32>() {
            Ok(1) => {
                println!("Service:");
                let service = read_line();

                println!("Username:");
                let username = read_line();

                println!("Password:");
                let password = read_line();
                let salt_str = SaltString::generate(&mut OsRng);
                let salt: Salt = Salt::from(&salt_str);

                let argon2 = Argon2::default();
                let hash = argon2.hash_password(password.as_bytes(), salt).unwrap();

                let def_password = hash.to_string();

                if confirm_action() {
                    let entry = Entry {
                        service,
                        username,
                        password_hash: def_password,
                    };
                    save_entry(entry);
                    println!("Saved.");
                }
            },
            Ok(2) => {
                clr();
                let contents = fs::read_to_string("passwords.json").expect("Something went wrong reading the file");

                let entries : Vec<Entry> = serde_json::from_str(&contents).expect("REASON");

                println!("Stored Credentials:");
                for (index, entry) in entries.iter().enumerate() {
                    println!("{}. {} ({})", index + 1, entry.service, entry.username);
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
        println!("Do you wish to proceed? (y/n)");

        let mut input = String::new();
        io::stdin().read_line(&mut input).unwrap();

        let clean_input = input.trim().to_lowercase();

        if clean_input == "y" || clean_input == "yes" {
            return true;
        } else if clean_input == "n" || clean_input == "no" {
            return false;
        } else {
            println!("Invalid input. Please type 'y' for yes or 'n' for no.");
        }
    }
}

fn clr() {
    print!("{}[2J", 27 as char);
}

fn save_entry(entry: Entry) {
    let path = "passwords.json";

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