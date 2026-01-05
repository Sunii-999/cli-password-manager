mod handlers;

use std::io;
use std::io::{Write};


fn main() {
    let choices: [&str; 4] = ["Add new", "List passwords", "Search", "Quit"];

    println!("Password manager:");
    println!("(Select by typing number)");

    for (count, v) in choices.into_iter().enumerate() {
        println!("{}. {}", count + 1, v);
    }

        println!("\nAwaiting input...");
        io::stdout().flush().unwrap();

        let mut selection = String::new();
        io::stdin().read_line(&mut selection).unwrap();

        let selection = selection.trim().parse::<u32>();

    match selection {
        Ok(1) => {
            // clr();
            println!("Add a new password: Service username password");
            println!("\nAwaiting input...");

            let mut new_password = String::new();
            io::stdin().read_line(&mut new_password).unwrap();
            println!("is this correct? {}", new_password);


            if confirm_action() {
                println!("Action confirmed.");
            } else {
                println!("Action cancelled.");
            }
            },
            Ok(2) => {
                println!("List passwords");
            }
            Ok(3) => {
                println!("Search");
            }
            Ok(4) => 'block: {
                println!("Goodbye!");
                break 'block;
            }
            Ok(_) => {
                println!("Please enter a number between 1 and 4.");
            }
            Err(_) => {
                println!("Invalid input. Please enter a number.");
            }
        };

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

// fn clr() {
//     print!("{}[2J", 27 as char);
// }
