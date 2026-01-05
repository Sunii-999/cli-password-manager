use serde::{Serialize, Deserialize};

#[derive(Serialize, Deserialize)]
pub struct Entry {
    pub service: String,
    pub username: String,
    pub password_hash: String,
}
