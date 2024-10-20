use serde::{Deserialize, Serialize};

pub mod service;

/// Determine if the String a is a prefix of String b.
pub fn is_prefix(a: &String, b: &String) -> bool {
    let a_size = a.len();
    if a_size > b.len() {
        return false;
    }

    *a == b[..a_size]
}

#[derive(Deserialize, Debug, Clone)]
pub struct PathDefinition {
    pub path: String,
    pub dst_addr: String,
    pub protected: Option<bool>,
}

impl PathDefinition {
    pub fn new(path: &str, dst_addr: &str) -> Self {
        Self {
            path: path.to_string(),
            dst_addr: dst_addr.to_string(),
            protected: None,
        }
    }

    pub fn protected(mut self) -> Self {
        self.protected = Some(true);

        self
    }
}
