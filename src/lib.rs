use once_cell::sync::Lazy;
use regex::Regex;

pub mod adapters;
pub mod config;
pub mod db;
pub mod error;
pub mod handlers;
pub mod models;
pub mod ports;
pub mod services;
pub mod state;

pub static NAME_REGEX: Lazy<Regex> = Lazy::new(|| Regex::new(r"^[a-zA-ZæøåÆØÅ\s]+$").unwrap());

pub static EMAIL_REGEX: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$").unwrap());

pub static PHONE_REGEX: Lazy<Regex> = Lazy::new(|| Regex::new(r"^\+[1-9]\d{6,14}$").unwrap());
