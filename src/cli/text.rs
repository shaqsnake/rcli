use std::{fmt, path::PathBuf, str::FromStr};

use anyhow::Result;
use clap::Parser;

use super::{verify_file, verify_path};

#[derive(Debug, Parser)]
pub enum TextSubCommand {
    #[command(about = "Sign a text with a private/session key")]
    Sign(TextSignOpts),

    #[command(about = "Verify a text with a public/session key")]
    Verify(TextVerifyOpts),

    #[command(about = "Generate a random blake3 key or ed25519 key pair")]
    Generate(KeyGenerateOpts),

    #[command(about = "Encrypt a text with a key")]
    Encrypt(TextCipherOpts),

    #[command(about = "Decrypt a text with a key")]
    Decrypt(TextCipherOpts),
}

#[derive(Debug, Parser)]
pub struct TextSignOpts {
    #[arg(short, long, value_parser = verify_file, default_value = "-")]
    pub input: String,

    #[arg(short, long, value_parser = verify_file)]
    pub key: String,

    #[arg(long, default_value = "blake3", value_parser = parse_text_format)]
    pub format: TextSignFormat,
}

#[derive(Debug, Parser)]
pub struct TextVerifyOpts {
    #[arg(short, long, value_parser = verify_file, default_value = "-")]
    pub input: String,

    #[arg(short, long, value_parser = verify_file)]
    pub key: String,

    #[arg(long, default_value = "blake3", value_parser = parse_text_format)]
    pub format: TextSignFormat,

    #[arg(short, long)]
    pub sig: String,
}

#[derive(Debug, Clone, Copy)]
pub enum TextSignFormat {
    Blake3,
    Ed25519,
    ChaCha20Poly1305,
}

#[derive(Debug, Parser)]
pub struct KeyGenerateOpts {
    #[arg(short, long, default_value = "blake3", value_parser = parse_text_format)]
    pub format: TextSignFormat,

    #[arg(short, long, value_parser = verify_path)]
    pub output: PathBuf,
}

fn parse_text_format(format: &str) -> Result<TextSignFormat, anyhow::Error> {
    format.parse()
}

impl FromStr for TextSignFormat {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "blake3" => Ok(TextSignFormat::Blake3),
            "ed25519" => Ok(TextSignFormat::Ed25519),
            "chacha20poly1305" => Ok(TextSignFormat::ChaCha20Poly1305),
            _ => Err(anyhow::anyhow!("Invalid format: {}", s)),
        }
    }
}

impl fmt::Display for TextSignFormat {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            TextSignFormat::Blake3 => write!(f, "blake3"),
            TextSignFormat::Ed25519 => write!(f, "ed25519"),
            TextSignFormat::ChaCha20Poly1305 => write!(f, "chacha20poly1305"),
        }
    }
}

#[derive(Debug, Parser)]
pub struct TextCipherOpts {
    #[arg(short, long, value_parser = verify_file, default_value = "-")]
    pub input: String,

    #[arg(short, long, value_parser = verify_file)]
    pub key: String,

    #[arg(long, default_value = "chacha20poly1305", value_parser = parse_text_format)]
    pub format: TextSignFormat,
}
