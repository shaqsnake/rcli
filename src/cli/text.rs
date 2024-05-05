use std::{fmt, path::PathBuf, str::FromStr};

use anyhow::Result;
use clap::Parser;
use enum_dispatch::enum_dispatch;

use crate::{
    process_text_decrypt, process_text_encrypt, process_text_generate, process_text_sign,
    process_text_verify, CmdExecutor,
};

use super::{verify_file, verify_path};

#[derive(Debug, Parser)]
#[enum_dispatch(CmdExecutor)]
pub enum TextSubCommand {
    #[command(about = "Sign a text with a private/session key")]
    Sign(TextSignOpts),

    #[command(about = "Verify a text with a public/session key")]
    Verify(TextVerifyOpts),

    #[command(about = "Generate a random blake3 key or ed25519 key pair")]
    Generate(KeyGenerateOpts),

    #[command(about = "Encrypt a text with a key")]
    Encrypt(TextEncryptOpts),

    #[command(about = "Decrypt a text with a key")]
    Decrypt(TextDecryptOpts),
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

impl CmdExecutor for TextSignOpts {
    async fn execute(self) -> anyhow::Result<()> {
        let signed = process_text_sign(&self.input, &self.key, self.format)?;
        println!("{}", signed);

        Ok(())
    }
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

impl CmdExecutor for TextVerifyOpts {
    async fn execute(self) -> anyhow::Result<()> {
        let verified = process_text_verify(&self.input, &self.key, self.format, &self.sig)?;
        println!("{}", verified);

        Ok(())
    }
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

impl CmdExecutor for KeyGenerateOpts {
    async fn execute(self) -> anyhow::Result<()> {
        process_text_generate(self.format, &self.output)?;

        Ok(())
    }
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
pub struct TextEncryptOpts {
    #[arg(short, long, value_parser = verify_file, default_value = "-")]
    pub input: String,

    #[arg(short, long, value_parser = verify_file)]
    pub key: String,

    #[arg(long, default_value = "chacha20poly1305", value_parser = parse_text_format)]
    pub format: TextSignFormat,
}

impl CmdExecutor for TextEncryptOpts {
    async fn execute(self) -> anyhow::Result<()> {
        let encrypted = process_text_encrypt(&self.input, &self.key, self.format)?;
        println!("{}", encrypted);

        Ok(())
    }
}

#[derive(Debug, Parser)]
pub struct TextDecryptOpts {
    #[arg(short, long, value_parser = verify_file, default_value = "-")]
    pub input: String,

    #[arg(short, long, value_parser = verify_file)]
    pub key: String,

    #[arg(long, default_value = "chacha20poly1305", value_parser = parse_text_format)]
    pub format: TextSignFormat,
}

impl CmdExecutor for TextDecryptOpts {
    async fn execute(self) -> anyhow::Result<()> {
        let decrypted = process_text_decrypt(&self.input, &self.key, self.format)?;
        println!("{}", decrypted);

        Ok(())
    }
}
