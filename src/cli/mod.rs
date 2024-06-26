mod base64;
mod csv;
mod genpass;
mod http;
mod jwt;
mod text;

use clap::Parser;
use enum_dispatch::enum_dispatch;
use std::path::{Path, PathBuf};

pub use self::{
    base64::{Base64Format, Base64Subcommand, DecodeOpts, EncodeOpts},
    csv::{CsvOpts, OutputFormat},
    genpass::GenPassOpts,
    http::{HttpServeOpts, HttpSubCommand},
    jwt::{JwtSignOpts, JwtSubCommand, JwtVerifyOpts},
    text::{
        KeyGenerateOpts, TextDecryptOpts, TextEncryptOpts, TextSignFormat, TextSignOpts,
        TextSubCommand, TextVerifyOpts,
    },
};

#[derive(Debug, Parser)]
#[command(name="rcli", version, author, about, long_about=None)]
pub struct Opts {
    #[clap(subcommand)]
    pub cmd: SubCommand,
}

#[derive(Debug, Parser)]
#[enum_dispatch(CmdExecutor)]
pub enum SubCommand {
    #[command(name = "csv", about = "Show CSV, or convert it to other formats")]
    Csv(CsvOpts),

    #[command(name = "genpass", about = "Generate a random password")]
    GenPass(GenPassOpts),

    #[command(subcommand, about = "Base64 encode/decode")]
    Base64(Base64Subcommand),

    #[command(subcommand, about = "Text sign/verify")]
    Text(TextSubCommand),

    #[command(subcommand, about = "Http server")]
    Http(HttpSubCommand),

    #[command(subcommand, about = "Work with JSON Web Tokens")]
    Jwt(JwtSubCommand),
}

fn verify_file(filename: &str) -> Result<String, &'static str> {
    if filename == "-" || Path::new(filename).exists() {
        Ok(filename.into())
    } else {
        Err("File does not exist")
    }
}

fn verify_path(path: &str) -> Result<PathBuf, &'static str> {
    let p = Path::new(path);
    if p.exists() && p.is_dir() {
        Ok(p.into())
    } else {
        Err("Path does not exist or is not a directory")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_verify_input_file() {
        assert_eq!(verify_file("-"), Ok("-".into()));
        assert_eq!(verify_file("*"), Err("File does not exist"));
        assert_eq!(verify_file("Cargo.toml"), Ok("Cargo.toml".into()));
        assert_eq!(verify_file("nonexistent"), Err("File does not exist"));
    }
}
