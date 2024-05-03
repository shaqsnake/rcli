mod base64;
mod csv;
mod genpass;
mod text;

use std::path::Path;

use self::{csv::CsvOpts, genpass::GenPassOpts};
use clap::Parser;

pub use self::{
    base64::{Base64Format, Base64Subcommand},
    csv::OutputFormat,
    text::{TextSignFormat, TextSubCommand},
};

#[derive(Debug, Parser)]
#[command(name="rcli", version, author, about, long_about=None)]
pub struct Opts {
    #[clap(subcommand)]
    pub cmd: SubCommand,
}

#[derive(Debug, Parser)]
pub enum SubCommand {
    #[command(name = "csv", about = "Show CSV, or convert it to other formats")]
    Csv(CsvOpts),

    #[command(name = "genpass", about = "Generate a random password")]
    GenPass(GenPassOpts),

    #[command(subcommand)]
    Base64(Base64Subcommand),

    #[command(subcommand)]
    Text(TextSubCommand),
}

fn verify_file(filename: &str) -> Result<String, &'static str> {
    if filename == "-" || Path::new(filename).exists() {
        Ok(filename.into())
    } else {
        Err("File does not exist")
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
