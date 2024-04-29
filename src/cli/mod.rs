mod csv;
mod genpass;

use self::{csv::CsvOpts, genpass::GenPassOpts};
use clap::Parser;

pub use self::csv::OutputFormat;

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
}
