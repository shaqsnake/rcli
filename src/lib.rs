mod cli;
mod process;
mod utils;

pub use cli::{Base64Format, Base64Subcommand, Opts, SubCommand, TextSignFormat, TextSubCommand};
pub use process::{
    process_csv, process_decode, process_encode, process_genpass, process_text_sign,
    process_text_verify,
};
pub use utils::get_reader;
