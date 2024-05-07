mod cli;
mod process;
mod utils;
use enum_dispatch::enum_dispatch;

pub use cli::{
    Base64Format, Base64Subcommand, CsvOpts, DecodeOpts, EncodeOpts, GenPassOpts, HttpServeOpts,
    HttpSubCommand, JwtSignOpts, JwtSubCommand, JwtVerifyOpts, KeyGenerateOpts, Opts, SubCommand,
    TextDecryptOpts, TextEncryptOpts, TextSignFormat, TextSignOpts, TextSubCommand, TextVerifyOpts,
};
pub use process::{
    process_csv, process_decode, process_encode, process_genpass, process_http_serve,
    process_jwt_sign, process_jwt_verify, process_text_decrypt, process_text_encrypt,
    process_text_generate, process_text_sign, process_text_verify,
};
pub use utils::get_reader;

#[allow(async_fn_in_trait)]
#[enum_dispatch]
pub trait CmdExecutor {
    async fn execute(self) -> anyhow::Result<()>;
}
