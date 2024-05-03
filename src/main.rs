use anyhow::Result;
use clap::Parser;
use rcli::{
    process_csv, process_decode, process_encode, process_genpass, process_http_serve,
    process_text_decrypt, process_text_encrypt, process_text_generate, process_text_sign,
    process_text_verify, Base64Subcommand, HttpSubCommand, Opts, SubCommand, TextSubCommand,
};
use zxcvbn::zxcvbn;

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt::init();
    let opts = Opts::parse();
    match opts.cmd {
        SubCommand::Csv(opts) => {
            let output = if let Some(output) = opts.output {
                output.clone()
            } else {
                format!("output.{}", opts.format)
            };
            process_csv(&opts.input, output, opts.format)?;
        }
        SubCommand::GenPass(opts) => {
            let password = process_genpass(
                opts.length,
                opts.uppercase,
                opts.lowercase,
                opts.number,
                opts.symbol,
            )?;
            println!("{}", password);

            // use zxcvbn to estimate password strength
            let estimate = zxcvbn(&password, &[])?;
            eprintln!("Password strength: {}", estimate.score());
        }
        SubCommand::Base64(base64_opts) => match base64_opts {
            Base64Subcommand::Encode(opts) => {
                let encoded = process_encode(&opts.input, opts.format)?;
                println!("{}", encoded);
            }
            Base64Subcommand::Decode(opts) => {
                let decoded = process_decode(&opts.input, opts.format)?;
                println!("{}", String::from_utf8(decoded)?);
            }
        },
        SubCommand::Text(opts) => match opts {
            TextSubCommand::Sign(opts) => {
                let signed = process_text_sign(&opts.input, &opts.key, opts.format)?;
                println!("{}", signed);
            }
            TextSubCommand::Verify(opts) => {
                let verified = process_text_verify(&opts.input, &opts.key, opts.format, &opts.sig)?;
                println!("{}", verified);
            }
            TextSubCommand::Generate(opts) => {
                process_text_generate(opts.format, &opts.output)?;
            }
            TextSubCommand::Encrypt(opts) => {
                let encrypted = process_text_encrypt(&opts.input, &opts.key, opts.format)?;
                println!("{}", encrypted);
            }
            TextSubCommand::Decrypt(opts) => {
                let decrypted = process_text_decrypt(&opts.input, &opts.key, opts.format)?;
                println!("{}", decrypted);
            }
        },
        SubCommand::Http(http_opts) => match http_opts {
            HttpSubCommand::Serve(opts) => {
                process_http_serve(opts.dir, opts.port).await?;
            }
        },
    }

    Ok(())
}
