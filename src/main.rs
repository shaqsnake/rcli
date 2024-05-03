use anyhow::Result;
use clap::Parser;
use rcli::{
    process_csv, process_decode, process_encode, process_genpass, process_text_sign,
    process_text_verify, Base64Subcommand, Opts, SubCommand, TextSubCommand,
};

fn main() -> Result<()> {
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
            process_genpass(
                opts.length,
                opts.uppercase,
                opts.lowercase,
                opts.number,
                opts.symbol,
            )?;
        }
        SubCommand::Base64(base64_opts) => match base64_opts {
            Base64Subcommand::Encode(opts) => {
                process_encode(&opts.input, opts.format)?;
            }
            Base64Subcommand::Decode(opts) => {
                process_decode(&opts.input, opts.format)?;
            }
        },
        SubCommand::Text(text_opts) => match text_opts {
            TextSubCommand::Sign(opts) => {
                process_text_sign(&opts.input, &opts.key, opts.format)?;
            }
            TextSubCommand::Verify(opts) => {
                process_text_verify(&opts.input, &opts.key, opts.format, &opts.sig)?;
            }
        },
    }

    Ok(())
}
