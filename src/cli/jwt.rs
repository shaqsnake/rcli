use crate::{process_jwt_sign, process_jwt_verify, CmdExecutor};
use anyhow::{anyhow, Result};
use clap::Parser;
use enum_dispatch::enum_dispatch;
use lazy_static::lazy_static;
use regex::Regex;
use time::{Duration, OffsetDateTime};

#[derive(Debug, Parser)]
#[enum_dispatch(CmdExecutor)]
pub enum JwtSubCommand {
    #[command(about = "Sign a JWT")]
    Sign(JwtSignOpts),

    #[command(about = "Verify a JWT")]
    Verify(JwtVerifyOpts),
}

#[derive(Debug, Parser)]
pub struct JwtSignOpts {
    #[arg(long, default_value = "")]
    pub iss: String,

    #[arg(long, default_value = "")]
    pub sub: String,

    #[arg(long, default_value = "")]
    pub aud: String,

    #[arg(long, default_value = "1d", value_parser = parse_duration)]
    pub exp: Duration,
}

impl CmdExecutor for JwtSignOpts {
    async fn execute(self) -> anyhow::Result<()> {
        let token = process_jwt_sign(
            &self.iss,
            &self.sub,
            &self.aud,
            OffsetDateTime::now_utc() + self.exp,
        )?;
        println!("{}", token);
        Ok(())
    }
}

#[derive(Debug, Parser)]
pub struct JwtVerifyOpts {
    #[arg(short, long)]
    pub token: String,
}

impl CmdExecutor for JwtVerifyOpts {
    async fn execute(self) -> anyhow::Result<()> {
        let claims = process_jwt_verify(&self.token)?;
        println!("{}", claims);
        Ok(())
    }
}

fn parse_duration(s: &str) -> Result<Duration> {
    lazy_static! {
        static ref RE: Regex = Regex::new(r"(\d+)([smhd]?)$").unwrap();
    }

    type Err = anyhow::Error;

    let s = s.trim();
    let caps = RE
        .captures(s)
        .ok_or_else(|| Err::msg("Invalid duration format"))?;
    let value = caps
        .get(1)
        .unwrap()
        .as_str()
        .parse()
        .map_err(|_| Err::msg("Invalid duration value"))?;
    let unit = caps.get(2).map(|m| m.as_str()).unwrap_or("s");

    let duration = match unit {
        "s" => Duration::seconds(value),
        "m" => Duration::minutes(value),
        "h" => Duration::hours(value),
        "d" => Duration::days(value),
        _ => return Err(anyhow!("Invalid duration unit")),
    };

    Ok(duration)
}
