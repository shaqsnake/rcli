use anyhow::Result;
use csv::Reader;
use serde::{Deserialize, Serialize};
use std::fs;

use crate::cli::OutputFormat;

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
struct Player {
    // Name,Position,DOB,Nationality,Kit Number
    name: String,
    position: String,
    #[serde(rename = "DOB")]
    dob: String,
    nationality: String,
    #[serde(rename = "Kit Number")]
    kit: u8,
}

pub fn process_csv(input: &str, output: String, format: OutputFormat) -> Result<()> {
    let mut reader = Reader::from_path(input)?;
    let mut res = Vec::with_capacity(128);
    let headers = reader.headers()?.clone();
    for record in reader.records() {
        let json_value = headers
            .iter()
            .zip(record?.iter())
            .collect::<serde_json::Value>();
        res.push(json_value);
    }

    let content = match format {
        OutputFormat::Json => serde_json::to_string_pretty(&res)?,
        OutputFormat::Yaml => serde_yaml::to_string(&res)?,
    };

    // let json = serde_json::to_string_pretty(&res)?;
    fs::write(output, content)?;
    Ok(())
}
