use anyhow::Result;
use csv::Reader;
use serde::{Deserialize, Serialize};
use std::fs;

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

pub fn process_csv(input: &str, output: &str) -> Result<()> {
    let mut reader = Reader::from_path(input)?;
    let mut res = Vec::with_capacity(128);
    for result in reader.deserialize() {
        let player: Player = result?;
        res.push(player);
    }

    let json = serde_json::to_string_pretty(&res)?;
    fs::write(output, json)?;
    Ok(())
}
