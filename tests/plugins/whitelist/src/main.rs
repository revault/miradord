use std::error::Error;
use std::fs::File;
use std::io::{self, BufRead, Write};
use std::str::FromStr;

use bitcoin::{consensus::encode, hashes::hex::FromHex, Address, Script, Transaction};
use serde::{Deserialize, Deserializer};
use serde_json::json;

/// A plugin which returns any attempt with a spend transaction sending funds to unknown addresses
fn main() -> Result<(), Box<dyn Error>> {
    let mut buffer = String::new();
    let stdin = io::stdin();
    stdin.read_line(&mut buffer)?;
    let req: Request = serde_json::from_str(&buffer)?;

    let whitelist_file = File::open(req.config.whitelist_file_path)?;
    let mut whitelist: Vec<Script> = Vec::new();
    for line in io::BufReader::new(whitelist_file).lines() {
        if let Ok(value) = line {
            let address = Address::from_str(&value)?;
            whitelist.push(address.payload.script_pubkey());
        }
    }

    let mut vaults_to_revault: Vec<String> = Vec::new();
    for attempt in req.block_info.new_attempts {
        for output in attempt.candidate_tx.output {
            if !whitelist.contains(&output.script_pubkey) {
                vaults_to_revault.push(attempt.deposit_outpoint);
                break;
            }
        }
    }

    let resp = json!({ "revault": vaults_to_revault });
    let bytes = serde_json::to_vec(&resp)?;
    io::stdout().write(&bytes)?;
    Ok(())
}

#[derive(Deserialize)]
struct Request {
    block_info: BlockInfo,
    config: Config,
}

#[derive(Deserialize)]
struct Config {
    whitelist_file_path: String,
}

#[derive(Deserialize)]
struct BlockInfo {
    new_attempts: Vec<Attempt>,
}

#[derive(Deserialize)]
struct Attempt {
    deposit_outpoint: String,
    #[serde(deserialize_with = "deserialize_tx")]
    candidate_tx: Transaction,
}

pub fn deserialize_tx<'de, D>(deserializer: D) -> Result<Transaction, D::Error>
where
    D: Deserializer<'de>,
{
    let hex = String::deserialize(deserializer)?;
    let bytes = Vec::from_hex(&hex).map_err(serde::de::Error::custom)?;
    encode::deserialize::<Transaction>(&bytes).map_err(serde::de::Error::custom)
}
