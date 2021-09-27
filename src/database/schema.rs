use revault_tx::{
    bitcoin::{consensus::encode, BlockHash, Network},
    scripts::{CpfpDescriptor, DepositDescriptor, UnvaultDescriptor},
};

use std::{convert::TryFrom, str::FromStr};

pub const SCHEMA: &str = "\
CREATE TABLE version (
    version INTEGER NOT NULL
);

/* This stores metadata about what we are watching. We only support (for now
 * and the foreseeable future) a single instance.
 */
CREATE TABLE instances (
    id INTEGER PRIMARY KEY NOT NULL,
    creation_timestamp INTEGER NOT NULL,
    deposit_descriptor TEXT NOT NULL,
    unvault_descriptor TEXT NOT NULL,
    cpfp_descriptor TEXT NOT NULL,
    network TEXT NOT NULL,
    tip_blockheight INTEGER NOT NULL,
    tip_blockhash BLOB NOT NULL
);
";

/// A row in the "instances" table
#[derive(Clone)]
pub struct DbInstance {
    pub id: i64,
    pub creation_timestamp: u32,
    pub deposit_descriptor: DepositDescriptor,
    pub unvault_descriptor: UnvaultDescriptor,
    pub cpfp_descriptor: CpfpDescriptor,
    pub network: Network,
    pub tip_blockheight: i32,
    pub tip_blockhash: BlockHash,
}

impl TryFrom<&rusqlite::Row<'_>> for DbInstance {
    type Error = rusqlite::Error;

    fn try_from(row: &rusqlite::Row) -> Result<Self, Self::Error> {
        let id = row.get(0)?;
        let creation_timestamp = row.get(1)?;

        let deposit_desc_str: String = row.get(2)?;
        let deposit_descriptor = DepositDescriptor::from_str(&deposit_desc_str)
            .expect("Insane database: can't parse deposit descriptor");

        let unvault_desc_str: String = row.get(3)?;
        let unvault_descriptor = UnvaultDescriptor::from_str(&unvault_desc_str)
            .expect("Insane database: can't parse unvault descriptor");

        let cpfp_desc_str: String = row.get(4)?;
        let cpfp_descriptor = CpfpDescriptor::from_str(&cpfp_desc_str)
            .expect("Insane database: can't parse CPFP descriptor");

        let network: String = row.get(5)?;
        let network =
            Network::from_str(&network).expect("Insane database: can't parse network string");

        let tip_blockheight: i32 = row.get(6)?;
        let tip_blockhash: Vec<u8> = row.get(7)?;
        let tip_blockhash: BlockHash = encode::deserialize(&tip_blockhash)
            .expect("Insane database: can't parse network string");

        Ok(DbInstance {
            id,
            creation_timestamp,
            deposit_descriptor,
            unvault_descriptor,
            cpfp_descriptor,
            network,
            tip_blockheight,
            tip_blockhash,
        })
    }
}
