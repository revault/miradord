use revault_tx::{
    bitcoin::{
        consensus::encode, secp256k1, util::bip32, Amount, BlockHash, Network, OutPoint, Txid,
    },
    scripts::{CpfpDescriptor, DepositDescriptor, UnvaultDescriptor},
};

use std::{
    convert::{TryFrom, TryInto},
    str::FromStr,
};

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

/* All the vaults we are watching, with necessary information to be able to derive
 * the transaction chain. A new entry is always created with the registration of the
 * Emergency transaction signatures in the 'signatures' table. If 'delegated' is set
 * to 1 it means that the Cancel and UnvaultEmergency signatures are present as well
 * and that we need to be watching for an Unvault transaction broadcast.
 * 'should_cancel' is a ternary indicating whether:
 *  - We should revault a triggered Unvault (1)
 *  - We should let a triggered Unvault pass through (0)
 *  - There is no Unvault attempt or we did not decide yet (NULL)
 * 'revoc_height' is the *max* block height at which the transaction revoking this vault
 * confirmed, or NULL.
 */
CREATE TABLE vaults (
    id INTEGER PRIMARY KEY NOT NULL,
    instance_id INTEGER NOT NULL,
    deposit_txid BLOB NOT NULL,
    deposit_vout INTEGER NOT NULL,
    derivation_index INTEGER NOT NULL,
    amount INTEGER NOT NULL,
    delegated INTEGER NOT NULL CHECK (delegated IN (0,1)),
    should_cancel INTEGER CHECK (should_cancel IN (NULL, 0,1)),
    revoc_height INTEGER,
    UNIQUE(deposit_txid, deposit_vout),
    FOREIGN KEY (instance_id) REFERENCES instances (id)
        ON UPDATE RESTRICT
        ON DELETE RESTRICT
);

/* All the signatures for the vaults we are watching, with tx_type being either:
 * - 0: Emergency
 * - 1: UnvaultEmergency
 * - 2: Cancel
 */
CREATE TABLE signatures (
    id INTEGER PRIMARY KEY NOT NULL,
    vault_id INTEGER NOT NULL,
    tx_type INTEGER NOT NULL CHECK (tx_type IN (0,1,2)),
    pubkey BLOB NOT NULL,
    signature BLOB UNIQUE NOT NULL,
    FOREIGN KEY (vault_id) REFERENCES vaults (id)
        ON UPDATE RESTRICT
        ON DELETE RESTRICT
);
";

/// A row in the "instances" table
#[derive(Clone, Debug)]
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

/// A row in the "vaults" table
#[derive(Clone, Debug, Copy, PartialEq)]
pub struct DbVault {
    pub id: i64,
    pub instance_id: i64,
    pub deposit_outpoint: OutPoint,
    pub derivation_index: bip32::ChildNumber,
    pub amount: Amount,
    pub delegated: bool,
    pub should_cancel: Option<bool>,
    pub revoc_height: Option<i32>,
}

impl TryFrom<&rusqlite::Row<'_>> for DbVault {
    type Error = rusqlite::Error;

    fn try_from(row: &rusqlite::Row) -> Result<Self, Self::Error> {
        let id = row.get(0)?;
        let instance_id = row.get(1)?;

        let deposit_txid: Vec<u8> = row.get(2)?;
        let deposit_txid: Txid = encode::deserialize(&deposit_txid)
            .expect("Insane db: invalid deposit txid in vault row");
        let deposit_vout: u32 = row.get(3)?;
        let deposit_outpoint = OutPoint {
            txid: deposit_txid,
            vout: deposit_vout,
        };

        let derivation_index: u32 = row.get(4)?;
        let derivation_index = bip32::ChildNumber::from_normal_idx(derivation_index)
            .expect("Insane db: hardened deriv index in vault row");

        let amount: i64 = row.get(5)?;
        assert!(amount > 0, "Insane db: negative vault amount");
        let amount = Amount::from_sat(amount as u64);

        let delegated = row.get(6)?;
        let should_cancel: Option<bool> = row.get(7)?;

        let revoc_height: Option<i32> = row.get(8)?;

        Ok(DbVault {
            id,
            instance_id,
            deposit_outpoint,
            derivation_index,
            amount,
            delegated,
            should_cancel,
            revoc_height,
        })
    }
}

/// The type of the transaction a signature is for
#[derive(Clone, Debug, Copy, PartialEq)]
pub enum SigTxType {
    Emergency,
    UnvaultEmergency,
    Cancel,
}

impl TryFrom<i64> for SigTxType {
    type Error = ();

    fn try_from(n: i64) -> Result<Self, Self::Error> {
        match n {
            0 => Ok(Self::Emergency),
            1 => Ok(Self::UnvaultEmergency),
            2 => Ok(Self::Cancel),
            _ => Err(()),
        }
    }
}

/// A row in the "signatures" table
#[derive(Clone, Debug, PartialEq)]
pub struct DbSignature {
    pub id: i64,
    pub vault_id: i64,
    pub tx_type: SigTxType,
    pub pubkey: secp256k1::PublicKey,
    pub signature: secp256k1::Signature,
}

impl TryFrom<&rusqlite::Row<'_>> for DbSignature {
    type Error = rusqlite::Error;

    fn try_from(row: &rusqlite::Row) -> Result<Self, Self::Error> {
        let id = row.get(0)?;
        let vault_id = row.get(1)?;

        let tx_type: i64 = row.get(2)?;
        let tx_type: SigTxType = tx_type
            .try_into()
            .expect("Insane db: tx_type out of bounds");

        let pubkey: Vec<u8> = row.get(3)?;
        let pubkey = secp256k1::PublicKey::from_slice(&pubkey)
            .expect("Insane db: invalid pubkey in sig table");

        let signature: Vec<u8> = row.get(4)?;
        let signature =
            secp256k1::Signature::from_der(&signature).expect("Insane db: non-DER signature");

        Ok(DbSignature {
            id,
            vault_id,
            tx_type,
            pubkey,
            signature,
        })
    }
}
