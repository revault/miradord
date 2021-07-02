pub mod schema;

use revault_tx::{
    bitcoin::{secp256k1, util::bip32, Amount, Network, OutPoint},
    scripts::{CpfpDescriptor, DepositDescriptor, UnvaultDescriptor},
};
use schema::{DbInstance, DbSignature, DbVault, SigTxType, SCHEMA};

use std::{convert::TryInto, fs, io, os::unix::fs::OpenOptionsExt, path, time};

use rusqlite::params;

pub const DB_VERSION: u32 = 0;

#[derive(Debug)]
pub enum DatabaseError {
    Rusqlite(rusqlite::Error),
    FileError(io::Error),
    InvalidVersion(u32),
    InvalidNetwork(Network),
    // First is db descriptor, second is config descriptor
    DescriptorMismatch(String, String),
    /// An operation was requested on a vault that doesn't exist
    UnknownVault(Box<dyn std::fmt::Debug>),
}

impl std::fmt::Display for DatabaseError {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self {
            Self::Rusqlite(ref e) => write!(f, "Internal error: '{}'", e),
            Self::FileError(ref e) => write!(f, "File error: '{}'", e),
            Self::InvalidVersion(ref v) => write!(
                f,
                "Invalid database version '{}', current version is '{}'",
                v, DB_VERSION
            ),
            Self::InvalidNetwork(ref n) => write!(f, "Invalid network '{}'", n),
            Self::DescriptorMismatch(ref db_desc, ref conf_desc) => {
                write!(f, "Descriptor mismatch: '{}' vs '{}'", db_desc, conf_desc)
            }
            Self::UnknownVault(ref id) => write!(
                f,
                "Operation requested on vault at '{:?}' but no such vault exist in database.",
                *id
            ),
        }
    }
}

impl std::error::Error for DatabaseError {}

impl From<rusqlite::Error> for DatabaseError {
    fn from(e: rusqlite::Error) -> Self {
        Self::Rusqlite(e)
    }
}

impl From<io::Error> for DatabaseError {
    fn from(e: io::Error) -> Self {
        Self::FileError(e)
    }
}

// Sqlite supports up to i64, thus rusqlite prevents us from inserting u64's.
// We use this to panic rather than inserting a truncated integer into the database (as we'd have
// done by using `n as u32`).
fn timestamp_to_u32(n: u64) -> u32 {
    n.try_into()
        .expect("Is this the year 2106 yet? Misconfigured system clock.")
}

// For some reasons rust-bitcoin store amounts as u64 instead of i64 (as does bitcoind), but SQLite
// does only support integers up to i64.
fn amount_to_i64(amount: &Amount) -> i64 {
    assert!(
        amount.as_sat() < i64::MAX as u64,
        "Invalid amount, larger than i64::MAX : {:?}",
        amount
    );
    amount.as_sat() as i64
}

fn db_exec<F>(path: &path::Path, modifications: F) -> Result<(), DatabaseError>
where
    F: FnOnce(&rusqlite::Transaction) -> Result<(), DatabaseError>,
{
    let mut conn = rusqlite::Connection::open(path)?;
    conn.busy_timeout(std::time::Duration::from_secs(60))?;

    let tx = conn.transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
    modifications(&tx)?;
    tx.commit()?;

    Ok(())
}

// Internal helper for queries boilerplate
fn db_query<'a, P, F, T>(
    path: &path::Path,
    stmt_str: &'a str,
    params: P,
    f: F,
) -> Result<Vec<T>, DatabaseError>
where
    P: rusqlite::Params,
    F: FnMut(&rusqlite::Row<'_>) -> rusqlite::Result<T>,
{
    let conn = rusqlite::Connection::open(path)?;

    conn.busy_timeout(std::time::Duration::from_secs(60))?;

    // rustc says 'borrowed value does not live long enough'
    let x = conn
        .prepare(stmt_str)?
        .query_map(params, f)?
        .collect::<rusqlite::Result<Vec<T>>>()?;

    Ok(x)
}

fn db_version(db_path: &path::Path) -> Result<u32, DatabaseError> {
    let mut rows = db_query(db_path, "SELECT version FROM version", [], |row| {
        row.get::<_, u32>(0)
    })?;

    Ok(rows.pop().expect("No row in version table?"))
}

/// Get the "metadata" entry from the DB
pub fn db_instance(db_path: &path::Path) -> Result<DbInstance, DatabaseError> {
    let mut rows: Vec<DbInstance> =
        db_query(db_path, "SELECT * FROM instances", [], |row| row.try_into())?;

    Ok(rows.pop().expect("No row in instances table?"))
}

/// Register a new vault to be watched. Atomically inserts the vault and the Emergency signatures.
fn db_new_vault(
    db_path: &path::Path,
    deposit_outpoint: &OutPoint,
    derivation_index: bip32::ChildNumber,
    amount: Amount,
    emer_sigs: &[(secp256k1::PublicKey, secp256k1::Signature)],
) -> Result<(), DatabaseError> {
    let instance_id = db_instance(db_path)?.id;
    let deposit_txid = deposit_outpoint.txid.to_vec();
    let deposit_vout = deposit_outpoint.vout;
    let deriv_index: u32 = derivation_index.into();
    let amount = amount_to_i64(&amount);

    assert!(
        emer_sigs.len() > 0,
        "Registering a vault without Emergency signature"
    );

    db_exec(db_path, |db_tx| {
        db_tx.execute(
            "INSERT INTO vaults (instance_id, deposit_txid, deposit_vout, derivation_index, amount, delegated)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            params![instance_id, deposit_txid, deposit_vout, deriv_index, amount, false],
        )?;

        let vault_id = db_tx.last_insert_rowid();
        for (key, sig) in emer_sigs {
            db_tx.execute(
                "INSERT INTO signatures (vault_id, tx_type, pubkey, signature) VALUES (?1, ?2, ?3, ?4)",
                params![
                    vault_id,
                    SigTxType::Emergency as i64,
                    key.serialize().to_vec(),
                    sig.serialize_der().to_vec()
                ],
            )?;
        }

        Ok(())
    })
}

/// Mark a vault as being delegated, storing the signatures of its second-stage transactions
fn db_delegate_vault(
    db_path: &path::Path,
    deposit_outpoint: &OutPoint,
    unemer_sigs: &[(secp256k1::PublicKey, secp256k1::Signature)],
    cancel_sigs: &[(secp256k1::PublicKey, secp256k1::Signature)],
) -> Result<(), DatabaseError> {
    let db_vault = db_vault(db_path, deposit_outpoint)?
        .ok_or_else(|| DatabaseError::UnknownVault(Box::new(*deposit_outpoint)))?;

    assert!(
        unemer_sigs.len() > 0,
        "Registering a vault without UnvaultEmergency signature"
    );
    assert!(
        cancel_sigs.len() > 0,
        "Registering a vault without Cancel signature"
    );

    db_exec(db_path, |db_tx| {
        db_tx.execute(
            "UPDATE vaults SET delegated = 1 WHERE id = (?1)",
            params![db_vault.id],
        )?;

        for (key, sig) in unemer_sigs {
            db_tx.execute(
                "INSERT INTO signatures (vault_id, tx_type, pubkey, signature) VALUES (?1, ?2, ?3, ?4)",
                params![
                    db_vault.id,
                    SigTxType::UnvaultEmergency as i64,
                    key.serialize().to_vec(),
                    sig.serialize_der().to_vec()
                ],
            )?;
        }
        for (key, sig) in cancel_sigs {
            db_tx.execute(
                "INSERT INTO signatures (vault_id, tx_type, pubkey, signature) VALUES (?1, ?2, ?3, ?4)",
                params![
                    db_vault.id,
                    SigTxType::Cancel as i64,
                    key.serialize().to_vec(),
                    sig.serialize_der().to_vec()
                ],
            )?;
        }

        Ok(())
    })
}

/// Mark a vault as needing to be canceled
pub fn db_should_cancel_vault(db_path: &path::Path, vault_id: i64) -> Result<(), DatabaseError> {
    db_exec(&db_path, |db_tx| {
        db_tx.execute(
            "UPDATE vaults SET should_cancel = 1 WHERE id = (?1)",
            params![vault_id],
        )?;

        Ok(())
    })
}

/// Mark a vault as should not cancel
pub fn db_should_not_cancel_vault(
    db_path: &path::Path,
    vault_id: i64,
) -> Result<(), DatabaseError> {
    db_exec(&db_path, |db_tx| {
        db_tx.execute(
            "UPDATE vaults SET should_cancel = 0 WHERE id = (?1)",
            params![vault_id],
        )?;

        Ok(())
    })
}

/// Remove a vault from the database by its id
fn db_del_vault(db_path: &path::Path, vault_id: i64) -> Result<(), DatabaseError> {
    db_exec(db_path, |db_tx| {
        db_tx.execute(
            "DELETE FROM signatures WHERE vault_id = (?1)",
            params![vault_id],
        )?;
        db_tx.execute("DELETE FROM vaults WHERE id = (?1)", params![vault_id])?;

        Ok(())
    })
}

/// Get a list of all vaults in the database
fn db_vaults(db_path: &path::Path) -> Result<Vec<DbVault>, DatabaseError> {
    db_query(db_path, "SELECT * FROM vaults", [], |row| row.try_into())
}

/// Get a vault in the database by its deposit outpoint
fn db_vault(
    db_path: &path::Path,
    deposit_outpoint: &OutPoint,
) -> Result<Option<DbVault>, DatabaseError> {
    let deposit_txid = deposit_outpoint.txid.to_vec();
    let deposit_vout = deposit_outpoint.vout;

    db_query(
        db_path,
        "SELECT * FROM vaults WHERE deposit_txid = (?1) AND deposit_vout = (?2)",
        params![deposit_txid, deposit_vout],
        |row| row.try_into(),
    )
    .map(|mut rows| rows.pop())
}

/// Get a list of all vaults we need to watch Unvault broadcast for that weren't yet both
/// unvaulted and taken a decision for.
pub fn db_delegated_vaults(db_path: &path::Path) -> Result<Vec<DbVault>, DatabaseError> {
    db_query(
        db_path,
        "SELECT * FROM vaults WHERE delegated = 1 AND should_cancel is NULL",
        [],
        |row| row.try_into(),
    )
}

// Internal helper for signature query boilerplate
fn db_sigs_by_type(
    db_path: &path::Path,
    vault_id: i64,
    tx_type: SigTxType,
) -> Result<Vec<DbSignature>, DatabaseError> {
    db_query(
        db_path,
        "SELECT * FROM signatures WHERE vault_id = (?1) AND tx_type = (?2)",
        params![vault_id, tx_type as i64],
        |row| row.try_into(),
    )
}

/// Get all the Emergency signatures of this vault
fn db_emergency_signatures(
    db_path: &path::Path,
    vault_id: i64,
) -> Result<Vec<DbSignature>, DatabaseError> {
    db_sigs_by_type(db_path, vault_id, SigTxType::Emergency)
}

/// Get all the UnvaultEmergency signatures of this vault
fn db_unvault_emergency_signatures(
    db_path: &path::Path,
    vault_id: i64,
) -> Result<Vec<DbSignature>, DatabaseError> {
    db_sigs_by_type(db_path, vault_id, SigTxType::UnvaultEmergency)
}

/// Get all the Cancel signatures of this vault
pub fn db_cancel_signatures(
    db_path: &path::Path,
    vault_id: i64,
) -> Result<Vec<DbSignature>, DatabaseError> {
    db_sigs_by_type(db_path, vault_id, SigTxType::Cancel)
}

// Create the db file with RW permissions only for the user
fn create_db_file(db_path: &path::Path) -> Result<(), DatabaseError> {
    let mut options = fs::OpenOptions::new();
    options
        .read(true)
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(db_path)?;

    Ok(())
}

fn create_db(
    db_path: &path::Path,
    deposit_descriptor: &DepositDescriptor,
    unvault_descriptor: &UnvaultDescriptor,
    cpfp_descriptor: &CpfpDescriptor,
    network: Network,
) -> Result<(), DatabaseError> {
    let timestamp = time::SystemTime::now()
        .duration_since(time::UNIX_EPOCH)
        .map(|dur| timestamp_to_u32(dur.as_secs()))
        .expect("Computing time since expoch");

    // Rusqlite could create it for us, but we want custom permissions
    create_db_file(&db_path)?;

    db_exec(&db_path, |tx| {
        tx.execute_batch(&SCHEMA)?;
        tx.execute(
            "INSERT INTO version (version) VALUES (?1)",
            params![DB_VERSION],
        )?;
        tx.execute(
            "INSERT INTO instances (creation_timestamp, deposit_descriptor, unvault_descriptor,\
            cpfp_descriptor, network, tip_blockheight, tip_blockhash) \
            VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
            params![
                timestamp,
                deposit_descriptor.to_string(),
                unvault_descriptor.to_string(),
                cpfp_descriptor.to_string(),
                network.to_string(),
                0,
                vec![0u8; 32],
            ],
        )?;

        Ok(())
    })
}

// Called at startup to check database integrity
fn check_db(
    db_path: &path::Path,
    deposit_descriptor: &DepositDescriptor,
    unvault_descriptor: &UnvaultDescriptor,
    cpfp_descriptor: &CpfpDescriptor,
    network: Network,
) -> Result<(), DatabaseError> {
    // Check if their database is not from the future.
    // We'll eventually do migration here if version < VERSION, but be strict until then.
    let version = db_version(&db_path)?;
    if version != DB_VERSION {
        return Err(DatabaseError::InvalidVersion(version));
    }

    let instance = db_instance(&db_path)?;

    // Then that we are on the right network..
    if instance.network != network {
        return Err(DatabaseError::InvalidNetwork(network));
    }

    // .. And managing the same Scripts!
    if &instance.deposit_descriptor != deposit_descriptor {
        return Err(DatabaseError::DescriptorMismatch(
            instance.deposit_descriptor.to_string(),
            deposit_descriptor.to_string(),
        ));
    }
    if &instance.unvault_descriptor != unvault_descriptor {
        return Err(DatabaseError::DescriptorMismatch(
            instance.unvault_descriptor.to_string(),
            unvault_descriptor.to_string(),
        ));
    }
    if &instance.cpfp_descriptor != cpfp_descriptor {
        return Err(DatabaseError::DescriptorMismatch(
            instance.cpfp_descriptor.to_string(),
            cpfp_descriptor.to_string(),
        ));
    }

    Ok(())
}

/// Create the database if it doesn't exist already, then sanity check it.
pub fn setup_db(
    db_path: &path::Path,
    deposit_descriptor: &DepositDescriptor,
    unvault_descriptor: &UnvaultDescriptor,
    cpfp_descriptor: &CpfpDescriptor,
    network: Network,
) -> Result<(), DatabaseError> {
    if !db_path.exists() {
        log::info!("No database at {:?}, creating a new one.", db_path);
        create_db(
            db_path,
            deposit_descriptor,
            unvault_descriptor,
            cpfp_descriptor,
            network,
        )?;
    }

    check_db(
        db_path,
        deposit_descriptor,
        unvault_descriptor,
        cpfp_descriptor,
        network,
    )?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use std::{fs, os::unix::fs::PermissionsExt, path, str::FromStr, thread};

    use super::*;

    // Create a dummy database and return its path (to be deleted by the caller)
    fn get_db() -> path::PathBuf {
        let db_path: path::PathBuf =
            format!("scratch_test_{:?}.sqlite3", thread::current().id()).into();
        let deposit_desc = DepositDescriptor::from_str("wsh(multi(2,xpub6AHA9hZDN11k2ijHMeS5QqHx2KP9aMBRhTDqANMnwVtdyw2TDYRmF8PjpvwUFcL1Et8Hj59S3gTSMcUQ5gAqTz3Wd8EsMTmF3DChhqPQBnU/*,xpub6AaffFGfH6WXfm6pwWzmUMuECQnoLeB3agMKaLyEBZ5ZVfwtnS5VJKqXBt8o5ooCWVy2H87GsZshp7DeKE25eWLyd1Ccuh2ZubQUkgpiVux/*))#n3cj9mhy").unwrap();
        let unvault_desc = UnvaultDescriptor::from_str("wsh(andor(thresh(1,pk(xpub6BaZSKgpaVvibu2k78QsqeDWXp92xLHZxiu1WoqLB9hKhsBf3miBUDX7PJLgSPvkj66ThVHTqdnbXpeu8crXFmDUd4HeM4s4miQS2xsv3Qb/*)),and_v(v:multi(2,03b506a1dbe57b4bf48c95e0c7d417b87dd3b4349d290d2e7e9ba72c912652d80a,0295e7f5d12a2061f1fd2286cefec592dff656a19f55f4f01305d6aa56630880ce),older(2)),thresh(2,pkh(xpub6AHA9hZDN11k2ijHMeS5QqHx2KP9aMBRhTDqANMnwVtdyw2TDYRmF8PjpvwUFcL1Et8Hj59S3gTSMcUQ5gAqTz3Wd8EsMTmF3DChhqPQBnU/*),a:pkh(xpub6AaffFGfH6WXfm6pwWzmUMuECQnoLeB3agMKaLyEBZ5ZVfwtnS5VJKqXBt8o5ooCWVy2H87GsZshp7DeKE25eWLyd1Ccuh2ZubQUkgpiVux/*))))#2vtuzh02").unwrap();
        let cpfp_desc = CpfpDescriptor::from_str("wsh(thresh(1,pk(xpub6BaZSKgpaVvibu2k78QsqeDWXp92xLHZxiu1WoqLB9hKhsBf3miBUDX7PJLgSPvkj66ThVHTqdnbXpeu8crXFmDUd4HeM4s4miQS2xsv3Qb/*)))#cwycq5xu").unwrap();

        // Remove any potential leftover from a previous crashed session
        fs::remove_file(&db_path).unwrap_or_else(|_| ());

        setup_db(
            &db_path,
            &deposit_desc,
            &unvault_desc,
            &cpfp_desc,
            Network::Bitcoin,
        )
        .unwrap();

        db_path
    }

    #[test]
    fn db_setup() {
        let db_path: path::PathBuf =
            format!("scratch_test_{:?}.sqlite3", thread::current().id()).into();
        let deposit_desc = DepositDescriptor::from_str("wsh(multi(2,xpub6AHA9hZDN11k2ijHMeS5QqHx2KP9aMBRhTDqANMnwVtdyw2TDYRmF8PjpvwUFcL1Et8Hj59S3gTSMcUQ5gAqTz3Wd8EsMTmF3DChhqPQBnU/*,xpub6AaffFGfH6WXfm6pwWzmUMuECQnoLeB3agMKaLyEBZ5ZVfwtnS5VJKqXBt8o5ooCWVy2H87GsZshp7DeKE25eWLyd1Ccuh2ZubQUkgpiVux/*))#n3cj9mhy").unwrap();
        let unvault_desc = UnvaultDescriptor::from_str("wsh(andor(thresh(1,pk(xpub6BaZSKgpaVvibu2k78QsqeDWXp92xLHZxiu1WoqLB9hKhsBf3miBUDX7PJLgSPvkj66ThVHTqdnbXpeu8crXFmDUd4HeM4s4miQS2xsv3Qb/*)),and_v(v:multi(2,03b506a1dbe57b4bf48c95e0c7d417b87dd3b4349d290d2e7e9ba72c912652d80a,0295e7f5d12a2061f1fd2286cefec592dff656a19f55f4f01305d6aa56630880ce),older(2)),thresh(2,pkh(xpub6AHA9hZDN11k2ijHMeS5QqHx2KP9aMBRhTDqANMnwVtdyw2TDYRmF8PjpvwUFcL1Et8Hj59S3gTSMcUQ5gAqTz3Wd8EsMTmF3DChhqPQBnU/*),a:pkh(xpub6AaffFGfH6WXfm6pwWzmUMuECQnoLeB3agMKaLyEBZ5ZVfwtnS5VJKqXBt8o5ooCWVy2H87GsZshp7DeKE25eWLyd1Ccuh2ZubQUkgpiVux/*))))#2vtuzh02").unwrap();
        let cpfp_desc = CpfpDescriptor::from_str("wsh(thresh(1,pk(xpub6BaZSKgpaVvibu2k78QsqeDWXp92xLHZxiu1WoqLB9hKhsBf3miBUDX7PJLgSPvkj66ThVHTqdnbXpeu8crXFmDUd4HeM4s4miQS2xsv3Qb/*)))#cwycq5xu").unwrap();

        let sec_deposit_desc = DepositDescriptor::from_str("wsh(multi(4,xpub6CFH8m3bnUFXWXxKVQjMXqMiQWYRhcTeZCW1QghmkNeGkPFwADfFNt9JMuW38MnYVSAV9eyqJ3A61kbsfC5PSCdkZWi7pD2L4jv6edaPxKp/*,xpub6FEZyiJxqwu7zkqqVGXVbGhcAj1L5imn55VVa4Mk5WE46xdAKgD4uSR9ems9EehAApZPVXFrxcLQ7zPqYywu1z4Cjhesyp7HeRSgSdUq1BB/*,xpub6CFH8m3bnUFXa6UB8KhTMTPDz3cNQ9wAsQ9fGM52WZ1jBenPtf1GED6fJoDmpEYQQkk3VUHFN5ZRDLV7SRgX4M8KMTpRTH9zGRzg5udqwwo/*,xpub6ETaaosT68a6mxPp1dRh1yeGjMZonsZMxA1SA95iqKWDcQUXxQPYFyottUR58E8qjjnAwPcEtYS9iejkERbnGuNqfF2wgToLcxzf97FHevs/*))#gu0vtd0k").unwrap();
        let sec_unvault_desc = UnvaultDescriptor::from_str("wsh(andor(multi(2,xpub6CFH8m3bnUFXvS78XZyCQ9mCbp7XmKXbS67YHGUS3NxHSLhAMCGHGaEPojcoYt5PYnocyuScAM5xuDzf4BqFQt3fhmKEaRgmVzDcAR46Byh/*,xpub6ECZqYNQzHkveSWmsGh6XSL8wMGXRtoZ5hkbWXwRSVEyEsKADe34dbdnMob1ZjUpd4TD7no1isnnvpQq9DchFes5DnHJ7JupSntZsKr7VbQ/*),and_v(v:multi(4,02644cf9e2b78feb0a751e50502f530a4cbd0bbda3020779605391e71654dd66c2,03ced55d1208bd8c6b42b11e29baa577711cae831b3a1296607c5e5d3ed365f49c,026237f655f3bf45fd6b7aa00e91c2603d6155f1cc001e40f5e47662d965c4c779,030a3cbcfbfdf7122fe7fa830354c956ea6595f2dbde23286f03bc1ec0c1685ca3),older(18)),thresh(4,pkh(xpub6CFH8m3bnUFXWXxKVQjMXqMiQWYRhcTeZCW1QghmkNeGkPFwADfFNt9JMuW38MnYVSAV9eyqJ3A61kbsfC5PSCdkZWi7pD2L4jv6edaPxKp/*),a:pkh(xpub6FEZyiJxqwu7zkqqVGXVbGhcAj1L5imn55VVa4Mk5WE46xdAKgD4uSR9ems9EehAApZPVXFrxcLQ7zPqYywu1z4Cjhesyp7HeRSgSdUq1BB/*),a:pkh(xpub6CFH8m3bnUFXa6UB8KhTMTPDz3cNQ9wAsQ9fGM52WZ1jBenPtf1GED6fJoDmpEYQQkk3VUHFN5ZRDLV7SRgX4M8KMTpRTH9zGRzg5udqwwo/*),a:pkh(xpub6ETaaosT68a6mxPp1dRh1yeGjMZonsZMxA1SA95iqKWDcQUXxQPYFyottUR58E8qjjnAwPcEtYS9iejkERbnGuNqfF2wgToLcxzf97FHevs/*))))#rzut3gm7").unwrap();
        let sec_cpfp_desc = CpfpDescriptor::from_str("wsh(multi(1,xpub6BhQvtXJmw6hi2ALFeWMi9m7G8rGterJnMTNRqUm29uvB6dVTELvnEs7hfxyN3JM48FR2oh4t8chsvw7bRRRukkyhqp9WZD4oB9UvxAMpqC/*,xpub6BhQvtXJmw6hksh9rRRfdLjaWjQiNMZWtkM5ebn8QkAgh5na2Un6mCDABwkUmHhPCMYtsM9zHY5jxbQ86ayvjfY8XtavbovB6NcNy8KyQLa/*))#4s76hpqg").unwrap();

        // Remove any potential leftover from a crashed instance
        fs::remove_file(&db_path).unwrap_or_else(|_| ());

        // The first call will create the DB file
        setup_db(
            &db_path,
            &deposit_desc,
            &unvault_desc,
            &cpfp_desc,
            Network::Bitcoin,
        )
        .unwrap();
        assert_eq!(
            fs::File::open(&db_path)
                .unwrap()
                .metadata()
                .unwrap()
                .permissions()
                .mode()
                // Mask cause we'll have the filetype too which we don't care about.
                & 0o777,
            0o600
        );

        // The second call will only check the DB, and should pass as we didn't mess up with it
        setup_db(
            &db_path,
            &deposit_desc,
            &unvault_desc,
            &cpfp_desc,
            Network::Bitcoin,
        )
        .unwrap();

        // If we try to use this DB on a different network, it'll fail.
        assert!(setup_db(
            &db_path,
            &deposit_desc,
            &unvault_desc,
            &cpfp_desc,
            Network::Signet,
        )
        .unwrap_err()
        .to_string()
        .contains("Invalid network"));

        // If any of the descriptor changed since DB creation, it'll fail.
        assert!(setup_db(
            &db_path,
            &sec_deposit_desc,
            &unvault_desc,
            &cpfp_desc,
            Network::Bitcoin,
        )
        .unwrap_err()
        .to_string()
        .contains("Descriptor mismatch"));
        assert!(setup_db(
            &db_path,
            &deposit_desc,
            &sec_unvault_desc,
            &cpfp_desc,
            Network::Bitcoin,
        )
        .unwrap_err()
        .to_string()
        .contains("Descriptor mismatch"));
        assert!(setup_db(
            &db_path,
            &deposit_desc,
            &unvault_desc,
            &sec_cpfp_desc,
            Network::Bitcoin,
        )
        .unwrap_err()
        .to_string()
        .contains("Descriptor mismatch"));

        // It will have stored the current DB version and will refuse to open a DB from
        // the future
        assert_eq!(db_version(&db_path).unwrap(), 0);
        db_exec(&db_path, |tx| {
            tx.execute("UPDATE version SET version = (?1)", params![DB_VERSION + 1])
                .unwrap();
            Ok(())
        })
        .unwrap();
        assert!(setup_db(
            &db_path,
            &deposit_desc,
            &unvault_desc,
            &cpfp_desc,
            Network::Bitcoin,
        )
        .unwrap_err()
        .to_string()
        .contains("Invalid database version"));

        // Cleanup
        fs::remove_file(&db_path).unwrap();
    }

    macro_rules! dummy_sig {
        ($sig:expr) => {
            (
                secp256k1::PublicKey::from_str(
                    "0279d1f38c1c80d47cb00ddbbe2915a60d5706e1ef66056a169150f083b288eb95",
                )
                .unwrap(),
                $sig,
            )
        };
    }

    // Sanity check we can create, delegate and delete a vault
    #[test]
    fn db_vault_creation() {
        let db_path = get_db();
        let outpoint_a = OutPoint::from_str(
            "5bebdb97b54e2268b3fccd4aeea99419d87a92f88f27e906ceea5e863946a731:0",
        )
        .unwrap();
        let deriv_a = bip32::ChildNumber::from(32);
        let amount_a = Amount::from_sat(i64::MAX as u64 - 100_000);
        let emer_sigs_a = [
            dummy_sig!(secp256k1::Signature::from_str("304402200b4025e855ac108cf4f5114c3a8af9f8122023ffa971c5de8a8bc3f67d18749902202cc9b7d36f57dbe70f8826fac13838c6757fe18fb4572328c76dd5b55e452528").unwrap()),
            dummy_sig!(secp256k1::Signature::from_str("3045022100cc110b2dc66b9a116f50c61548d33f589d00ef57fb2fa784100ffb84e1577faf02206eec4e600f76f347b2014752a3619df8b2406fa61a34f0ec01ce4900f0b22083").unwrap())
        ];
        let unemer_sigs_a = [
            dummy_sig!(secp256k1::Signature::from_str("30450221008f4abfaa7c22adbf621e46f520fea81779b4fce81c22889354f8044336a542ff02205b5bf7c7a677414fdf20f5192c51f0fd34a8447b709a5d0f7df6e6c8d5dfbeff").unwrap()),
            dummy_sig!(secp256k1::Signature::from_str("3045022100a1da27080b26a6a328a26dfe0c076931ea5e22ad06e31b867a2ccd11d57e912102203ccb9388e104e13a81bc02c700d214278541ff8da67f27359b7bbb0e6eea6a41").unwrap())
        ];
        let cancel_sigs_a = [
            dummy_sig!(secp256k1::Signature::from_str("304502210089a1b4a09cafb8f26d6355c5ad51c686d8796d3a833945de35687085b1cd048e022068f6ac3fd4d3909f5d3cf93b0cf6538edfbafdd0b36d858c073e4b9b4137a027").unwrap()),
            dummy_sig!(secp256k1::Signature::from_str("3044022009334cec178a66aef6a473fc9d7608cc2b53495d433920262ba50e8a2947bba202207a0eb002ebe2fc0774adbe9b28885d00758d3043497aae414884bbc8cf7c84dc").unwrap()),
        ];
        let outpoint_b = OutPoint::from_str(
            "69a747cd1ea7ce4904e6173b06a4a83e0df173661046e70f5128b3c9bef8241d:18",
        )
        .unwrap();
        let deriv_b = bip32::ChildNumber::from((1 << 31) - 1);
        let amount_b = Amount::from_sat(1298766);
        let emer_sigs_b = [
            dummy_sig!(secp256k1::Signature::from_str("304402207d1d99b6164597cee75baa0de60d4988f298fbc1857ca67102996287d8ccc76402207d9a2997a79c895d34d9bc450219b988d40cc2054f25a9a4e582666b96dc2444").unwrap()),
            dummy_sig!(secp256k1::Signature::from_str("3044022031c4547c4f3688b02ff749c6830579318d4ba24bb832dffff5156b2bb751480c022060f6745664612b70e8acb3db3e00af60952bda853891edc6d98a83825e92aeb6").unwrap())
        ];
        let unemer_sigs_b = [
            dummy_sig!(secp256k1::Signature::from_str("30450221009c93c095d2d8cb7f7918bc6b43de451f146eec07d8569a77eed2d14d25fafee50220656328e7e74953c82c4af62fd809bea903de1d9b92de8f4d02450f5d9a2d02ab").unwrap()),
            dummy_sig!(secp256k1::Signature::from_str("3045022100ca96469270b45e4be24c70115de4545b975c27b60c007b4668cc6edb97944ee302203a078a1cd7d36c6293635dc9604bb7ced31d5a98c8a01a2f7fb2da533245d074").unwrap())
        ];
        let cancel_sigs_b = [
            dummy_sig!(secp256k1::Signature::from_str("304402207e17f075edacc44be94263caa38e0b94dcffd65f2e76159def578d61dd82cbbe02202f300241721dfa8334cc8835d422e8928a7a87301be094e8c296ecdf945c9d71").unwrap()),
            dummy_sig!(secp256k1::Signature::from_str("30440220398b5d0a75911f69c37c71e929727d16bf48a6b6cc46b1db0d6097f91eb7ecfa0220379c43fc3db9b70b2d3d5d945f8d51ae2660bdedd94b8468abb92c7f2c1989a8").unwrap()),
        ];

        // We can insert and query no-yet-delegated vaults
        db_new_vault(&db_path, &outpoint_a, deriv_a, amount_a, &emer_sigs_a).unwrap();
        assert_eq!(
            db_vault(&db_path, &outpoint_a).unwrap().unwrap(),
            DbVault {
                id: 1,
                instance_id: 1,
                deposit_outpoint: outpoint_a,
                derivation_index: deriv_a,
                amount: amount_a,
                delegated: false,
                should_cancel: None,
            }
        );
        assert_eq!(
            db_vault(&db_path, &outpoint_a).unwrap().unwrap(),
            db_vaults(&db_path).unwrap()[0]
        );
        db_new_vault(&db_path, &outpoint_b, deriv_b, amount_b, &emer_sigs_b).unwrap();
        assert_eq!(
            db_vault(&db_path, &outpoint_b).unwrap().unwrap(),
            DbVault {
                id: 2,
                instance_id: 1,
                deposit_outpoint: outpoint_b,
                derivation_index: deriv_b,
                amount: amount_b,
                delegated: false,
                should_cancel: None,
            }
        );
        assert_eq!(
            vec![
                db_vault(&db_path, &outpoint_a).unwrap().unwrap(),
                db_vault(&db_path, &outpoint_b).unwrap().unwrap(),
            ],
            db_vaults(&db_path).unwrap()
        );
        assert!(db_delegated_vaults(&db_path).unwrap().is_empty());

        // We can get the Emergency signatures for these vaults now
        assert_eq!(
            db_emergency_signatures(&db_path, 1)
                .unwrap()
                .into_iter()
                .map(|db_sig| (db_sig.pubkey, db_sig.signature))
                .collect::<Vec<(secp256k1::PublicKey, secp256k1::Signature)>>(),
            emer_sigs_a.to_vec()
        );
        assert_eq!(
            db_emergency_signatures(&db_path, 2)
                .unwrap()
                .into_iter()
                .map(|db_sig| (db_sig.pubkey, db_sig.signature))
                .collect::<Vec<(secp256k1::PublicKey, secp256k1::Signature)>>(),
            emer_sigs_b.to_vec()
        );

        // We can't insert a vault twice
        db_new_vault(&db_path, &outpoint_a, deriv_a, amount_a, &emer_sigs_a).unwrap_err();

        // Querying a random outpoint will return None
        let uk_outpoint = OutPoint::from_str(
            "69a747cd1ea7ce4904e6173b06a4a83e0df173661046e70f5128b3c9bef8241d:1",
        )
        .unwrap();
        assert!(db_vault(&db_path, &uk_outpoint).unwrap().is_none());

        // We can delegate the vaults, they'll be marked as such
        db_delegate_vault(&db_path, &outpoint_a, &unemer_sigs_a, &cancel_sigs_a).unwrap();
        assert_eq!(
            db_vault(&db_path, &outpoint_a).unwrap().unwrap(),
            DbVault {
                id: 1,
                instance_id: 1,
                deposit_outpoint: outpoint_a,
                derivation_index: deriv_a,
                amount: amount_a,
                delegated: true,
                should_cancel: None,
            }
        );
        db_delegate_vault(&db_path, &outpoint_b, &unemer_sigs_b, &cancel_sigs_b).unwrap();
        assert_eq!(
            db_vault(&db_path, &outpoint_b).unwrap().unwrap(),
            DbVault {
                id: 2,
                instance_id: 1,
                deposit_outpoint: outpoint_b,
                derivation_index: deriv_b,
                amount: amount_b,
                delegated: true,
                should_cancel: None,
            }
        );
        assert_eq!(
            db_delegated_vaults(&db_path).unwrap(),
            db_vaults(&db_path).unwrap()
        );

        // We can get the signatures of the second-stage transactions for these vaults now
        assert_eq!(
            db_unvault_emergency_signatures(&db_path, 1)
                .unwrap()
                .into_iter()
                .map(|db_sig| (db_sig.pubkey, db_sig.signature))
                .collect::<Vec<(secp256k1::PublicKey, secp256k1::Signature)>>(),
            unemer_sigs_a.to_vec()
        );
        assert_eq!(
            db_cancel_signatures(&db_path, 1)
                .unwrap()
                .into_iter()
                .map(|db_sig| (db_sig.pubkey, db_sig.signature))
                .collect::<Vec<(secp256k1::PublicKey, secp256k1::Signature)>>(),
            cancel_sigs_a.to_vec()
        );
        assert_eq!(
            db_unvault_emergency_signatures(&db_path, 2)
                .unwrap()
                .into_iter()
                .map(|db_sig| (db_sig.pubkey, db_sig.signature))
                .collect::<Vec<(secp256k1::PublicKey, secp256k1::Signature)>>(),
            unemer_sigs_b.to_vec()
        );
        assert_eq!(
            db_cancel_signatures(&db_path, 2)
                .unwrap()
                .into_iter()
                .map(|db_sig| (db_sig.pubkey, db_sig.signature))
                .collect::<Vec<(secp256k1::PublicKey, secp256k1::Signature)>>(),
            cancel_sigs_b.to_vec()
        );

        // And if we mark them as either 'to cancel' or 'to let go through', they won't be
        // returned by db_delegated_vaults
        db_should_cancel_vault(&db_path, 1).unwrap();
        assert_eq!(
            db_delegated_vaults(&db_path).unwrap(),
            vec![DbVault {
                id: 2,
                instance_id: 1,
                deposit_outpoint: outpoint_b,
                derivation_index: deriv_b,
                amount: amount_b,
                delegated: true,
                should_cancel: None,
            }]
        );
        db_should_not_cancel_vault(&db_path, 2).unwrap();
        assert_eq!(db_delegated_vaults(&db_path).unwrap(), vec![]);

        // And we can delete them
        assert_eq!(db_vaults(&db_path).unwrap().len(), 2);
        db_del_vault(&db_path, 2).unwrap();
        assert_eq!(db_vaults(&db_path).unwrap().len(), 1);
        db_del_vault(&db_path, 1).unwrap();
        assert!(db_vaults(&db_path).unwrap().is_empty());

        // This deleted the sigs too (or the constraint would have failed anyways but hey)
        assert!(db_emergency_signatures(&db_path, 1).unwrap().is_empty());
        assert!(db_unvault_emergency_signatures(&db_path, 1)
            .unwrap()
            .is_empty());
        assert!(db_cancel_signatures(&db_path, 1).unwrap().is_empty());

        assert!(db_emergency_signatures(&db_path, 2).unwrap().is_empty());
        assert!(db_unvault_emergency_signatures(&db_path, 2)
            .unwrap()
            .is_empty());
        assert!(db_cancel_signatures(&db_path, 2).unwrap().is_empty());

        // Cleanup
        fs::remove_file(&db_path).unwrap();
    }
}
