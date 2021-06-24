mod schema;

use revault_tx::{
    bitcoin::Network,
    scripts::{CpfpDescriptor, DepositDescriptor, UnvaultDescriptor},
};
use schema::{DbInstance, SCHEMA};

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

// Sqlite supports up to i64, thus rusqlite prevents us from inserting u64's.
// We use this to panic rather than inserting a truncated integer into the database (as we'd have
// done by using `n as u32`).
fn timestamp_to_u32(n: u64) -> u32 {
    n.try_into()
        .expect("Is this the year 2106 yet? Misconfigured system clock.")
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
}
