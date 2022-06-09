use crate::{
    bitcoind::{
        interface::{BitcoinD, ChainTip},
        BitcoindError,
    },
    config::Config,
    database::{
        db_blank_vaults, db_cancel_signatures, db_del_vault, db_instance, db_should_cancel_vault,
        db_should_not_cancel_vault, db_unvault_spender_confirmed, db_unvaulted_vaults,
        db_update_tip, db_vault, schema::DbVault, DatabaseError,
    },
    plugins::{NewBlockInfo, VaultInfo},
};
use revault_tx::{
    bitcoin::{consensus::encode, secp256k1, Amount, OutPoint},
    scripts::{DerivedCpfpDescriptor, DerivedDepositDescriptor, DerivedUnvaultDescriptor},
    transactions::{
        CancelTransaction, RevaultPresignedTransaction, RevaultTransaction, UnvaultTransaction,
    },
    txins::{DepositTxIn, RevaultTxIn, UnvaultTxIn},
    txouts::DepositTxOut,
};

use revault_net::noise::SecretKey as NoisePrivkey;

use std::{collections::HashMap, convert::TryInto, path, thread};

use crate::coordinator;

/// How many blocks are we waiting to consider a consumed vault irreversably spent
const REORG_WATCH_LIMIT: i32 = 288;

/// An error happened in the main loop
#[derive(Debug)]
pub enum PollerError {
    TipChanged,
    Database(DatabaseError),
    Bitcoind(BitcoindError),
}

impl std::fmt::Display for PollerError {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self {
            Self::Database(ref e) => write!(f, "Database error in main loop: '{}'", e),
            Self::Bitcoind(ref e) => write!(f, "Bitcoind error in main loop: '{}'", e),
            Self::TipChanged => write!(
                f,
                "The bitcoind best tip changed while we were processing the new block"
            ),
        }
    }
}

impl std::error::Error for PollerError {}

impl From<BitcoindError> for PollerError {
    fn from(e: BitcoindError) -> Self {
        Self::Bitcoind(e)
    }
}

impl From<DatabaseError> for PollerError {
    fn from(e: DatabaseError) -> Self {
        Self::Database(e)
    }
}

fn descriptors(
    secp: &secp256k1::Secp256k1<impl secp256k1::Verification>,
    config: &Config,
    db_vault: &DbVault,
) -> (
    DerivedDepositDescriptor,
    DerivedUnvaultDescriptor,
    DerivedCpfpDescriptor,
) {
    (
        config
            .scripts_config
            .deposit_descriptor
            .derive(db_vault.derivation_index, secp),
        config
            .scripts_config
            .unvault_descriptor
            .derive(db_vault.derivation_index, secp),
        config
            .scripts_config
            .cpfp_descriptor
            .derive(db_vault.derivation_index, secp),
    )
}

fn unvault_tx(
    db_vault: &DbVault,
    deposit_desc: &DerivedDepositDescriptor,
    unvault_desc: &DerivedUnvaultDescriptor,
    cpfp_desc: &DerivedCpfpDescriptor,
) -> Result<UnvaultTransaction, revault_tx::error::TransactionCreationError> {
    let deposit_txo = DepositTxOut::new(db_vault.amount, deposit_desc);
    let deposit_txin = DepositTxIn::new(db_vault.deposit_outpoint, deposit_txo);
    UnvaultTransaction::new(deposit_txin, &unvault_desc, &cpfp_desc)
}

// The database updates we cache to avoid partial write in case the chain tip moved
#[derive(Default, Debug)]
struct DbUpdates {
    // vault_id, unvault_height
    pub should_cancel: Vec<(i64, i32)>,
    // vault_id -> DbVault
    pub new_unvaulted: HashMap<i64, DbVault>,
    // vault_id
    pub to_be_deleted: Vec<i64>,
    // vault_id, confirmed height
    pub spender_confirmed: Vec<(i64, i32)>,
}

impl DbUpdates {
    // Write the cached DB updates to the specified database. Move out so we never write twice.
    pub fn write(self, db_path: &path::Path) -> Result<(), DatabaseError> {
        for (_, vault) in self.new_unvaulted {
            db_should_not_cancel_vault(
                db_path,
                vault.id,
                vault.unvault_height.expect("We always set it"),
            )?;
        }

        for (vault_id, unvault_height) in self.should_cancel {
            db_should_cancel_vault(db_path, vault_id, unvault_height)?;
        }

        for vault_id in self.to_be_deleted {
            db_del_vault(db_path, vault_id)?;
        }

        for (vault_id, height) in self.spender_confirmed {
            db_unvault_spender_confirmed(db_path, vault_id, height)?;
        }

        Ok(())
    }
}

struct UpdatedVaults {
    pub successful_attempts: Vec<OutPoint>,
    pub revaulted_attempts: Vec<OutPoint>,
}

fn manage_unvaulted_vaults(
    db_path: &path::Path,
    secp: &secp256k1::Secp256k1<impl secp256k1::Verification>,
    config: &Config,
    bitcoind: &BitcoinD,
    current_tip: &ChainTip,
    db_updates: &mut DbUpdates,
) -> Result<UpdatedVaults, PollerError> {
    // We don't have all the unvaulted_vaults in db, some of them are
    // in our db_updates
    let unvaulted_vaults = db_unvaulted_vaults(db_path)?;
    let unvaulted_vaults = unvaulted_vaults
        .iter()
        .chain(db_updates.new_unvaulted.values());
    let mut updated_vaults = UpdatedVaults {
        successful_attempts: vec![],
        revaulted_attempts: vec![],
    };

    for db_vault in unvaulted_vaults {
        let (deposit_desc, unvault_desc, cpfp_desc) = descriptors(secp, config, &db_vault);
        let unvault_tx = match unvault_tx(&db_vault, &deposit_desc, &unvault_desc, &cpfp_desc) {
            Ok(tx) => tx,
            Err(e) => {
                // TODO: handle dust better (they should never send us dust vaults though)
                log::error!("Unexpected error deriving Unvault transaction: '{}'", e);
                continue;
            }
        };
        let unvault_txin = unvault_tx.revault_unvault_txin(&unvault_desc);
        let unvault_outpoint = unvault_txin.outpoint();

        // Don't do anything if the Unvault is still unspent. TODO: re-bumping
        if bitcoind.utxoinfo(&unvault_outpoint).is_some() {
            if bitcoind.chain_tip().hash != current_tip.hash {
                return Err(PollerError::TipChanged);
            }
            log::debug!(
                "Unvault transaction '{}' for vault at '{}' is still unspent at height '{}'",
                unvault_outpoint.txid,
                &db_vault.deposit_outpoint,
                current_tip.height
            );
            continue;
        }

        // If the spending tx was previously confirmed, check for how long it has been and
        // maybe forget about this vault.
        // NOTE: plugins would already have been notified.
        if let Some(conf_height) = db_vault.spent_height {
            let n_confs = current_tip
                .height
                .checked_add(1)
                .expect("A block height>2147483647?")
                .checked_sub(conf_height)
                .expect("Impossible, the confirmation height is always <= tip");
            if n_confs > REORG_WATCH_LIMIT {
                db_updates.to_be_deleted.push(db_vault.id);
                log::info!(
                    "Forgetting about consumed vault at '{}' after its spending transaction \
                     had at least '{}' confirmations.",
                    &db_vault.deposit_outpoint,
                    n_confs
                );
            }
            continue;
        }

        // If the chain didn't change and the Unvault UTxO was spent before the expiration of the
        // CSV, it must have been canceled.
        // Otherwise, we assume it was spent by managers. FIXME: is it fine?
        let csv: i32 = config
            .scripts_config
            .unvault_descriptor
            .csv_value()
            .try_into()
            .expect("CSV value doesn't fit in i32?");
        let unvault_height = db_vault
            .unvault_height
            .expect("No unvault_height for unvaulted vault?");
        if current_tip.height < unvault_height + csv {
            updated_vaults
                .revaulted_attempts
                .push(db_vault.deposit_outpoint);
            log::debug!(
                "Noticed at height '{}' that Cancel transaction was confirmed for vault at '{}'",
                current_tip.height,
                &db_vault.deposit_outpoint,
            );
        } else {
            updated_vaults
                .successful_attempts
                .push(db_vault.deposit_outpoint);
            log::debug!(
                "Noticed at height '{}' that Spend transaction was confirmed for vault at '{}'",
                current_tip.height,
                &db_vault.deposit_outpoint,
            )
        }

        // Note we set the current tip height as spent height, no harm in overestimating this.
        db_updates
            .spender_confirmed
            .push((db_vault.id, current_tip.height));
    }

    Ok(updated_vaults)
}

// Translate an estimate into the feerate threshold to use.
fn cancel_feerate_from_estimate(estimate: Amount) -> Amount {
    // NOTE: Because of the MSRV, we can't iterate by value on the array.
    // TODO: a constant in revault_tx instead of these? (need to move from WU to vb first)
    for threshold in &[20, 100, 200, 500] {
        if estimate.as_sat() <= *threshold {
            return Amount::from_sat(*threshold);
        }
    }

    Amount::from_sat(1_000)
}

// Get a finalized Cancel transaction from the estimated feerate to get included in the next
// block(s).
fn cancel_tx_from_estimate(
    db_path: &path::Path,
    secp: &secp256k1::Secp256k1<impl secp256k1::Verification>,
    db_vault: &DbVault,
    unvault_txin: UnvaultTxIn,
    deposit_desc: &DerivedDepositDescriptor,
    estimate: Amount,
) -> CancelTransaction {
    let cancel_feerate = cancel_feerate_from_estimate(estimate);

    // FIXME: WU and vbytes in revault_tx..
    let mut cancel_tx = CancelTransaction::new(unvault_txin, deposit_desc, cancel_feerate / 4)
        .expect("Checked before registering the vault in DB");

    for db_sig in db_cancel_signatures(db_path, db_vault.id, Some(cancel_feerate))
        .expect("Database must be available")
    {
        cancel_tx
            .add_sig(db_sig.pubkey, db_sig.signature, secp)
            .unwrap_or_else(|e| {
                // Checked before adding signatures to the DB.
                panic!(
                    "Error adding signature '{:?}' to Cancel transaction '{}': '{:?}'",
                    db_sig, cancel_tx, e
                );
            });
        log::trace!(
            "Added signature '{:?}' to Cancel transaction '{}'",
            db_sig,
            cancel_tx
        );
    }

    cancel_tx.finalize(secp).unwrap_or_else(|e|
        // Checked before registering the vault in DB.
        panic!(
            "Error finalizing Cancel transaction '{}': '{:?}'",
            cancel_tx,
            e
        ));

    cancel_tx
}

// TODO: register attempt in db and re-bump if necessary
fn revault(
    db_path: &path::Path,
    secp: &secp256k1::Secp256k1<impl secp256k1::Verification>,
    bitcoind: &BitcoinD,
    db_vault: &DbVault,
    unvault_txin: UnvaultTxIn,
    deposit_desc: &DerivedDepositDescriptor,
) -> Result<(), PollerError> {
    let estimate = bitcoind.estimatefee_next_block();
    let cancel_tx = cancel_tx_from_estimate(
        db_path,
        secp,
        db_vault,
        unvault_txin,
        deposit_desc,
        // TODO: fallback for estimation failure.
        estimate.unwrap_or_else(|| Amount::from_sat(1)),
    );
    log::trace!("Finalized Cancel transaction '{}'", cancel_tx);

    let cancel_tx = cancel_tx.into_tx();
    if let Err(e) = bitcoind.broadcast_tx(&cancel_tx) {
        log::error!(
            "Error broadcasting Cancel transaction '{}': '{:?}'",
            encode::serialize_hex(&cancel_tx),
            e
        );
    } else {
        log::debug!(
            "Broadcasted Cancel transaction '{}'",
            encode::serialize_hex(&cancel_tx)
        );
    }

    Ok(())
}

// Poll bitcoind for new Unvault UTxO of vaults we are watching. Return info about each
// new Unvault attempt.
fn check_for_unvault(
    db_path: &path::Path,
    secp: &secp256k1::Secp256k1<impl secp256k1::Verification>,
    config: &Config,
    bitcoind: &BitcoinD,
    current_tip: &ChainTip,
    db_updates: &mut DbUpdates,
    coordinator_client: Option<&coordinator::CoordinatorClient>,
) -> Result<Vec<VaultInfo>, PollerError> {
    let deleg_vaults = db_blank_vaults(db_path)?;
    let mut new_attempts = vec![];

    for mut db_vault in deleg_vaults {
        let (deposit_desc, unvault_desc, cpfp_desc) = descriptors(secp, config, &db_vault);
        let unvault_tx = match unvault_tx(&db_vault, &deposit_desc, &unvault_desc, &cpfp_desc) {
            Ok(tx) => tx,
            Err(e) => {
                // TODO: handle dust better (they should never send us dust vaults though)
                log::error!("Unexpected error deriving Unvault transaction: '{}'", e);
                continue;
            }
        };
        let unvault_txin = unvault_tx.revault_unvault_txin(&unvault_desc);

        if let Some(utxoinfo) = bitcoind.utxoinfo(&unvault_txin.outpoint()) {
            if current_tip.hash != utxoinfo.bestblock {
                return Err(PollerError::TipChanged);
            }
            let confs: i32 = utxoinfo
                .confirmations
                .try_into()
                .expect("A number of confs that doesn't fit in a i32?");
            let unvault_height = current_tip.height - (confs - 1);
            assert!(confs > 0 && unvault_height > 0);
            log::debug!(
                "Got a confirmed Unvault UTXO for vault at '{}': '{:?}'",
                &db_vault.deposit_outpoint,
                utxoinfo
            );

            db_vault.unvault_height = Some(unvault_height);
            // If needed to be canceled it will be marked as such when plugins tell us so.
            db_updates.new_unvaulted.insert(db_vault.id, db_vault);

            let candidate_tx = if let Some(client) = coordinator_client {
                match client.get_spend_transaction(db_vault.deposit_outpoint.clone()) {
                    Ok(res) => res,
                    Err(_e) => {
                        // Because we do not trust the coordinator, we consider it refuses to deliver the
                        // spend tx if a communication error happened.
                        None
                    }
                }
            } else {
                // No coordinator configuration was found in the config
                // therefore no spend transaction can be shared to plugins
                None
            };

            let vault_info = VaultInfo {
                value: db_vault.amount,
                deposit_outpoint: db_vault.deposit_outpoint,
                unvault_tx,
                candidate_tx,
            };
            new_attempts.push(vault_info);
        }
    }

    Ok(new_attempts)
}

// Poll each of our plugins for vaults to be revaulted given the updates to our vaults' state
// (which might be an empty set) in the latest block.
fn get_vaults_to_revault(
    db_path: &path::Path,
    secp: &secp256k1::Secp256k1<impl secp256k1::Verification>,
    config: &Config,
    block_height: i32,
    block_info: &NewBlockInfo,
    db_updates: &mut DbUpdates,
) -> Result<Vec<(DbVault, UnvaultTxIn, DerivedDepositDescriptor)>, PollerError> {
    let outpoints_to_revault = config
        .plugins
        .iter()
        .fold(vec![], |mut to_revault, plugin| {
            match plugin.poll(block_height, block_info) {
                Ok(mut res) => to_revault.append(&mut res),
                Err(e) => {
                    // FIXME: should we crash instead?
                    log::error!("Error when polling plugin: '{}'", e);
                }
            };
            to_revault
        })
        .into_iter()
        .map(|outpoint| db_vault(db_path, &outpoint))
        .collect::<Result<Vec<Option<DbVault>>, _>>()?
        .into_iter()
        .filter_map(|v| {
            let v = match v {
                Some(v) => v,
                None => {
                    log::error!("One of the plugins returned an inexistant outpoint.");
                    return None;
                }
            };
            // The unvault height might not be here, as we still haven't updated
            // the db. Look into db_updates if we have it, just in case
            let unvault_height = v.unvault_height.or_else(|| {
                db_updates
                    .new_unvaulted
                    .get(&v.id)
                    .map(|v| v.unvault_height)
                    .flatten()
            });
            if let Some(unvault_height) = unvault_height {
                let (deposit_desc, unvault_desc, cpfp_desc) = descriptors(secp, config, &v);
                let unvault_tx = match unvault_tx(&v, &deposit_desc, &unvault_desc, &cpfp_desc) {
                    Ok(tx) => tx,
                    Err(e) => {
                        // TODO: handle dust better (they should never send us dust vaults though)
                        log::error!("Unexpected error deriving Unvault transaction: '{}'", e);
                        return None;
                    }
                };
                let unvault_txin = unvault_tx.revault_unvault_txin(&unvault_desc);

                db_updates.should_cancel.push((v.id, unvault_height));
                Some((v, unvault_txin, deposit_desc))
            } else {
                // FIXME: should we crash? This must never happen.
                log::error!("One of the plugins told us to revault a non-unvaulted vault");
                None
            }
        })
        .collect();

    Ok(outpoints_to_revault)
}

// We only do actual processing on new blocks. This puts a natural limit on the amount of work
// we are doing, reduces the number of edge cases we need to handle, and there is no benefit to try
// to cancel Unvaults right after their broadcast.
// NOTE: we don't handle Emergency transactions for now.
fn new_block(
    db_path: &path::Path,
    secp: &secp256k1::Secp256k1<impl secp256k1::Verification>,
    config: &Config,
    bitcoind: &BitcoinD,
    current_tip: &ChainTip,
    coordinator_client: Option<&coordinator::CoordinatorClient>,
) -> Result<(), PollerError> {
    // We want to update our state for a given height, therefore we need to stop the updating
    // process if we notice that the chain moved forward under us (or we could end up assuming
    // events that happened in the new block had already occured at the initial height). In order
    // to avoid partial writes to the DB we cache the state updates to only apply them once we've
    // made sure the chain didn't move in-between the beginning and the end of the updating
    // process.
    // The same goes for polling the plugins as for updating the DB.
    let mut db_updates = DbUpdates::default();

    // Update the fee-bumping reserves estimates
    // TODO

    // Any vault to forget about?
    // TODO

    // Any Unvault txo confirmed?
    let new_attempts = check_for_unvault(
        db_path,
        secp,
        config,
        bitcoind,
        current_tip,
        &mut db_updates,
        coordinator_client,
    )?;

    // Any Cancel tx still unconfirmed? Any vault to forget about?
    let UpdatedVaults {
        successful_attempts,
        revaulted_attempts,
    } = manage_unvaulted_vaults(
        db_path,
        secp,
        config,
        bitcoind,
        current_tip,
        &mut db_updates,
    )?;

    // Any vault plugins tell us to revault?
    let new_blk_info = NewBlockInfo {
        new_attempts,
        successful_attempts,
        revaulted_attempts,
    };

    let outpoints_to_revault = get_vaults_to_revault(
        db_path,
        secp,
        config,
        current_tip.height,
        &new_blk_info,
        &mut db_updates,
    )?;
    for (db_vault, unvault_txin, deposit_desc) in outpoints_to_revault {
        revault(
            db_path,
            secp,
            bitcoind,
            &db_vault,
            unvault_txin,
            &deposit_desc,
        )?;
    }
    db_updates.write(db_path)?;
    db_update_tip(db_path, current_tip.height, current_tip.hash)?;

    log::debug!(
        "Done processing block '{}' ({})",
        current_tip.hash,
        current_tip.height
    );

    Ok(())
}

pub fn main_loop(
    db_path: &path::Path,
    secp: &secp256k1::Secp256k1<impl secp256k1::Verification>,
    config: &Config,
    bitcoind: &BitcoinD,
    noise_privkey: NoisePrivkey,
) -> Result<(), PollerError> {
    let coordinator_client = config.coordinator_config.as_ref().map(|config| {
        coordinator::CoordinatorClient::new(noise_privkey, config.host, config.noise_key)
    });
    loop {
        let db_instance = db_instance(db_path)?;
        let bitcoind_tip = bitcoind.chain_tip();

        if bitcoind_tip.height > db_instance.tip_blockheight {
            let curr_tip_hash = bitcoind.block_hash(db_instance.tip_blockheight);
            if db_instance.tip_blockheight != 0 && curr_tip_hash != db_instance.tip_blockhash {
                panic!("No reorg handling yet");
            }

            match new_block(
                db_path,
                secp,
                config,
                bitcoind,
                &bitcoind_tip,
                coordinator_client.as_ref(),
            ) {
                Ok(()) => {}
                // Retry immediately if the tip changed while we were updating ourselves
                Err(PollerError::TipChanged) => continue,
                Err(e) => return Err(e),
            }
        } else if bitcoind_tip.hash != db_instance.tip_blockhash {
            panic!("No reorg handling yet");
        }

        thread::sleep(config.bitcoind_config.poll_interval_secs);
    }
}

#[cfg(test)]
mod tests {
    use std::{collections::BTreeMap, fs, iter::repeat_with, path, str::FromStr, thread};

    use super::*;

    use crate::database::{db_new_vault, setup_db};
    use revault_tx::{
        bitcoin::{util::bip32, Address, Amount, Network},
        miniscript::descriptor::{DescriptorPublicKey, DescriptorXKey, Wildcard},
        scripts::{CpfpDescriptor, DepositDescriptor, EmergencyAddress, UnvaultDescriptor},
        transactions::{transaction_chain, RevaultPresignedTransaction},
    };

    fn get_random_privkey(rng: &mut fastrand::Rng) -> bip32::ExtendedPrivKey {
        let rand_bytes: Vec<u8> = repeat_with(|| rng.u8(..)).take(64).collect();

        bip32::ExtendedPrivKey::new_master(Network::Bitcoin, &rand_bytes)
            .unwrap_or_else(|_| get_random_privkey(rng))
    }

    fn get_participants_sets(
        n_stk: usize,
        n_man: usize,
        secp: &secp256k1::Secp256k1<secp256k1::All>,
    ) -> (
        (Vec<bip32::ExtendedPrivKey>, Vec<DescriptorPublicKey>),
        (Vec<bip32::ExtendedPrivKey>, Vec<DescriptorPublicKey>),
        (Vec<bip32::ExtendedPrivKey>, Vec<DescriptorPublicKey>),
    ) {
        let mut rng = fastrand::Rng::new();

        let managers_priv = (0..n_man)
            .map(|_| get_random_privkey(&mut rng))
            .collect::<Vec<bip32::ExtendedPrivKey>>();
        let managers = managers_priv
            .iter()
            .map(|xpriv| {
                DescriptorPublicKey::XPub(DescriptorXKey {
                    origin: None,
                    xkey: bip32::ExtendedPubKey::from_private(&secp, &xpriv),
                    derivation_path: bip32::DerivationPath::from(vec![]),
                    wildcard: Wildcard::Unhardened,
                })
            })
            .collect::<Vec<DescriptorPublicKey>>();

        let stakeholders_priv = (0..n_stk)
            .map(|_| get_random_privkey(&mut rng))
            .collect::<Vec<bip32::ExtendedPrivKey>>();
        let stakeholders = stakeholders_priv
            .iter()
            .map(|xpriv| {
                DescriptorPublicKey::XPub(DescriptorXKey {
                    origin: None,
                    xkey: bip32::ExtendedPubKey::from_private(&secp, &xpriv),
                    derivation_path: bip32::DerivationPath::from(vec![]),
                    wildcard: Wildcard::Unhardened,
                })
            })
            .collect::<Vec<DescriptorPublicKey>>();

        let cosigners_priv = (0..n_stk)
            .map(|_| get_random_privkey(&mut rng))
            .collect::<Vec<bip32::ExtendedPrivKey>>();
        let cosigners = cosigners_priv
            .iter()
            .map(|xpriv| {
                DescriptorPublicKey::XPub(DescriptorXKey {
                    origin: None,
                    xkey: bip32::ExtendedPubKey::from_private(&secp, &xpriv),
                    derivation_path: bip32::DerivationPath::from(vec![]),
                    wildcard: Wildcard::Unhardened,
                })
            })
            .collect::<Vec<DescriptorPublicKey>>();

        (
            (managers_priv, managers),
            (stakeholders_priv, stakeholders),
            (cosigners_priv, cosigners),
        )
    }

    // Sanity check we can get the Cancel transaction and finalize it from the DB signatures
    // at all feerate thresholds.
    #[test]
    fn cancel_from_feerate() {
        // Boilerplate for the setup
        let secp_ctx = secp256k1::Secp256k1::new();
        let db_path: path::PathBuf =
            format!("scratch_test_{:?}.sqlite3", thread::current().id()).into();

        let ((_, managers), (stakeholders_priv, stakeholders), (_, cosigners)) =
            get_participants_sets(3, 2, &secp_ctx);

        let deposit_descriptor = DepositDescriptor::new(stakeholders.clone()).unwrap();
        let cpfp_descriptor = CpfpDescriptor::new(managers.clone()).unwrap();
        let unvault_descriptor =
            UnvaultDescriptor::new(stakeholders.clone(), managers, 2, cosigners, 2021).unwrap();
        let emergency_address = EmergencyAddress::from(
            Address::from_str("bc1q906h8q49vu20cyffqklnzcda20k7c3m83fltey344kz3lctlx9xqhf2v56")
                .unwrap(),
        )
        .unwrap();

        // Remove any potential leftover from a previous crashed session and create the database
        fs::remove_file(&db_path).unwrap_or_else(|_| ());
        setup_db(
            &db_path,
            &deposit_descriptor,
            &unvault_descriptor,
            &cpfp_descriptor,
            Network::Bitcoin,
        )
        .unwrap();

        // A dummy deposit
        let deposit_outpoint = OutPoint::from_str(
            "cb5eb24aa77687b1e9794a826e50a35ed7378b2e5879692827de0a597446f0c8:0",
        )
        .unwrap();
        let deposit_value = Amount::from_sat(98765145);
        let derivation_index = 456789.into();
        let (_, cancel_batch, emer_tx, unemer_tx) = transaction_chain(
            deposit_outpoint,
            deposit_value,
            &deposit_descriptor,
            &unvault_descriptor,
            &cpfp_descriptor,
            derivation_index,
            emergency_address.clone(),
            &secp_ctx,
        )
        .unwrap();

        // Valid signatures for all transactions for this dummy deposit
        let sighash = emer_tx.sig_hash().unwrap();
        let sighash = secp256k1::Message::from_slice(&sighash).unwrap();
        let emergency_sigs: BTreeMap<secp256k1::PublicKey, secp256k1::Signature> =
            stakeholders_priv
                .iter()
                .map(|xpriv| {
                    let privkey = xpriv.derive_priv(&secp_ctx, &[derivation_index]).unwrap();
                    (
                        privkey.private_key.public_key(&secp_ctx).key,
                        secp_ctx.sign(&sighash, &privkey.private_key.key),
                    )
                })
                .collect();

        let mut all_cancel_sigs = BTreeMap::new();
        for (feerate, cancel_tx) in cancel_batch.feerates_map() {
            let sighash = cancel_tx.sig_hash().unwrap();
            let sighash = secp256k1::Message::from_slice(&sighash).unwrap();
            let cancel_sigs: BTreeMap<secp256k1::PublicKey, secp256k1::Signature> =
                stakeholders_priv
                    .iter()
                    .map(|xpriv| {
                        let privkey = xpriv.derive_priv(&secp_ctx, &[derivation_index]).unwrap();
                        (
                            privkey.private_key.public_key(&secp_ctx).key,
                            secp_ctx.sign(&sighash, &privkey.private_key.key),
                        )
                    })
                    .collect();
            all_cancel_sigs.insert(feerate, cancel_sigs);
        }
        let sighash = unemer_tx.sig_hash().unwrap();
        let sighash = secp256k1::Message::from_slice(&sighash).unwrap();
        let unemer_sigs: BTreeMap<secp256k1::PublicKey, secp256k1::Signature> = stakeholders_priv
            .iter()
            .map(|xpriv| {
                let privkey = xpriv.derive_priv(&secp_ctx, &[derivation_index]).unwrap();
                (
                    privkey.private_key.public_key(&secp_ctx).key,
                    secp_ctx.sign(&sighash, &privkey.private_key.key),
                )
            })
            .collect();

        // Register this vault in DB, get the data needed to compute all the Cancels
        db_new_vault(
            &db_path,
            &deposit_outpoint,
            derivation_index,
            deposit_value,
            emergency_sigs,
            all_cancel_sigs,
            unemer_sigs,
        )
        .unwrap();
        let db_vault = db_vault(&db_path, &deposit_outpoint).unwrap().unwrap();
        let der_deposit_desc = deposit_descriptor.derive(derivation_index, &secp_ctx);
        let der_unvault_desc = unvault_descriptor.derive(derivation_index, &secp_ctx);
        let unvault_txin = unvault_tx(
            &db_vault,
            &der_deposit_desc,
            &der_unvault_desc,
            &cpfp_descriptor.derive(derivation_index, &secp_ctx),
        )
        .unwrap()
        .revault_unvault_txin(&der_unvault_desc);

        // It would panic on failure to satisfy the transaction. All these estimates exercise the
        // various thresholds (20, 100, 200, 500, 1_000).
        // NOTE: because of the MSRV, we can't iterate by value here.
        for estimate in &[15, 57, 199, 322, 777, 1_500, 9_999_999] {
            cancel_tx_from_estimate(
                &db_path,
                &secp_ctx,
                &db_vault,
                unvault_txin.clone(),
                &der_deposit_desc,
                Amount::from_sat(*estimate),
            );
        }

        // Done: remove the db
        fs::remove_file(&db_path).unwrap_or_else(|_| ());
    }
}
