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
    bitcoin::{consensus::encode, secp256k1, OutPoint},
    scripts::{DerivedCpfpDescriptor, DerivedDepositDescriptor, DerivedUnvaultDescriptor},
    transactions::{CancelTransaction, RevaultTransaction, UnvaultTransaction},
    txins::{DepositTxIn, RevaultTxIn, UnvaultTxIn},
    txouts::DepositTxOut,
};

use std::{collections::HashMap, convert::TryInto, path, thread};

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
    UnvaultTransaction::new(
        deposit_txin,
        &unvault_desc,
        &cpfp_desc,
        /* FIXME: remove from the API */ 0,
    )
}

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

// TODO: actual feebump computation, register attempt in db, ..
fn revault(
    db_path: &path::Path,
    secp: &secp256k1::Secp256k1<impl secp256k1::Verification>,
    bitcoind: &BitcoinD,
    db_vault: &DbVault,
    unvault_txin: UnvaultTxIn,
    deposit_desc: &DerivedDepositDescriptor,
) -> Result<(), PollerError> {
    let mut cancel_tx = CancelTransaction::new(
        unvault_txin,
        None,
        &deposit_desc,
        /* FIXME: remove from the API */ 0,
    )
    .expect("Can only fail if we have an insane feebumping input");

    for db_sig in db_cancel_signatures(db_path, db_vault.id)? {
        cancel_tx
            .add_cancel_sig(db_sig.pubkey, db_sig.signature, secp)
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
            let vault_info = VaultInfo {
                value: db_vault.amount,
                deposit_outpoint: db_vault.deposit_outpoint,
                unvault_tx,
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

fn update_db(db_path: &path::Path, db_updates: DbUpdates) -> Result<(), PollerError> {
    for (_, vault) in db_updates.new_unvaulted {
        db_should_not_cancel_vault(
            db_path,
            vault.id,
            vault.unvault_height.expect("We always set it"),
        )?;
    }

    for (vault_id, unvault_height) in db_updates.should_cancel {
        db_should_cancel_vault(db_path, vault_id, unvault_height)?;
    }

    for vault_id in db_updates.to_be_deleted {
        db_del_vault(db_path, vault_id)?;
    }

    for (vault_id, height) in db_updates.spender_confirmed {
        db_unvault_spender_confirmed(db_path, vault_id, height)?;
    }

    Ok(())
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
) -> Result<(), PollerError> {
    // Storing everything we need to udpate in the db, so we can update it
    // all in one batch at the end
    let mut db_updates = DbUpdates::default();

    // Update the fee-bumping reserves estimates
    // TODO

    // Any vault to forget and feebump coins to unregister?
    // TODO

    // Any Unvault txo confirmed?
    let new_attempts = check_for_unvault(
        db_path,
        secp,
        config,
        bitcoind,
        current_tip,
        &mut db_updates,
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

    // Any coin received on the FB wallet?
    // TODO

    // Any FB coin to be registered for consolidation?
    // TODO

    // Any consolidation to be processed given the current fee market?
    // TODO

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

    update_db(&db_path, db_updates)?;
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
) -> Result<(), PollerError> {
    loop {
        let db_instance = db_instance(db_path)?;
        let bitcoind_tip = bitcoind.chain_tip();

        if bitcoind_tip.height > db_instance.tip_blockheight {
            let curr_tip_hash = bitcoind.block_hash(db_instance.tip_blockheight);
            if db_instance.tip_blockheight != 0 && curr_tip_hash != db_instance.tip_blockhash {
                panic!("No reorg handling yet");
            }

            match new_block(db_path, secp, config, bitcoind, &bitcoind_tip) {
                Ok(()) | Err(PollerError::TipChanged) => {}
                Err(e) => return Err(e),
            }
        } else if bitcoind_tip.hash != db_instance.tip_blockhash {
            panic!("No reorg handling yet");
        }

        thread::sleep(config.bitcoind_config.poll_interval_secs);
    }
}
