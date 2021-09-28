use crate::{
    bitcoind::{
        interface::{BitcoinD, ChainTip},
        BitcoindError,
    },
    config::Config,
    database::{
        db_cancel_signatures, db_canceling_vaults, db_del_vault, db_delegated_vaults, db_instance,
        db_revoc_confirmed, db_should_cancel_vault, db_should_not_cancel_vault, schema::DbVault,
        DatabaseError,
    },
};
use revault_tx::{
    bitcoin::{consensus::encode, secp256k1},
    scripts::{DerivedCpfpDescriptor, DerivedDepositDescriptor, DerivedUnvaultDescriptor},
    transactions::{CancelTransaction, RevaultTransaction, UnvaultTransaction},
    txins::{DepositTxIn, RevaultTxIn, UnvaultTxIn},
    txouts::DepositTxOut,
};

use std::{convert::TryInto, path, thread};

/// How many blocks are we waiting to consider a consumed vault irreversably spent
const REORG_WATCH_LIMIT: i32 = 288;

/// An error happened in the main loop
#[derive(Debug)]
pub enum PollerError {
    Database(DatabaseError),
    Bitcoind(BitcoindError),
}

impl std::fmt::Display for PollerError {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self {
            Self::Database(ref e) => write!(f, "Database error in main loop: '{}'", e),
            Self::Bitcoind(ref e) => write!(f, "Bitcoind error in main loop: '{}'", e),
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

fn manage_cancel_attempts(
    db_path: &path::Path,
    secp: &secp256k1::Secp256k1<impl secp256k1::Verification>,
    config: &Config,
    bitcoind: &BitcoinD,
    current_tip: &ChainTip,
) -> Result<(), PollerError> {
    let canceling_vaults = db_canceling_vaults(db_path)?;

    for db_vault in canceling_vaults {
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
        let cancel_tx = CancelTransaction::new(
            unvault_txin,
            None,
            &deposit_desc,
            /* FIXME: remove from the API */ 0,
        );

        // If it was confirmed, check for how long and maybe forget it. Otherwise check if it got
        // confirmed since our last poll.
        if let Some(conf_height) = db_vault.revoc_height {
            let n_confs = current_tip
                .height
                .checked_add(1)
                // FIXME all heights should be i32s
                .expect("A block height>2147483647?")
                .checked_sub(conf_height)
                .expect("Impossible, the confirmation height is always <= tip");
            if n_confs > REORG_WATCH_LIMIT {
                db_del_vault(db_path, db_vault.id)?;
            }
        } else {
            let cancel_outpoint = cancel_tx.deposit_txin(&deposit_desc).outpoint();
            if let Some(utxoinfo) = bitcoind.utxoinfo(&cancel_outpoint) {
                if utxoinfo.bestblock != current_tip.hash {
                    // TODO
                }

                let confirmation_height = current_tip
                    .height
                    .checked_add(1)
                    .expect("A block height>2147483647?")
                    .checked_sub(
                        // Can't be 0, as we don't include the mempool
                        utxoinfo
                            .confirmations
                            .try_into()
                            .expect("A block height>2147483648?"),
                    )
                    .expect("Impossible, we just checked the tip is in sync");
                db_revoc_confirmed(db_path, db_vault.id, confirmation_height)?;
                log::debug!(
                    "Vault at '{}' Cancel transaction '{}' confirmed at height '{}'",
                    &db_vault.deposit_outpoint,
                    cancel_tx.txid(),
                    confirmation_height
                );
            } else {
                // If the chain didn't change, and there is no Cancel UTXO at the best block there
                // are only 2 possibilities: either the Cancel transaction is still unconfirmed
                // (and therefore the Unvault UTXO is still present) or it was spent.
                if bitcoind.utxoinfo(&unvault_outpoint).is_none() {
                    if bitcoind.chain_tip().hash != current_tip.hash {
                        // TODO
                    }

                    db_revoc_confirmed(db_path, db_vault.id, current_tip.height)?;
                    log::debug!(
                        "Noticed at height '{}' that Cancel transaction '{}' was confirmed for vault at '{}'",
                        current_tip.height,
                        cancel_tx.txid(),
                        &db_vault.deposit_outpoint,
                    );
                } else {
                    log::debug!("Cancel transaction '{}' for vault at '{}' is still unconfirmed at height '{}'",
                                cancel_tx.txid(), &db_vault.deposit_outpoint, current_tip.height);
                    // TODO: maybe feebump
                }
            }
        }
    }

    Ok(())
}

// TODO: actual feebump computation, register attempt in db, ..
fn revault(
    db_path: &path::Path,
    secp: &secp256k1::Secp256k1<impl secp256k1::Verification>,
    bitcoind: &BitcoinD,
    db_vault: DbVault,
    unvault_txin: UnvaultTxIn,
    deposit_desc: &DerivedDepositDescriptor,
) -> Result<(), PollerError> {
    let mut cancel_tx = CancelTransaction::new(
        unvault_txin,
        None,
        &deposit_desc,
        /* FIXME: remove from the API */ 0,
    );

    for db_sig in db_cancel_signatures(db_path, db_vault.id)? {
        if let Err(e) = cancel_tx.add_cancel_sig(db_sig.pubkey, db_sig.signature, secp) {
            log::error!(
                "Error adding signature '{:?}' to Cancel transaction '{}': '{:?}'",
                db_sig,
                cancel_tx,
                e
            );
        } else {
            log::trace!(
                "Added signature '{:?}' to Cancel transaction '{}'",
                db_sig,
                cancel_tx
            );
        }
    }

    if let Err(e) = cancel_tx.finalize(secp) {
        log::error!(
            "Error finalizing Cancel transaction '{}': '{:?}'",
            cancel_tx,
            e
        );
        return Ok(()); // Don't crash, though.
    } else {
        log::trace!("Finalized Cancel transaction '{}'", cancel_tx);
    }

    let cancel_tx = cancel_tx.into_tx();
    if let Err(e) = bitcoind.broadcast_tx(&cancel_tx) {
        log::error!(
            "Error broadcasting Cancel transaction '{}': '{:?}'",
            encode::serialize_hex(&cancel_tx),
            e
        );
    } else {
        log::trace!(
            "Broadcasted Cancel transaction '{}'",
            encode::serialize_hex(&cancel_tx)
        );
    }

    Ok(())
}

// TODO: actually implement the interface to plugins for taking the decision to Revault
fn should_revault(_unvault_tx: &UnvaultTransaction) -> bool {
    true
}

fn check_for_unvault(
    db_path: &path::Path,
    secp: &secp256k1::Secp256k1<impl secp256k1::Verification>,
    config: &Config,
    bitcoind: &BitcoinD,
    current_tip: &ChainTip,
) -> Result<(), PollerError> {
    let deleg_vaults = db_delegated_vaults(db_path)?;

    for db_vault in deleg_vaults {
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
            log::debug!("Got a confirmed Unvault UTXO: '{:?}'", utxoinfo);

            if current_tip.hash != utxoinfo.bestblock {
                // TODO
            }

            if should_revault(&unvault_tx) {
                db_should_cancel_vault(db_path, db_vault.id)?;
                revault(
                    db_path,
                    secp,
                    bitcoind,
                    db_vault,
                    unvault_txin,
                    &deposit_desc,
                )?;
            } else {
                db_should_not_cancel_vault(db_path, db_vault.id)?;
            }
        }
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
    // 1. Update the fee-bumping reserves estimates
    // TODO

    // 2. Any vault to forget and feebump coins to unregister?
    // TODO

    // 3. Any Unvault txo confirmed?
    check_for_unvault(db_path, secp, config, bitcoind, current_tip)?;

    // 4. Any Cancel tx still unconfirmed? Any to forget about?
    manage_cancel_attempts(db_path, secp, config, bitcoind, current_tip)?;

    // 5. Any coin received on the FB wallet?
    // TODO

    // 6. Any FB coin to be registered for consolidation?
    // TODO

    // 7. Any consolidation to be processed given the current fee market?
    // TODO

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

            new_block(db_path, secp, config, bitcoind, &bitcoind_tip)?;
            // TODO: update tip in db
        } else if bitcoind_tip.hash != db_instance.tip_blockhash {
            panic!("No reorg handling yet");
        }

        thread::sleep(config.bitcoind_config.poll_interval_secs);
    }
}
