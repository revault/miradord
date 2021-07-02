use crate::{
    bitcoind::{
        interface::{BitcoinD, ChainTip},
        BitcoindError,
    },
    config::Config,
    database::{
        db_cancel_signatures, db_instance, db_delegated_vaults, schema::DbVault,
        DatabaseError, db_should_cancel_vault, db_should_not_cancel_vault

    },
};
use revault_tx::{
    bitcoin::{consensus::encode, secp256k1},
    scripts::DerivedDepositDescriptor,
    transactions::{CancelTransaction, RevaultTransaction, UnvaultTransaction},
    txins::{DepositTxIn, RevaultTxIn, UnvaultTxIn},
    txouts::DepositTxOut,
};

use std::{path, thread};

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
        let deposit_desc = config
            .scripts_config
            .deposit_descriptor
            .derive(db_vault.derivation_index, secp);
        let unvault_desc = config
            .scripts_config
            .unvault_descriptor
            .derive(db_vault.derivation_index, secp);
        let cpfp_desc = config
            .scripts_config
            .cpfp_descriptor
            .derive(db_vault.derivation_index, secp);
        let deposit_txo = DepositTxOut::new(db_vault.amount, &deposit_desc);
        let deposit_txin = DepositTxIn::new(db_vault.deposit_outpoint, deposit_txo);
        let unvault_tx = match UnvaultTransaction::new(
            deposit_txin,
            &unvault_desc,
            &cpfp_desc,
            /* FIXME: remove from the API */ 0,
        ) {
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

    // 4. Any Cancel tx still unconfirmed?
    // TODO

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
