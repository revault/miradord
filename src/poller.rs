use crate::{
    bitcoind::{interface::BitcoinD, BitcoindError},
    config::Config,
    database::{db_instance, DatabaseError},
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

// We only do actual processing on new blocks. This puts a natural limit on the amount of work
// we are doing, reduces the number of edge cases we need to handle, and there is no benefit to try
// to cancel Unvaults right after their broadcast.
// NOTE: we don't handle Emergency transactions for now.
fn new_block() {
    // 1. Update the fee-bumping reserves estimates
    // TODO

    // 2. Any vault to forget and feebump coins to unregister?
    // TODO

    // 3. Any Unvault txo confirmed?
    // TODO

    // 4. Any Cancel tx still unconfirmed?
    // TODO

    // 5. Any coin received on the FB wallet?
    // TODO

    // 6. Any FB coin to be registered for consolidation?
    // TODO

    // 7. Any consolidation to be processed given the current fee market?
    // TODO
}

pub fn main_loop(
    db_path: &path::Path,
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

            new_block();
        } else if bitcoind_tip.hash != db_instance.tip_blockhash {
            panic!("No reorg handling yet");
        }

        thread::sleep(config.bitcoind_config.poll_interval_secs);
    }
}
