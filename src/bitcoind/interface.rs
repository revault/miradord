use crate::{bitcoind::BitcoindError, config::BitcoindConfig};
use revault_tx::bitcoin::{
    blockdata::constants::COIN_VALUE, consensus::encode, Amount, BlockHash, OutPoint,
    Transaction as BitcoinTransaction,
};

use std::{
    any::Any,
    fs, process,
    str::FromStr,
    thread,
    time::{Duration, Instant},
};

use jsonrpc::{
    arg,
    client::Client,
    simple_http::{Error as HttpError, SimpleHttpTransport},
};
use serde_json::Value as Json;

// No call should take more than 10min to process (we don't do any rescan, at least for now, and we
// check that bitcoind is synced at startup).
// Actually every call should take way less time than that but we are over-precautionous as a
// failure to get the response of a call would usually mean that we have to crash, and therefore
// that we are not watching the funds anymore.
const RPC_REQ_TIMEOUT_SEC: u64 = 600;

// For how long do we keep retrying on communication error to the bitcoind server before giving up.
const RPC_REQ_RETRY_TIMEOUT_SEC: u64 = 300;

fn retry_timeout_exceeded(now: Instant, start: Instant) -> bool {
    now.duration_since(start) > Duration::from_secs(RPC_REQ_RETRY_TIMEOUT_SEC)
}

#[derive(Debug)]
pub struct BitcoinD {
    // For generalistic node RPC commands
    node_client: Client,
    // For watchonly RPC commands to the vaults descriptors
    vault_client: Client,
    // TODO: feebumping wallet
}

macro_rules! params {
    ($($param:expr),* $(,)?) => {
        [
            $(
                arg($param),
            )*
        ]
    };
}

impl BitcoinD {
    pub fn new(
        config: &BitcoindConfig,
        vault_wallet_path: String,
    ) -> Result<BitcoinD, BitcoindError> {
        let cookie_string =
            fs::read_to_string(&config.cookie_path).map_err(BitcoindError::CookieFile)?;

        // Create a dummy client with a low timeout first to test the connection
        let dummy_node_client = Client::with_transport(
            SimpleHttpTransport::builder()
                .url(&config.addr.to_string())
                .map_err(BitcoindError::from)?
                .timeout(Duration::from_secs(3))
                .cookie_auth(cookie_string.clone())
                .build(),
        );
        let req = dummy_node_client.build_request("echo", &[]);
        dummy_node_client.send_request(req.clone())?;

        let node_client = Client::with_transport(
            SimpleHttpTransport::builder()
                .url(&config.addr.to_string())
                .map_err(BitcoindError::from)?
                .timeout(Duration::from_secs(RPC_REQ_TIMEOUT_SEC))
                .cookie_auth(cookie_string.clone())
                .build(),
        );

        // Create a dummy client with a low timeout first to test the connection
        let url = format!("http://{}/wallet/{}", config.addr, vault_wallet_path);
        let dummy_vault_client = Client::with_transport(
            SimpleHttpTransport::builder()
                .url(&url)
                .map_err(BitcoindError::from)?
                .timeout(Duration::from_secs(3))
                .cookie_auth(cookie_string.clone())
                .build(),
        );
        let req = dummy_vault_client.build_request("echo", &[]);
        dummy_vault_client.send_request(req.clone())?;

        let vault_client = Client::with_transport(
            SimpleHttpTransport::builder()
                .url(&url)
                .map_err(BitcoindError::from)?
                .timeout(Duration::from_secs(RPC_REQ_TIMEOUT_SEC))
                .cookie_auth(cookie_string)
                .build(),
        );

        Ok(BitcoinD {
            node_client,
            vault_client,
        })
    }

    // Try to be robust against spurious communication failures as much as possible.
    fn handle_error(
        &self,
        e: jsonrpc::Error,
        start: Instant,
        is_startup: bool,
    ) -> Result<(), BitcoindError> {
        let now = Instant::now();

        match e {
            jsonrpc::Error::Transport(ref err) => {
                log::error!("Transport error when talking to bitcoind: '{}'", err);

                // This is *always* a simple_http::Error. Rule out the error that can
                // not occur after startup (ie if we encounter them it must be startup
                // and we better be failing quickly).
                let any_err = err as &dyn Any;
                if let Some(http_err) = any_err.downcast_ref::<HttpError>() {
                    match http_err {
                        HttpError::InvalidUrl { .. } => return Err(BitcoindError::Server(e)),
                        HttpError::SocketError(_) => {
                            // On startup, we want to fail ASAP if there is an issue with the
                            // connection. On the other hand we certainly don't afterward if
                            // there is a spurious error!
                            if is_startup || retry_timeout_exceeded(now, start) {
                                return Err(BitcoindError::Server(e));
                            }
                            thread::sleep(Duration::from_secs(1));
                        }
                        HttpError::HttpParseError => {
                            // Weird. Try again once, just in case.
                            if now.duration_since(start) > Duration::from_secs(1) {
                                return Err(BitcoindError::Server(e));
                            }
                            thread::sleep(Duration::from_secs(1));
                        }
                        _ => {}
                    }
                }

                // This one *may* happen. For a number of reasons, the obvious one being
                // that the RPC work queue is exceeded.
                if retry_timeout_exceeded(now, start) {
                    return Err(BitcoindError::Server(e));
                }
                thread::sleep(Duration::from_secs(1));
                log::debug!("Retrying RPC request to bitcoind.");
            }
            jsonrpc::Error::Rpc(ref err) => {
                log::error!("JSONRPC error when talking to bitcoind: '{:?}'", err);

                if retry_timeout_exceeded(now, start) {
                    return Err(BitcoindError::Server(e));
                }
                thread::sleep(Duration::from_secs(1));
            }
            jsonrpc::Error::Json(ref err) => {
                // Weird. A JSON serialization error? Just try again but
                // fail fast anyways as it should not happen.
                log::error!(
                    "JSON serialization error when talking to bitcoind: '{}'",
                    err
                );
                if now.duration_since(start) > Duration::from_secs(1) {
                    return Err(BitcoindError::Server(e));
                }
                thread::sleep(Duration::from_millis(500));
                log::debug!("Retrying RPC request to bitcoind.");
            }
            _ => return Err(BitcoindError::Server(e)),
        };

        Ok(())
    }

    fn make_request<'a, 'b>(
        &self,
        client: &Client,
        method: &'a str,
        params: &'b [Box<serde_json::value::RawValue>],
        fail_fast: bool,
    ) -> Result<Json, BitcoindError> {
        let req = client.build_request(method, &params);
        log::trace!("Sending to bitcoind: {:#?}", req);

        // If we are explicitly told to not try again, don't.
        if fail_fast {
            return client
                .send_request(req.clone())
                .map_err(BitcoindError::Server)?
                .result()
                .map_err(BitcoindError::Server);
        }

        // Trying to be robust on bitcoind's spurious failures.
        let start = Instant::now();
        loop {
            match client.send_request(req.clone()) {
                Ok(resp) => {
                    log::trace!("Got from bitcoind: {:#?}", resp);
                    match resp.result() {
                        Ok(res) => return Ok(res),
                        Err(e) => {
                            self.handle_error(e, start, false)?;
                        }
                    };
                }
                Err(e) => {
                    // Decide wether we should error, or not yet
                    self.handle_error(e, start, false)?;
                }
            }
        }
    }

    fn make_node_request<'a, 'b>(
        &self,
        method: &'a str,
        params: &'b [Box<serde_json::value::RawValue>],
    ) -> Json {
        self.make_request(&self.node_client, method, params, false)
            .unwrap_or_else(|e| {
                log::error!("Fatal bitcoind RPC error (node client): '{}'", e);
                process::exit(1);
            })
    }

    fn make_node_request_failible<'a, 'b>(
        &self,
        method: &'a str,
        params: &'b [Box<serde_json::value::RawValue>],
    ) -> Result<Json, BitcoindError> {
        self.make_request(&self.node_client, method, params, true)
    }

    /// Network name as returned by 'getblockchainfo'
    pub fn bip70_net(&self) -> String {
        self.make_node_request("getblockchaininfo", &[])
            .get("chain")
            .and_then(|c| c.as_str())
            .expect("No 'chain' in 'getblockchaininfo' response?")
            .to_string()
    }

    /// Fetch info about bitcoind's synchronization status
    pub fn synchronization_info(&self) -> SyncInfo {
        let chaininfo = self.make_node_request("getblockchaininfo", &[]);
        SyncInfo {
            headers: chaininfo
                .get("headers")
                .and_then(|h| h.as_u64())
                .expect("No valid 'headers' in getblockchaininfo response?"),
            blocks: chaininfo
                .get("blocks")
                .and_then(|b| b.as_u64())
                .expect("No valid 'blocks' in getblockchaininfo response?"),
            ibd: chaininfo
                .get("initialblockdownload")
                .and_then(|i| i.as_bool())
                .expect("No valid 'initialblockdownload' in getblockchaininfo response?"),
            progress: chaininfo
                .get("verificationprogress")
                .and_then(|i| i.as_f64())
                .expect("No valid 'verificationprogress' in getblockchaininfo response?"),
        }
    }

    /// Create a descriptor watchonly wallet
    pub fn createwallet(&self, wallet_path: String) -> Result<(), BitcoindError> {
        let res = self.make_node_request_failible(
            "createwallet",
            &params!(
                Json::String(wallet_path),
                Json::Bool(true),             // watchonly
                Json::Bool(false),            // blank
                Json::String("".to_string()), // passphrase,
                Json::Bool(false),            // avoid_reuse
                Json::Bool(true),             // descriptors
                Json::Bool(true),             // load_on_startup
            ),
        )?;

        if let Some(w) = res.get("warning") {
            log::warn!("Warning creating wallet: '{}'", w);
        }

        Ok(())
    }

    /// Get a list of the name of loaded wallets on bitcoind
    pub fn listwallets(&self) -> Vec<String> {
        self.make_node_request("listwallets", &[])
            .as_array()
            .expect("API break, 'listwallets' didn't return an array.")
            .into_iter()
            .map(|json_str| {
                json_str
                    .as_str()
                    .expect("API break: 'listwallets' contains a non-string value")
                    .to_string()
            })
            .collect()
    }

    /// Load a watchonly wallet. Failible since called at startup.
    pub fn loadwallet(&self, wallet_path: String) -> Result<(), BitcoindError> {
        let res = self.make_node_request_failible(
            "loadwallet",
            &params!(
                Json::String(wallet_path),
                Json::Bool(true), // load_on_startup
            ),
        )?;

        if let Some(w) = res.get("warning") {
            log::warn!("Warning loading wallet: '{}'", w);
        }

        Ok(())
    }

    /// Unload a watchonly wallet.
    pub fn unloadwallet(&self, wallet_path: String) -> Result<(), BitcoindError> {
        let res =
            self.make_node_request_failible("unloadwallet", &params!(Json::String(wallet_path),))?;

        if let Some(w) = res.get("warning") {
            log::warn!("Warning unloading wallet: '{}'", w);
        }

        Ok(())
    }

    /// Get the (height, hash) pair of the current best block
    pub fn chain_tip(&self) -> ChainTip {
        let chaininfo = self.make_node_request("getblockchaininfo", &[]);
        ChainTip {
            height: chaininfo
                .get("blocks")
                .and_then(|b| b.as_i64())
                .expect("No valid 'blocks' in getblockchaininfo response?")
                as i32,
            hash: BlockHash::from_str(
                chaininfo
                    .get("bestblockhash")
                    .and_then(|i| i.as_str())
                    .expect("No valid 'bestblockhash' in getblockchaininfo response?"),
            )
            .expect("Not a valid block hash in 'bestblockhash' field?"),
        }
    }

    /// Get the hash of the block at this height
    pub fn block_hash(&self, height: i32) -> BlockHash {
        BlockHash::from_str(
            self.make_node_request("getblockhash", &params!(height))
                .as_str()
                .expect("'getblockhash' didn't return a string."),
        )
        .expect("'getblockhash' returned an invalid block hash")
    }

    /// Get information about this tx output, if it is in the best block chain and unspent.
    pub fn utxoinfo(&self, outpoint: &OutPoint) -> Option<UtxoInfo> {
        let res = self.make_node_request(
            "gettxout",
            &params!(
                outpoint.txid,
                outpoint.vout,
                false // include_mempool
            ),
        );

        // It returns null on "not found"
        if res == Json::Null {
            return None;
        }

        let confirmations = res
            .get("confirmations")
            .and_then(|c| c.as_i64())
            .expect("'gettxout' didn't return a valid 'confirmations' value");
        let bestblock = res
            .get("bestblock")
            .and_then(|bb| bb.as_str())
            .and_then(|bb_str| BlockHash::from_str(bb_str).ok())
            .expect("'gettxout' didn't return a valid 'bestblock' value");
        let value = res
            .get("value")
            .and_then(|v| v.as_f64())
            .and_then(|v| Amount::from_btc(v).ok())
            .expect("'gettxout' didn't return a valid 'value' entry");
        Some(UtxoInfo {
            confirmations,
            bestblock,
            value,
        })
    }

    /// Broadcast this transaction to the Bitcoin network
    pub fn broadcast_tx(&self, tx: &BitcoinTransaction) -> Result<(), BitcoindError> {
        let tx_hex = encode::serialize_hex(tx);
        self.make_node_request_failible("sendrawtransaction", &params!(tx_hex))
            .map(|_| ())
    }

    // TODO: don't return an optional, use the last 6 block 85th percentile feerate as a fallback.
    /// Get the feerate estimation for inclusion in the next block(s) in sat/vb.
    pub fn estimatefee_next_block(&self) -> Option<Amount> {
        let res = self.make_node_request("estimatesmartfee", &params!(2));

        if let Some(rate_btc_kvb) = res.get("feerate").and_then(|f| f.as_f64()) {
            let rate_sat_vb = (rate_btc_kvb * COIN_VALUE as f64 / 1_000.0) as u64;
            if !(1..=100_000).contains(&rate_sat_vb) {
                log::error!(
                    "Insane value converting feerate returned by estimatesmartfee ({})",
                    rate_btc_kvb
                );
                return None;
            }
            return Some(Amount::from_sat(rate_sat_vb));
        }

        if let Some(errors) = res.get("errors") {
            log::error!("Error calling 'estimatesmartfee': {:?}", errors);
        }

        None
    }
}

/// Info about bitcoind's sync state
pub struct SyncInfo {
    pub headers: u64,
    pub blocks: u64,
    pub ibd: bool,
    pub progress: f64,
}

/// Block height and block hash of what we consider to be the block chain tip
pub struct ChainTip {
    pub height: i32,
    pub hash: BlockHash,
}

/// Info about a block chain UTXO
#[derive(Debug)]
pub struct UtxoInfo {
    pub confirmations: i64,
    pub bestblock: BlockHash,
    pub value: Amount,
}
