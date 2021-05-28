use crate::{bitcoind::BitcoindError, config::BitcoindConfig};

use std::{
    any::Any,
    fs, process, thread,
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
                log::error!(
                    "JSON serialization error when talking to bitcoind: '{}'",
                    err
                );
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
    ) -> Result<Json, BitcoindError> {
        let req = client.build_request(method, &params);
        log::trace!("Sending to bitcoind: {:#?}", req);

        // Trying to be robust on bitcoind's spurious failures. We try to support bitcoind failing
        // under our feet for a few dozens of seconds, while not delaying an early failure (for
        // example, if we got the RPC listening address or path to the cookie wrong).
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
        self.make_request(&self.node_client, method, params)
            .unwrap_or_else(|e| {
                log::error!("Fatal bitcoind RPC error (node client): '{}'", e);
                process::exit(1);
            })
    }

    fn make_vault_request<'a, 'b>(
        &self,
        method: &'a str,
        params: &'b [Box<serde_json::value::RawValue>],
    ) -> Json {
        self.make_request(&self.vault_client, method, params)
            .unwrap_or_else(|e| {
                log::error!("Fatal bitcoind RPC error (vault watchonly client): '{}'", e);
                process::exit(1);
            })
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
                .expect("No valid 'initialblockdownload' in getblockchaininfo response?"),
        }
    }
}

/// Info about bitcoind's sync state
pub struct SyncInfo {
    pub headers: u64,
    pub blocks: u64,
    pub ibd: bool,
    pub progress: f64,
}
