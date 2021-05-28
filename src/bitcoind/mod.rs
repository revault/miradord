pub mod interface;

use crate::{
    bitcoind::interface::{BitcoinD, SyncInfo},
    config::BitcoindConfig,
};
use revault_tx::bitcoin::Network;

use std::{io, thread, time::Duration};

use jsonrpc::{
    error::{Error, RpcError},
    simple_http,
};

/// An error happened in the bitcoind-manager thread
#[derive(Debug)]
pub enum BitcoindError {
    /// Error reading bitcoind's cookie file
    CookieFile(io::Error),
    /// Error related to bitcoind's RPC server
    Server(Error),
    /// Bitcoind isn't on the right network!
    InvalidNetwork(String /* Actual net */, String /* Expected net */),
}

impl BitcoindError {
    /// Is bitcoind just starting ?
    pub fn is_warming_up(&self) -> bool {
        match self {
            // https://github.com/bitcoin/bitcoin/blob/dca80ffb45fcc8e6eedb6dc481d500dedab4248b/src/rpc/protocol.h#L49
            BitcoindError::Server(Error::Rpc(RpcError { code: -28, .. })) => true,
            _ => false,
        }
    }
}

impl std::fmt::Display for BitcoindError {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self {
            BitcoindError::CookieFile(ref e) => write!(f, "Bitcoind cookie file error: '{}'", e),
            BitcoindError::Server(ref e) => write!(f, "Bitcoind server error: '{}'", e),
            BitcoindError::InvalidNetwork(ref expected, ref actual) => write!(
                f,
                "Bitcoind is running on '{}' but we are configured for '{}'",
                actual, expected
            ),
        }
    }
}

impl std::error::Error for BitcoindError {}

impl From<simple_http::Error> for BitcoindError {
    fn from(e: simple_http::Error) -> Self {
        Self::Server(Error::Transport(Box::new(e)))
    }
}

impl From<Error> for BitcoindError {
    fn from(e: Error) -> Self {
        Self::Server(e)
    }
}

fn check_bitcoind_network(
    bitcoind: &BitcoinD,
    config_network: &Network,
) -> Result<(), BitcoindError> {
    let bitcoind_net = bitcoind.bip70_net();
    let config_net = config_network.to_string();
    if bitcoind_net != config_net {
        return Err(BitcoindError::InvalidNetwork(bitcoind_net, config_net));
    }

    Ok(())
}

/// Some sanity checks to be done at startup to make sure our bitcoind isn't going to fail under
/// our feet for a legitimate reason.
fn bitcoind_sanity_checks(
    bitcoind: &BitcoinD,
    bitcoind_config: &BitcoindConfig,
) -> Result<(), BitcoindError> {
    check_bitcoind_network(&bitcoind, &bitcoind_config.network)
}

/// Connects to and sanity checks bitcoind.
pub fn start_bitcoind(
    bitcoind_config: &BitcoindConfig,
    vault_wallet_file: String,
) -> Result<BitcoinD, BitcoindError> {
    let bitcoind = BitcoinD::new(bitcoind_config, vault_wallet_file)?;

    while let Err(e) = bitcoind_sanity_checks(&bitcoind, bitcoind_config) {
        if e.is_warming_up() {
            log::info!("Bitcoind is warming up. Waiting for it to be back up.");
            thread::sleep(Duration::from_secs(3))
        } else {
            return Err(e);
        }
    }

    Ok(bitcoind)
}

/// Poll 'getblockchaininfo' until bitcoind is synced, by trying to not harass it.
pub fn wait_bitcoind_synced(bitcoind: &BitcoinD) {
    loop {
        let SyncInfo {
            headers,
            blocks,
            ibd,
            progress,
        } = bitcoind.synchronization_info();

        // We consider it good enough, as it may take some time to get to 1.0
        if !ibd && progress > 0.999 {
            break;
        }

        if ibd {
            log::info!(
                "Bitcoind is currently performing IBD, this may take some time (progress: {})",
                progress
            );
        } else if progress < 0.9 {
            log::info!(
                "Bitcoind is far behind network tip, this may take some time (progress: {})",
                progress
            );
        }

        // We don't want to harass bitcoind by locking cs_main while it's doing its best
        // to get up to date, therefore sleep long enough, but not too much.
        // Sleeping a second per 20 blocks seems a good upper bound estimation
        // (~7h for 500_000 blocks), so we divide it by 2 here in order to be
        // conservative. Eg if 10_000 are left to be downloaded we'll check back
        // in ~4min.
        let delta = headers.checked_sub(blocks).unwrap_or(0);
        #[cfg(test)]
        let min_duration = Duration::from_secs(1);
        #[cfg(not(test))]
        let min_duration = Duration::from_secs(5);
        let sleep_duration = std::cmp::max(Duration::from_secs(delta / 20 / 2), min_duration);

        log::info!(
            "Current sync progress: '{}' ({}/{}). We'll poll back in {} seconds.",
            progress,
            blocks,
            headers,
            sleep_duration.as_secs()
        );
        thread::sleep(sleep_duration);
    }
}

#[cfg(test)]
mod tests {
    use std::{
        fs,
        io::{BufRead, BufReader, Write},
        net, path, thread, time,
    };

    use super::{
        super::VAULT_WATCHONLY_FILENAME, start_bitcoind, wait_bitcoind_synced, BitcoindConfig,
        Network,
    };

    fn client_test<F>(cb: F) -> ()
    where
        F: FnOnce(net::TcpListener, BitcoindConfig) -> (),
    {
        let network = Network::Bitcoin;
        let cookie: path::PathBuf =
            format!("scratch_test_{:?}.cookie", thread::current().id()).into();
        // Will overwrite should it exist already
        fs::write(&cookie, &[0; 32]).unwrap();
        let addr: net::SocketAddr =
            net::SocketAddrV4::new(net::Ipv4Addr::new(127, 0, 0, 1), 0).into();
        let server = net::TcpListener::bind(&addr).unwrap();
        let addr = server.local_addr().unwrap();
        let bitcoind_config = BitcoindConfig {
            network,
            addr,
            cookie_path: cookie.clone(),
            poll_interval_secs: time::Duration::from_secs(2),
        };

        cb(server, bitcoind_config);
        // It may have already been removed as tests run in parallel
        fs::remove_file(&cookie).unwrap_or_else(|_| ());
    }

    // Read all bytes from the socket until the end of a JSON object, good enough approximation.
    fn read_til_json_end(stream: &mut net::TcpStream) {
        stream
            .set_read_timeout(Some(time::Duration::from_secs(5)))
            .unwrap();
        let mut reader = BufReader::new(stream);
        loop {
            let mut line = String::new();
            reader.read_line(&mut line).unwrap();

            if line.starts_with("Authorization") {
                let mut buf = vec![0; 256];
                reader.read_until(b'}', &mut buf).unwrap();
                return;
            }
        }
    }

    // Respond to the two "echo" sent at startup to sanity check the connection
    fn complete_sanity_check(server: &net::TcpListener) {
        let echo_resp =
            "HTTP/1.1 200\n\r\n{\"jsonrpc\":\"2.0\",\"id\":1,\"result\":[]}\n".as_bytes();

        // Read the first echo, respond to it
        let (mut stream, _) = server.accept().unwrap();
        read_til_json_end(&mut stream);
        stream.write_all(echo_resp).unwrap();
        stream.flush().unwrap();

        // Read the second echo, respond to it
        let (mut stream, _) = server.accept().unwrap();
        read_til_json_end(&mut stream);
        stream.write_all(echo_resp).unwrap();
        stream.flush().unwrap();
    }

    // Send them a pruned getblockchaininfo telling them we are on mainnet
    fn complete_network_check(server: &net::TcpListener) {
        let net_resp =
            "HTTP/1.1 200\n\r\n{\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{\"chain\":\"bitcoin\"}}\n"
                .as_bytes();
        let (mut stream, _) = server.accept().unwrap();
        read_til_json_end(&mut stream);
        stream.write_all(net_resp).unwrap();
        stream.flush().unwrap();
    }

    #[test]
    fn bitcoind_connection_garbage() {
        client_test(|server, bitcoind_config| {
            let client_thread = thread::spawn(move || {
                start_bitcoind(&bitcoind_config, VAULT_WATCHONLY_FILENAME.to_string())
            });

            // If we send garbage, it won't start
            let (mut stream, _) = server.accept().unwrap();
            read_til_json_end(&mut stream);
            stream.write_all(b"111GARBAGE\n").unwrap();
            client_thread.join().unwrap().unwrap_err();
        });
    }

    #[test]
    fn bitcoind_connection_wrong_net() {
        client_test(|server, bitcoind_config| {
            let client_thread = thread::spawn(move || {
                start_bitcoind(&bitcoind_config, VAULT_WATCHONLY_FILENAME.to_string())
            });

            complete_sanity_check(&server);

            // If we tell them we are on the wrong network, they'll crash
            let net_resp =
            "HTTP/1.1 200\n\r\n{\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{\"chain\":\"testnet\"}}\n"
                .as_bytes();
            let (mut stream, _) = server.accept().unwrap();
            read_til_json_end(&mut stream);
            stream.write_all(net_resp).unwrap();
            stream.flush().unwrap();
            client_thread.join().unwrap().unwrap_err();
        })
    }

    #[test]
    fn bitcoind_connection_sanity_check() {
        client_test(|server, bitcoind_config| {
            let client_thread = thread::spawn(move || {
                start_bitcoind(&bitcoind_config, VAULT_WATCHONLY_FILENAME.to_string())
            });

            complete_sanity_check(&server);
            complete_network_check(&server);

            // It should have started
            client_thread.join().unwrap().unwrap();
        })
    }

    #[test]
    fn bitcoind_connection_spurious_failure() {
        client_test(|server, bitcoind_config| {
            let client_thread = thread::spawn(move || {
                let bitcoind =
                    start_bitcoind(&bitcoind_config, VAULT_WATCHONLY_FILENAME.to_string()).unwrap();
                bitcoind.bip70_net();
            });

            complete_sanity_check(&server);
            complete_network_check(&server);

            // Read the second 'getblockchaininfo' req
            let (mut stream, _) = server.accept().unwrap();
            // We can hang for a bit..
            thread::sleep(time::Duration::from_secs(2));
            read_til_json_end(&mut stream);
            // .. And we them an error, they will retry
            let error_resp =
                "HTTP/1.1 200\n\r\n{\"jsonrpc\":\"2.0\",\"id\":1,\"error\":{\"code\":1,\"message\":\"\"}}\n".as_bytes();
            stream.write_all(error_resp).unwrap();
            stream.flush().unwrap();

            let (mut stream, _) = server.accept().unwrap();
            read_til_json_end(&mut stream);
            // We can hang, they won't timeout anytime soon
            thread::sleep(time::Duration::from_secs(3));
            // Now let them have the result
            let net_resp =
            "HTTP/1.1 200\n\r\n{\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{\"chain\":\"unchecked\"}}\n"
                .as_bytes();
            stream.write_all(net_resp).unwrap();
            stream.flush().unwrap();

            // It should have ended cleanly.
            client_thread.join().unwrap();
        })
    }

    #[test]
    fn bitcoind_sync_status() {
        client_test(|server, bitcoind_config| {
            let client_thread = thread::spawn(move || {
                let bitcoind =
                    start_bitcoind(&bitcoind_config, VAULT_WATCHONLY_FILENAME.to_string()).unwrap();
                wait_bitcoind_synced(&bitcoind);
            });

            complete_sanity_check(&server);
            complete_network_check(&server);

            // First tell them we aren't synced yet, they will sleep a bit and try again
            let (mut stream, _) = server.accept().unwrap();
            read_til_json_end(&mut stream);
            let resp =
            "HTTP/1.1 200\n\r\n{\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{\"blocks\":1000,\"headers\":1100,\"verificationprogress\":0.98,\"initialblockdownload\":false}}\n"
                .as_bytes();
            stream.write_all(resp).unwrap();
            stream.flush().unwrap();

            // Almost done!
            let (mut stream, _) = server.accept().unwrap();
            read_til_json_end(&mut stream);
            let resp =
            "HTTP/1.1 200\n\r\n{\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{\"blocks\":1099,\"headers\":1100,\"verificationprogress\":0.998,\"initialblockdownload\":false}}\n"
                .as_bytes();
            stream.write_all(resp).unwrap();
            stream.flush().unwrap();

            // Now tell them we are synced
            let (mut stream, _) = server.accept().unwrap();
            read_til_json_end(&mut stream);
            let resp =
            "HTTP/1.1 200\n\r\n{\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{\"blocks\":1,\"headers\":1,\"verificationprogress\":0.9991,\"initialblockdownload\":false}}\n"
                .as_bytes();
            stream.write_all(resp).unwrap();
            stream.flush().unwrap();

            // They should finish cleanly
            client_thread.join().unwrap();
        })
    }
}
