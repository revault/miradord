use crate::{
    bitcoind::{interface::BitcoinD, BitcoindError},
    config::{Config, ScriptsConfig},
    database::{
        db_delegate_vault, db_new_vault, db_store_cancel_sigs, db_store_unemer_sigs,
        db_unvault_emergency_signatures, db_vault, DatabaseError,
    },
};

use revault_net::{
    message::{
        watchtower::{Sig, SigResult},
        RequestParams, ResponseResult,
    },
    noise::SecretKey as NoisePrivkey,
};
use revault_tx::{
    bitcoin::{secp256k1, OutPoint, Txid},
    transactions::{transaction_chain, RevaultTransaction},
};

use std::{io, net::TcpListener, path, sync};

#[derive(Debug)]
pub enum ListenerError {
    Io(io::Error),
    Db(DatabaseError),
    Tx(revault_tx::Error),
    BitcoinD(BitcoindError),
    UnknownTxid(Txid),
    UnknownOutpoint(OutPoint),
    UnexpectedEmerSig(OutPoint),
    UnexpectedUnEmerSig(OutPoint),
    UnexpectedCancelSig(OutPoint),
}

impl std::fmt::Display for ListenerError {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self {
            Self::Io(ref e) => write!(f, "io error: '{}'", e),
            Self::Db(ref e) => write!(f, "database error: '{}'", e),
            Self::Tx(ref e) => write!(f, "transaction handling error: '{}'", e),
            Self::BitcoinD(ref e) => write!(f, "bitcoind communication error: '{}'", e),
            Self::UnknownOutpoint(ref o) => write!(f, "unknown outpoint: '{}'", o),
            Self::UnknownTxid(ref t) => write!(f, "unknown txid: '{}'", t),
            Self::UnexpectedEmerSig(ref o) => write!(f, "received an Emergency signature for an \
                                                         existing vault ('{}')", o),
            Self::UnexpectedUnEmerSig(ref o) => write!(f, "received an UnvaultEmergency signature for a \
                                                           delegated vault or before receiving Emergency \
                                                           signatures for  '{}'", o),
            Self::UnexpectedCancelSig(ref o) => write!(f, "received a Cancel signature for a \
                                                           delegated vault or before receiving both Emergency \
                                                           and UnEmer signatures for  '{}'", o),
        }
    }
}

impl std::error::Error for ListenerError {}

impl From<io::Error> for ListenerError {
    fn from(e: io::Error) -> Self {
        Self::Io(e)
    }
}

impl From<DatabaseError> for ListenerError {
    fn from(e: DatabaseError) -> Self {
        Self::Db(e)
    }
}

impl From<revault_tx::Error> for ListenerError {
    fn from(e: revault_tx::Error) -> Self {
        Self::Tx(e)
    }
}

impl From<revault_tx::error::InputSatisfactionError> for ListenerError {
    fn from(e: revault_tx::error::InputSatisfactionError) -> Self {
        Self::Tx(e.into())
    }
}

impl From<BitcoindError> for ListenerError {
    fn from(e: BitcoindError) -> Self {
        Self::BitcoinD(e)
    }
}

// TODO: make Emergency sharing optional
fn process_sig_message<C: secp256k1::Verification>(
    db_path: &path::Path,
    scripts_config: &ScriptsConfig,
    bitcoind: &sync::Arc<BitcoinD>,
    msg: Sig,
    secp: &secp256k1::Secp256k1<C>,
) -> Result<SigResult, ListenerError> {
    let deposit_utxo = bitcoind
        .utxoinfo(&msg.deposit_outpoint)
        .ok_or(ListenerError::UnknownOutpoint(msg.deposit_outpoint))?;
    let (_, mut cancel_tx, mut emer_tx, mut unemer_tx) = transaction_chain(
        msg.deposit_outpoint,
        deposit_utxo.value,
        &scripts_config.deposit_descriptor,
        &scripts_config.unvault_descriptor,
        &scripts_config.cpfp_descriptor,
        msg.derivation_index,
        scripts_config.emergency_address.clone(),
        0, /* FIXME: remove from API */
        secp,
    )?;

    if msg.txid == emer_tx.txid() {
        // Receiving the signatures of an Emergency tx means they just signed the revocation
        // transactions. The vault must not exist yet.
        if db_vault(db_path, &msg.deposit_outpoint)?.is_some() {
            return Err(ListenerError::UnexpectedEmerSig(msg.deposit_outpoint));
        }

        // Check that the sig they gave us are valid, and enough to make the transaction valid.
        for (key, sig) in msg.signatures.iter() {
            // Note this checks for ALL|ACP.
            emer_tx.add_emer_sig(*key, *sig, secp)?;
        }
        emer_tx.finalize(secp)?;

        // Ok, we have enough info to be able to broadcast it. Store it as a not-yet-delegated
        // vault.
        db_new_vault(
            db_path,
            &msg.deposit_outpoint,
            msg.derivation_index,
            deposit_utxo.value,
            &msg.signatures,
        )?;
        log::debug!("Registered a new vault at '{}'", &msg.deposit_outpoint);

        Ok(SigResult {
            ack: true,
            txid: msg.txid,
        })
    } else if msg.txid == unemer_tx.txid() {
        // If we are receiving the signatures of an UnEmer tx they must have already sent the sigs
        // for the Emergency one.
        let db_vault = db_vault(db_path, &msg.deposit_outpoint)?
            .ok_or(ListenerError::UnexpectedUnEmerSig(msg.deposit_outpoint))?;
        if db_vault.delegated || !db_unvault_emergency_signatures(db_path, db_vault.id)?.is_empty()
        {
            return Err(ListenerError::UnexpectedUnEmerSig(msg.deposit_outpoint));
        }

        // Check that the sig they gave us are valid, and enough to make the transaction valid
        // before storing it.
        for (key, sig) in msg.signatures.iter() {
            unemer_tx.add_emer_sig(*key, *sig, secp)?;
        }
        unemer_tx.finalize(secp)?;
        db_store_unemer_sigs(db_path, &msg.deposit_outpoint, &msg.signatures)?;
        log::debug!(
            "Got UnEmer transaction signatures for vault at '{}'",
            &msg.deposit_outpoint
        );

        Ok(SigResult {
            ack: true,
            txid: msg.txid,
        })
    } else if msg.txid == cancel_tx.txid() {
        // Receiving the signatures of a Cancel tx means they just delegated this vault and we need
        // to start watching for Unvault broadcasts.
        let db_vault = db_vault(db_path, &msg.deposit_outpoint)?
            .ok_or(ListenerError::UnexpectedCancelSig(msg.deposit_outpoint))?;
        if db_vault.delegated {
            return Err(ListenerError::UnexpectedCancelSig(msg.deposit_outpoint));
        }
        // We check their validity before storing them hence it's enough to just check if they are
        // present.
        if db_unvault_emergency_signatures(db_path, db_vault.id)?.is_empty() {
            return Err(ListenerError::UnexpectedCancelSig(msg.deposit_outpoint));
        }

        // Check that the sig they gave us are valid, and enough to make the transaction valid.
        for (key, sig) in msg.signatures.iter() {
            cancel_tx.add_cancel_sig(*key, *sig, secp)?;
        }
        cancel_tx.finalize(secp)?;

        // Ok, store those signatures and mark the vault as being delegated if it's not already
        db_store_cancel_sigs(db_path, &msg.deposit_outpoint, &msg.signatures)?;
        if !db_vault.delegated {
            db_delegate_vault(db_path, &msg.deposit_outpoint)?;
        }
        log::debug!(
            "Got Cancel transaction signatures for vault at '{}'. Now watching for Unvault broadcast.",
            &msg.deposit_outpoint
        );

        Ok(SigResult {
            ack: true,
            txid: msg.txid,
        })
    } else {
        Err(ListenerError::UnknownTxid(msg.txid))
    }
}

/// Wait for connections from the stakeholder on the configured interface and process `sig` messages.
pub fn listener_main(
    db_path: &path::Path,
    config: &Config,
    bitcoind: sync::Arc<BitcoinD>,
    noise_privkey: &NoisePrivkey,
) -> Result<(), ListenerError> {
    let host = config.listen;
    let listener = TcpListener::bind(host)?;
    let secp_ctx = secp256k1::Secp256k1::verification_only();

    log::info!("Listener thread started.");

    // There is only going to be a small amount of ephemeral connections, there is no need for
    // complexity so just sequentially process each message.
    loop {
        let mut kk_stream = match revault_net::transport::KKTransport::accept(
            &listener,
            noise_privkey,
            &[config.stakeholder_noise_key],
        ) {
            Ok(s) => s,
            Err(e) => {
                log::error!("Listener: Error during handshake: '{}'", e);
                continue;
            }
        };
        log::trace!("New connection");

        // Handle all messages from this connection.
        loop {
            match kk_stream.read_req(|req_params| match req_params {
                RequestParams::WtSig(sig_msg) => {
                    log::debug!("Decoded request: {:#?}", sig_msg);

                    let txid = sig_msg.txid;
                    match process_sig_message(
                        db_path,
                        &config.scripts_config,
                        &bitcoind,
                        sig_msg,
                        &secp_ctx,
                    ) {
                        Ok(res) => {
                            log::debug!("Decoded response: {:#?}", res);
                            Some(ResponseResult::WtSig(res))
                        }
                        Err(e) => {
                            log::error!("Error when processing 'sig' message: '{}'.", e);
                            Some(ResponseResult::WtSig(SigResult { ack: false, txid }))
                        }
                    }
                }
                _ => {
                    log::error!("Unexpected message: '{:?}'", req_params);
                    None
                }
            }) {
                Ok(buf) => buf,
                Err(revault_net::Error::Transport(e)) => {
                    log::error!(
                        "Transport error trying to read request: '{}'. Dropping connection.",
                        e
                    );
                    break;
                }
                Err(e) => {
                    log::error!("Error handling request: '{}'", e);
                    continue;
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use std::{
        collections::BTreeMap,
        fs,
        io::{BufRead, BufReader, Write},
        iter::repeat_with,
        net, path,
        str::FromStr,
        thread, time,
    };

    use super::*;

    use crate::{
        config::BitcoindConfig,
        database::{db_cancel_signatures, db_emergency_signatures, setup_db},
    };
    use revault_tx::{
        bitcoin::{util::bip32, Address, Amount, Network, SigHashType, Txid},
        miniscript::descriptor::{DescriptorPublicKey, DescriptorXKey, Wildcard},
        scripts::{CpfpDescriptor, DepositDescriptor, EmergencyAddress, UnvaultDescriptor},
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
    fn complete_bitcoind_sanity_check(server: &net::TcpListener) {
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

    fn dummy_bitcoind(deposit_amount: Amount) -> BitcoinD {
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

        thread::spawn({
            move || {
                complete_bitcoind_sanity_check(&server);

                // The listener is always only going to poll for gettxout (and only care about the
                // value of the utxo). So, just listen and answer a dummy gettxout with the right
                // deposit value forever.
                loop {
                    let gettxout_resp =
                        format!("HTTP/1.1 200\n\r\n{{\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{{\"bestblock\":\"000000000000000000143e36c08e4686f2c7e317bce11c192106ca5ae44207cd\",\"confirmations\":1,\"value\":{}}}}}\n", deposit_amount.as_btc());
                    let gettxout_resp = gettxout_resp.as_bytes();

                    let (mut stream, _) = server.accept().unwrap();
                    read_til_json_end(&mut stream);
                    stream.write_all(gettxout_resp).unwrap();
                    stream.flush().unwrap();
                }
            }
        });
        let bitcoind_client =
            BitcoinD::new(&bitcoind_config, "dummy_filename".to_string()).unwrap();
        // We don't need it anymore
        fs::remove_file(&cookie).unwrap_or_else(|_| ());

        bitcoind_client
    }

    // Sanity check `sig` message processing
    #[test]
    fn sig_message() {
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
        let scripts_config = ScriptsConfig {
            deposit_descriptor,
            unvault_descriptor,
            cpfp_descriptor,
            emergency_address,
        };

        // Remove any potential leftover from a previous crashed session and create the database
        fs::remove_file(&db_path).unwrap_or_else(|_| ());
        setup_db(
            &db_path,
            &scripts_config.deposit_descriptor,
            &scripts_config.unvault_descriptor,
            &scripts_config.cpfp_descriptor,
            Network::Bitcoin,
        )
        .unwrap();

        // Given a new vault deposit at this outpoint try different scenarii
        let deposit_outpoint = OutPoint::from_str(
            "f21885abfb5a0706d0d56542fbff2483e455a788075c85f567c07df775f3742b:0",
        )
        .unwrap();
        let deposit_value = Amount::from_sat(8765432);
        let derivation_index = bip32::ChildNumber::from(45678);
        let (_, cancel, emer, unemer) = transaction_chain(
            deposit_outpoint,
            deposit_value,
            &scripts_config.deposit_descriptor,
            &scripts_config.unvault_descriptor,
            &scripts_config.cpfp_descriptor,
            derivation_index,
            scripts_config.emergency_address.clone(),
            0,
            &secp_ctx,
        )
        .unwrap();

        // This starts a dummy server to answer our gettxout requests
        let bitcoind = sync::Arc::from(dummy_bitcoind(deposit_value));

        // Invalid txid, no sigs
        let msg = Sig {
            signatures: BTreeMap::new(),
            txid: Txid::default(),
            deposit_outpoint,
            derivation_index,
        };
        assert!(
            process_sig_message(&db_path, &scripts_config, &bitcoind, msg, &secp_ctx)
                .unwrap_err()
                .to_string()
                .contains("unknown txid"),
        );

        // An UnEmer before an Emer
        let msg = Sig {
            signatures: BTreeMap::new(),
            txid: unemer.txid(),
            deposit_outpoint,
            derivation_index,
        };
        assert!(
            process_sig_message(&db_path, &scripts_config, &bitcoind, msg, &secp_ctx)
                .unwrap_err()
                .to_string()
                .contains("received an UnvaultEmergency")
        );

        // A Cancel before an Emer
        let msg = Sig {
            signatures: BTreeMap::new(),
            txid: cancel.txid(),
            deposit_outpoint,
            derivation_index,
        };
        assert!(
            process_sig_message(&db_path, &scripts_config, &bitcoind, msg, &secp_ctx)
                .unwrap_err()
                .to_string()
                .contains("received a Cancel")
        );

        // Not enough signatures
        let sighash = emer
            .signature_hash(0, SigHashType::AllPlusAnyoneCanPay)
            .unwrap();
        let sighash = secp256k1::Message::from_slice(&sighash).unwrap();
        let signatures: BTreeMap<secp256k1::PublicKey, secp256k1::Signature> = stakeholders_priv
            [..2]
            .iter()
            .map(|xpriv| {
                let privkey = xpriv.derive_priv(&secp_ctx, &[derivation_index]).unwrap();
                (
                    privkey.private_key.public_key(&secp_ctx).key,
                    secp_ctx.sign(&sighash, &privkey.private_key.key),
                )
            })
            .collect();
        let msg = Sig {
            signatures,
            txid: emer.txid(),
            deposit_outpoint,
            derivation_index,
        };
        assert!(
            process_sig_message(&db_path, &scripts_config, &bitcoind, msg, &secp_ctx)
                .unwrap_err()
                .to_string()
                .contains("Revault transaction finalisation error")
        );

        // Enough sigs, but invalid signature type
        let bad_sighash = emer.signature_hash(0, SigHashType::All).unwrap();
        let bad_sighash = secp256k1::Message::from_slice(&bad_sighash).unwrap();
        let signatures: BTreeMap<secp256k1::PublicKey, secp256k1::Signature> = stakeholders_priv
            .iter()
            .map(|xpriv| {
                let privkey = xpriv.derive_priv(&secp_ctx, &[derivation_index]).unwrap();
                (
                    privkey.private_key.public_key(&secp_ctx).key,
                    secp_ctx.sign(&bad_sighash, &privkey.private_key.key),
                )
            })
            .collect();
        let msg = Sig {
            signatures,
            txid: emer.txid(),
            deposit_outpoint,
            derivation_index,
        };
        assert!(
            process_sig_message(&db_path, &scripts_config, &bitcoind, msg, &secp_ctx)
                .unwrap_err()
                .to_string()
                .contains("Invalid signature")
        );

        // Enough invalid sigs
        let signatures: BTreeMap<secp256k1::PublicKey, secp256k1::Signature> = stakeholders_priv
            .iter()
            .map(|xpriv| {
                let privkey = xpriv
                    .derive_priv(&secp_ctx, &[derivation_index.increment().unwrap()])
                    .unwrap();
                (
                    privkey.private_key.public_key(&secp_ctx).key,
                    secp_ctx.sign(&sighash, &privkey.private_key.key),
                )
            })
            .collect();
        let msg = Sig {
            signatures,
            txid: emer.txid(),
            deposit_outpoint,
            derivation_index,
        };
        assert!(
            process_sig_message(&db_path, &scripts_config, &bitcoind, msg, &secp_ctx)
                .unwrap_err()
                .to_string()
                .contains("Miniscript Error: could not satisfy")
        );

        // Enough *valid* sigs, vault must now be registered and Emer sigs present
        let signatures: BTreeMap<secp256k1::PublicKey, secp256k1::Signature> = stakeholders_priv
            .iter()
            .map(|xpriv| {
                let privkey = xpriv.derive_priv(&secp_ctx, &[derivation_index]).unwrap();
                (
                    privkey.private_key.public_key(&secp_ctx).key,
                    secp_ctx.sign(&sighash, &privkey.private_key.key),
                )
            })
            .collect();
        let msg = Sig {
            signatures,
            txid: emer.txid(),
            deposit_outpoint,
            derivation_index,
        };
        assert_eq!(
            process_sig_message(&db_path, &scripts_config, &bitcoind, msg, &secp_ctx).unwrap(),
            SigResult {
                ack: true,
                txid: emer.txid()
            }
        );
        let vault = db_vault(&db_path, &deposit_outpoint).unwrap().unwrap();
        assert_eq!(vault.delegated, false);
        assert_eq!(
            db_emergency_signatures(&db_path, vault.id).unwrap().len(),
            stakeholders.len()
        );

        // We won't accept to process an Emergency for this vault anymore
        let msg = Sig {
            signatures: BTreeMap::new(),
            txid: emer.txid(),
            deposit_outpoint,
            derivation_index,
        };
        assert!(
            process_sig_message(&db_path, &scripts_config, &bitcoind, msg, &secp_ctx)
                .unwrap_err()
                .to_string()
                .contains("received an Emergency")
        );

        // We won't accept to process a Cancel just yet
        let msg = Sig {
            signatures: BTreeMap::new(),
            txid: cancel.txid(),
            deposit_outpoint,
            derivation_index,
        };
        assert!(
            process_sig_message(&db_path, &scripts_config, &bitcoind, msg, &secp_ctx)
                .unwrap_err()
                .to_string()
                .contains("received a Cancel")
        );

        let sighash = unemer
            .signature_hash(0, SigHashType::AllPlusAnyoneCanPay)
            .unwrap();
        let sighash = secp256k1::Message::from_slice(&sighash).unwrap();
        let signatures: BTreeMap<secp256k1::PublicKey, secp256k1::Signature> = stakeholders_priv
            [..2]
            .iter()
            .map(|xpriv| {
                let privkey = xpriv.derive_priv(&secp_ctx, &[derivation_index]).unwrap();
                (
                    privkey.private_key.public_key(&secp_ctx).key,
                    secp_ctx.sign(&sighash, &privkey.private_key.key),
                )
            })
            .collect();
        let msg = Sig {
            signatures,
            txid: unemer.txid(),
            deposit_outpoint,
            derivation_index,
        };
        assert!(
            process_sig_message(&db_path, &scripts_config, &bitcoind, msg, &secp_ctx)
                .unwrap_err()
                .to_string()
                .contains("Revault transaction finalisation error")
        );

        // Enough sigs, but invalid signature type
        let bad_sighash = unemer.signature_hash(0, SigHashType::All).unwrap();
        let bad_sighash = secp256k1::Message::from_slice(&bad_sighash).unwrap();
        let signatures: BTreeMap<secp256k1::PublicKey, secp256k1::Signature> = stakeholders_priv
            .iter()
            .map(|xpriv| {
                let privkey = xpriv.derive_priv(&secp_ctx, &[derivation_index]).unwrap();
                (
                    privkey.private_key.public_key(&secp_ctx).key,
                    secp_ctx.sign(&bad_sighash, &privkey.private_key.key),
                )
            })
            .collect();
        let msg = Sig {
            signatures,
            txid: unemer.txid(),
            deposit_outpoint,
            derivation_index,
        };
        assert!(
            process_sig_message(&db_path, &scripts_config, &bitcoind, msg, &secp_ctx)
                .unwrap_err()
                .to_string()
                .contains("Invalid signature")
        );

        // Enough invalid sigs
        let signatures: BTreeMap<secp256k1::PublicKey, secp256k1::Signature> = stakeholders_priv
            .iter()
            .map(|xpriv| {
                let privkey = xpriv
                    .derive_priv(&secp_ctx, &[derivation_index.increment().unwrap()])
                    .unwrap();
                (
                    privkey.private_key.public_key(&secp_ctx).key,
                    secp_ctx.sign(&sighash, &privkey.private_key.key),
                )
            })
            .collect();
        let msg = Sig {
            signatures,
            txid: unemer.txid(),
            deposit_outpoint,
            derivation_index,
        };
        assert!(
            process_sig_message(&db_path, &scripts_config, &bitcoind, msg, &secp_ctx)
                .unwrap_err()
                .to_string()
                .contains("Miniscript Error: could not satisfy")
        );

        // Enough *valid* sigs, UnvaultEmer sigs are now stored.
        let signatures: BTreeMap<secp256k1::PublicKey, secp256k1::Signature> = stakeholders_priv
            .iter()
            .map(|xpriv| {
                let privkey = xpriv.derive_priv(&secp_ctx, &[derivation_index]).unwrap();
                (
                    privkey.private_key.public_key(&secp_ctx).key,
                    secp_ctx.sign(&sighash, &privkey.private_key.key),
                )
            })
            .collect();
        let msg = Sig {
            signatures,
            txid: unemer.txid(),
            deposit_outpoint,
            derivation_index,
        };
        assert_eq!(
            process_sig_message(&db_path, &scripts_config, &bitcoind, msg, &secp_ctx).unwrap(),
            SigResult {
                ack: true,
                txid: unemer.txid()
            }
        );
        let vault = db_vault(&db_path, &deposit_outpoint).unwrap().unwrap();
        assert_eq!(vault.delegated, false);
        assert_eq!(
            db_unvault_emergency_signatures(&db_path, vault.id)
                .unwrap()
                .len(),
            stakeholders.len()
        );

        // We won't accept it twice
        let msg = Sig {
            signatures: BTreeMap::new(),
            txid: unemer.txid(),
            deposit_outpoint,
            derivation_index,
        };
        assert!(
            process_sig_message(&db_path, &scripts_config, &bitcoind, msg, &secp_ctx)
                .unwrap_err()
                .to_string()
                .contains("received an UnvaultEmergency")
        );

        // We won't accept to process an Emergency either
        let msg = Sig {
            signatures: BTreeMap::new(),
            txid: emer.txid(),
            deposit_outpoint,
            derivation_index,
        };
        assert!(
            process_sig_message(&db_path, &scripts_config, &bitcoind, msg, &secp_ctx)
                .unwrap_err()
                .to_string()
                .contains("received an Emergency")
        );

        let sighash = cancel
            .signature_hash(0, SigHashType::AllPlusAnyoneCanPay)
            .unwrap();
        let sighash = secp256k1::Message::from_slice(&sighash).unwrap();
        let signatures: BTreeMap<secp256k1::PublicKey, secp256k1::Signature> = stakeholders_priv
            [..2]
            .iter()
            .map(|xpriv| {
                let privkey = xpriv.derive_priv(&secp_ctx, &[derivation_index]).unwrap();
                (
                    privkey.private_key.public_key(&secp_ctx).key,
                    secp_ctx.sign(&sighash, &privkey.private_key.key),
                )
            })
            .collect();
        let msg = Sig {
            signatures,
            txid: cancel.txid(),
            deposit_outpoint,
            derivation_index,
        };
        assert!(
            process_sig_message(&db_path, &scripts_config, &bitcoind, msg, &secp_ctx)
                .unwrap_err()
                .to_string()
                .contains("Revault transaction finalisation error")
        );

        // Enough sigs, but invalid signature type
        let bad_sighash = cancel.signature_hash(0, SigHashType::All).unwrap();
        let bad_sighash = secp256k1::Message::from_slice(&bad_sighash).unwrap();
        let signatures: BTreeMap<secp256k1::PublicKey, secp256k1::Signature> = stakeholders_priv
            .iter()
            .map(|xpriv| {
                let privkey = xpriv.derive_priv(&secp_ctx, &[derivation_index]).unwrap();
                (
                    privkey.private_key.public_key(&secp_ctx).key,
                    secp_ctx.sign(&bad_sighash, &privkey.private_key.key),
                )
            })
            .collect();
        let msg = Sig {
            signatures,
            txid: cancel.txid(),
            deposit_outpoint,
            derivation_index,
        };
        assert!(
            process_sig_message(&db_path, &scripts_config, &bitcoind, msg, &secp_ctx)
                .unwrap_err()
                .to_string()
                .contains("Invalid signature")
        );

        // Enough invalid sigs
        let signatures: BTreeMap<secp256k1::PublicKey, secp256k1::Signature> = stakeholders_priv
            .iter()
            .map(|xpriv| {
                let privkey = xpriv
                    .derive_priv(&secp_ctx, &[derivation_index.increment().unwrap()])
                    .unwrap();
                (
                    privkey.private_key.public_key(&secp_ctx).key,
                    secp_ctx.sign(&sighash, &privkey.private_key.key),
                )
            })
            .collect();
        let msg = Sig {
            signatures,
            txid: cancel.txid(),
            deposit_outpoint,
            derivation_index,
        };
        assert!(
            process_sig_message(&db_path, &scripts_config, &bitcoind, msg, &secp_ctx)
                .unwrap_err()
                .to_string()
                .contains("Miniscript Error: could not satisfy")
        );

        // Enough *valid* sigs, Cancel sigs are now stored.
        let signatures: BTreeMap<secp256k1::PublicKey, secp256k1::Signature> = stakeholders_priv
            .iter()
            .map(|xpriv| {
                let privkey = xpriv.derive_priv(&secp_ctx, &[derivation_index]).unwrap();
                (
                    privkey.private_key.public_key(&secp_ctx).key,
                    secp_ctx.sign(&sighash, &privkey.private_key.key),
                )
            })
            .collect();
        let msg = Sig {
            signatures,
            txid: cancel.txid(),
            deposit_outpoint,
            derivation_index,
        };
        assert_eq!(
            process_sig_message(&db_path, &scripts_config, &bitcoind, msg, &secp_ctx).unwrap(),
            SigResult {
                ack: true,
                txid: cancel.txid()
            }
        );
        let vault = db_vault(&db_path, &deposit_outpoint).unwrap().unwrap();
        assert!(vault.delegated);
        assert_eq!(
            db_cancel_signatures(&db_path, vault.id).unwrap().len(),
            stakeholders.len()
        );

        // Done: remove the db
        fs::remove_file(&db_path).unwrap_or_else(|_| ());
    }
}
