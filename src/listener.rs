use crate::{
    bitcoind::{interface::BitcoinD, BitcoindError},
    config::{Config, ScriptsConfig},
    database::{db_new_vault, db_vault, DatabaseError},
};

use revault_net::{
    message::{
        watchtower::{Signatures, Sigs, SigsResult},
        RequestParams, ResponseResult,
    },
    noise::SecretKey as NoisePrivkey,
};
use revault_tx::{
    bitcoin::{secp256k1, OutPoint},
    transactions::{transaction_chain, RevaultTransaction},
};

use std::{io, net::TcpListener, path, sync};

#[derive(Debug)]
pub enum ListenerError {
    Io(io::Error),
    Db(DatabaseError),
    Tx(revault_tx::Error),
    BitcoinD(BitcoindError),
    UnknownOutpoint(OutPoint),
}

impl std::fmt::Display for ListenerError {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self {
            Self::Io(ref e) => write!(f, "io error: '{}'", e),
            Self::Db(ref e) => write!(f, "database error: '{}'", e),
            Self::Tx(ref e) => write!(f, "transaction handling error: '{}'", e),
            Self::BitcoinD(ref e) => write!(f, "bitcoind communication error: '{}'", e),
            Self::UnknownOutpoint(ref o) => write!(f, "unknown outpoint: '{}'", o),
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
fn process_sigs_message<C: secp256k1::Verification>(
    db_path: &path::Path,
    scripts_config: &ScriptsConfig,
    bitcoind: &sync::Arc<BitcoinD>,
    msg: Sigs,
    secp: &secp256k1::Secp256k1<C>,
) -> Result<SigsResult, ListenerError> {
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

    // If we already have it, just acknowledge it.
    if db_vault(db_path, &msg.deposit_outpoint)?.is_some() {
        log::debug!(
            "Got signatures for already registered vault '{}'",
            &msg.deposit_outpoint
        );
        return Ok(SigsResult { ack: true });
    }

    // Otherwise, check the sigs they gave us are valid
    let Sigs {
        signatures:
            Signatures {
                emergency,
                cancel,
                unvault_emergency,
            },
        ..
    } = msg;
    for (key, sig) in emergency.iter() {
        // Note this checks for ALL|ACP.
        emer_tx.add_emer_sig(*key, *sig, secp)?;
    }
    emer_tx.finalize(secp)?;
    for (key, sig) in cancel.iter() {
        cancel_tx.add_cancel_sig(*key, *sig, secp)?;
    }
    cancel_tx.finalize(secp)?;
    for (key, sig) in unvault_emergency.iter() {
        unemer_tx.add_emer_sig(*key, *sig, secp)?;
    }
    unemer_tx.finalize(secp)?;

    db_new_vault(
        db_path,
        &msg.deposit_outpoint,
        msg.derivation_index,
        deposit_utxo.value,
        &emergency,
        &cancel,
        &unvault_emergency,
    )?;
    log::debug!("Registered a new vault at '{}'", &msg.deposit_outpoint);

    Ok(SigsResult { ack: true })
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
                RequestParams::WtSigs(sigs_msg) => {
                    log::debug!("Decoded request: {:#?}", sigs_msg);

                    match process_sigs_message(
                        db_path,
                        &config.scripts_config,
                        &bitcoind,
                        sigs_msg,
                        &secp_ctx,
                    ) {
                        Ok(res) => {
                            log::debug!("Decoded response: {:#?}", res);
                            Some(ResponseResult::WtSigs(res))
                        }
                        Err(e) => {
                            log::error!("Error when processing 'sig' message: '{}'.", e);
                            Some(ResponseResult::WtSigs(SigsResult { ack: false }))
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
        database::{
            db_cancel_signatures, db_emergency_signatures, db_unvault_emergency_signatures,
            setup_db,
        },
    };
    use revault_tx::{
        bitcoin::{util::bip32, Address, Amount, Network, SigHashType},
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

    // Sanity check `sigs` message processing
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
        let (_, cancel_tx, emer_tx, unemer_tx) = transaction_chain(
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

        // Not enough emergency signatures
        let sighash = emer_tx
            .signature_hash(0, SigHashType::AllPlusAnyoneCanPay)
            .unwrap();
        let sighash = secp256k1::Message::from_slice(&sighash).unwrap();
        let emergency: BTreeMap<secp256k1::PublicKey, secp256k1::Signature> = stakeholders_priv
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
        let cancel: BTreeMap<secp256k1::PublicKey, secp256k1::Signature> = BTreeMap::new();
        let unvault_emergency: BTreeMap<secp256k1::PublicKey, secp256k1::Signature> =
            BTreeMap::new();
        let signatures = Signatures {
            emergency,
            cancel,
            unvault_emergency,
        };
        let msg = Sigs {
            signatures,
            deposit_outpoint,
            derivation_index,
        };
        assert!(
            process_sigs_message(&db_path, &scripts_config, &bitcoind, msg, &secp_ctx)
                .unwrap_err()
                .to_string()
                .contains("Revault transaction finalisation error")
        );

        // Enough emergency sigs, but invalid signature type
        let bad_sighash = emer_tx.signature_hash(0, SigHashType::All).unwrap();
        let bad_sighash = secp256k1::Message::from_slice(&bad_sighash).unwrap();
        let emergency: BTreeMap<secp256k1::PublicKey, secp256k1::Signature> = stakeholders_priv
            .iter()
            .map(|xpriv| {
                let privkey = xpriv.derive_priv(&secp_ctx, &[derivation_index]).unwrap();
                (
                    privkey.private_key.public_key(&secp_ctx).key,
                    secp_ctx.sign(&bad_sighash, &privkey.private_key.key),
                )
            })
            .collect();
        let cancel: BTreeMap<secp256k1::PublicKey, secp256k1::Signature> = BTreeMap::new();
        let unvault_emergency: BTreeMap<secp256k1::PublicKey, secp256k1::Signature> =
            BTreeMap::new();
        let signatures = Signatures {
            emergency,
            cancel,
            unvault_emergency,
        };
        let msg = Sigs {
            signatures,
            deposit_outpoint,
            derivation_index,
        };
        assert!(
            process_sigs_message(&db_path, &scripts_config, &bitcoind, msg, &secp_ctx)
                .unwrap_err()
                .to_string()
                .contains("Invalid signature")
        );

        // Enough invalid emergency sigs
        let emergency: BTreeMap<secp256k1::PublicKey, secp256k1::Signature> = stakeholders_priv
            .iter()
            .map(|xpriv| {
                // Note the derivation index increment
                let privkey = xpriv
                    .derive_priv(&secp_ctx, &[derivation_index.increment().unwrap()])
                    .unwrap();
                (
                    privkey.private_key.public_key(&secp_ctx).key,
                    secp_ctx.sign(&sighash, &privkey.private_key.key),
                )
            })
            .collect();
        let cancel: BTreeMap<secp256k1::PublicKey, secp256k1::Signature> = BTreeMap::new();
        let unvault_emergency: BTreeMap<secp256k1::PublicKey, secp256k1::Signature> =
            BTreeMap::new();
        let signatures = Signatures {
            emergency,
            cancel,
            unvault_emergency,
        };
        let msg = Sigs {
            signatures,
            deposit_outpoint,
            derivation_index,
        };
        assert!(
            process_sigs_message(&db_path, &scripts_config, &bitcoind, msg, &secp_ctx)
                .unwrap_err()
                .to_string()
                .contains("Miniscript Error: could not satisfy")
        );

        // Valid emergency signatures.
        let emergency_valid: BTreeMap<secp256k1::PublicKey, secp256k1::Signature> =
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

        // Now do the same dance with Cancel signatures.

        // Not enough Cancel signatures
        let sighash = cancel_tx
            .signature_hash(0, SigHashType::AllPlusAnyoneCanPay)
            .unwrap();
        let sighash = secp256k1::Message::from_slice(&sighash).unwrap();
        let cancel: BTreeMap<secp256k1::PublicKey, secp256k1::Signature> = stakeholders_priv[..2]
            .iter()
            .map(|xpriv| {
                let privkey = xpriv.derive_priv(&secp_ctx, &[derivation_index]).unwrap();
                (
                    privkey.private_key.public_key(&secp_ctx).key,
                    secp_ctx.sign(&sighash, &privkey.private_key.key),
                )
            })
            .collect();
        let unvault_emergency: BTreeMap<secp256k1::PublicKey, secp256k1::Signature> =
            BTreeMap::new();
        let signatures = Signatures {
            emergency: emergency_valid.clone(),
            cancel,
            unvault_emergency,
        };
        let msg = Sigs {
            signatures,
            deposit_outpoint,
            derivation_index,
        };
        assert!(
            process_sigs_message(&db_path, &scripts_config, &bitcoind, msg, &secp_ctx)
                .unwrap_err()
                .to_string()
                .contains("Revault transaction finalisation error"),
        );

        // Enough Cancel sigs, but invalid signature type
        let bad_sighash = cancel_tx.signature_hash(0, SigHashType::All).unwrap();
        let bad_sighash = secp256k1::Message::from_slice(&bad_sighash).unwrap();
        let cancel: BTreeMap<secp256k1::PublicKey, secp256k1::Signature> = stakeholders_priv
            .iter()
            .map(|xpriv| {
                let privkey = xpriv.derive_priv(&secp_ctx, &[derivation_index]).unwrap();
                (
                    privkey.private_key.public_key(&secp_ctx).key,
                    secp_ctx.sign(&bad_sighash, &privkey.private_key.key),
                )
            })
            .collect();
        let unvault_emergency: BTreeMap<secp256k1::PublicKey, secp256k1::Signature> =
            BTreeMap::new();
        let signatures = Signatures {
            emergency: emergency_valid.clone(),
            cancel,
            unvault_emergency,
        };
        let msg = Sigs {
            signatures,
            deposit_outpoint,
            derivation_index,
        };
        assert!(
            process_sigs_message(&db_path, &scripts_config, &bitcoind, msg, &secp_ctx)
                .unwrap_err()
                .to_string()
                .contains("Invalid signature")
        );

        // Enough invalid Cancel sigs
        let cancel: BTreeMap<secp256k1::PublicKey, secp256k1::Signature> = stakeholders_priv
            .iter()
            .map(|xpriv| {
                // Note the derivation index increment
                let privkey = xpriv
                    .derive_priv(&secp_ctx, &[derivation_index.increment().unwrap()])
                    .unwrap();
                (
                    privkey.private_key.public_key(&secp_ctx).key,
                    secp_ctx.sign(&sighash, &privkey.private_key.key),
                )
            })
            .collect();
        let unvault_emergency: BTreeMap<secp256k1::PublicKey, secp256k1::Signature> =
            BTreeMap::new();
        let signatures = Signatures {
            emergency: emergency_valid.clone(),
            cancel,
            unvault_emergency,
        };
        let msg = Sigs {
            signatures,
            deposit_outpoint,
            derivation_index,
        };
        assert!(
            process_sigs_message(&db_path, &scripts_config, &bitcoind, msg, &secp_ctx)
                .unwrap_err()
                .to_string()
                .contains("Miniscript Error: could not satisfy")
        );

        // Valid Cancel signatures.
        let cancel_valid: BTreeMap<secp256k1::PublicKey, secp256k1::Signature> = stakeholders_priv
            .iter()
            .map(|xpriv| {
                let privkey = xpriv.derive_priv(&secp_ctx, &[derivation_index]).unwrap();
                (
                    privkey.private_key.public_key(&secp_ctx).key,
                    secp_ctx.sign(&sighash, &privkey.private_key.key),
                )
            })
            .collect();

        // Now do the same dance with Unvault Emergency signatures.

        // Not enough UnEmer signatures
        let sighash = unemer_tx
            .signature_hash(0, SigHashType::AllPlusAnyoneCanPay)
            .unwrap();
        let sighash = secp256k1::Message::from_slice(&sighash).unwrap();
        let unvault_emergency: BTreeMap<secp256k1::PublicKey, secp256k1::Signature> =
            stakeholders_priv[..2]
                .iter()
                .map(|xpriv| {
                    let privkey = xpriv.derive_priv(&secp_ctx, &[derivation_index]).unwrap();
                    (
                        privkey.private_key.public_key(&secp_ctx).key,
                        secp_ctx.sign(&sighash, &privkey.private_key.key),
                    )
                })
                .collect();
        let signatures = Signatures {
            emergency: emergency_valid.clone(),
            cancel: cancel_valid.clone(),
            unvault_emergency,
        };
        let msg = Sigs {
            signatures,
            deposit_outpoint,
            derivation_index,
        };
        assert!(
            process_sigs_message(&db_path, &scripts_config, &bitcoind, msg, &secp_ctx)
                .unwrap_err()
                .to_string()
                .contains("Revault transaction finalisation error")
        );

        // Enough UnEmer sigs, but invalid signature type
        let bad_sighash = unemer_tx.signature_hash(0, SigHashType::All).unwrap();
        let bad_sighash = secp256k1::Message::from_slice(&bad_sighash).unwrap();
        let unvault_emergency: BTreeMap<secp256k1::PublicKey, secp256k1::Signature> =
            stakeholders_priv
                .iter()
                .map(|xpriv| {
                    let privkey = xpriv.derive_priv(&secp_ctx, &[derivation_index]).unwrap();
                    (
                        privkey.private_key.public_key(&secp_ctx).key,
                        secp_ctx.sign(&bad_sighash, &privkey.private_key.key),
                    )
                })
                .collect();
        let signatures = Signatures {
            emergency: emergency_valid.clone(),
            cancel: cancel_valid.clone(),
            unvault_emergency,
        };
        let msg = Sigs {
            signatures,
            deposit_outpoint,
            derivation_index,
        };
        assert!(
            process_sigs_message(&db_path, &scripts_config, &bitcoind, msg, &secp_ctx)
                .unwrap_err()
                .to_string()
                .contains("Invalid signature")
        );

        // Enough invalid UnEmer sigs
        let unvault_emergency: BTreeMap<secp256k1::PublicKey, secp256k1::Signature> =
            stakeholders_priv
                .iter()
                .map(|xpriv| {
                    // Note the derivation index increment
                    let privkey = xpriv
                        .derive_priv(&secp_ctx, &[derivation_index.increment().unwrap()])
                        .unwrap();
                    (
                        privkey.private_key.public_key(&secp_ctx).key,
                        secp_ctx.sign(&sighash, &privkey.private_key.key),
                    )
                })
                .collect();
        let signatures = Signatures {
            emergency: emergency_valid.clone(),
            cancel: cancel_valid.clone(),
            unvault_emergency,
        };
        let msg = Sigs {
            signatures,
            deposit_outpoint,
            derivation_index,
        };
        assert!(
            process_sigs_message(&db_path, &scripts_config, &bitcoind, msg, &secp_ctx)
                .unwrap_err()
                .to_string()
                .contains("Miniscript Error: could not satisfy")
        );

        // Now, enough valid signatures of all kinds.
        let unemer_valid: BTreeMap<secp256k1::PublicKey, secp256k1::Signature> = stakeholders_priv
            .iter()
            .map(|xpriv| {
                let privkey = xpriv.derive_priv(&secp_ctx, &[derivation_index]).unwrap();
                (
                    privkey.private_key.public_key(&secp_ctx).key,
                    secp_ctx.sign(&sighash, &privkey.private_key.key),
                )
            })
            .collect();
        let signatures = Signatures {
            emergency: emergency_valid,
            cancel: cancel_valid,
            unvault_emergency: unemer_valid,
        };
        let msg = Sigs {
            signatures,
            deposit_outpoint,
            derivation_index,
        };
        // We must register the vault.
        assert!(
            process_sigs_message(&db_path, &scripts_config, &bitcoind, msg.clone(), &secp_ctx)
                .unwrap()
                .ack
        );
        // And it becomes (as well as all rev sigs) queriable.
        assert!(db_vault(&db_path, &deposit_outpoint).unwrap().is_some());
        assert!(!db_emergency_signatures(&db_path, 1).unwrap().is_empty());
        assert!(!db_cancel_signatures(&db_path, 1).unwrap().is_empty());
        assert!(!db_unvault_emergency_signatures(&db_path, 1)
            .unwrap()
            .is_empty());

        // If they send the signatures for the same vault again, we'll ACK immediately.
        assert!(
            process_sigs_message(&db_path, &scripts_config, &bitcoind, msg.clone(), &secp_ctx)
                .unwrap()
                .ack
        );

        // Done: remove the db
        fs::remove_file(&db_path).unwrap_or_else(|_| ());
    }
}
