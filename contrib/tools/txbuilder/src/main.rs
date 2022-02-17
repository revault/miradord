use std::{collections::BTreeMap, env, process, str::FromStr};

use revault_tx::{
    bitcoin::{
        consensus::encode::serialize_hex, secp256k1, util::bip32, Address, Amount, OutPoint,
        Script, TxOut,
    },
    miniscript::{
        descriptor::{Descriptor, DescriptorTrait},
        MiniscriptKey,
    },
    scripts::{CpfpDescriptor, DepositDescriptor, EmergencyAddress, UnvaultDescriptor},
    transactions::RevaultTransaction,
    txins::RevaultTxIn,
    txouts::RevaultTxOut,
};

macro_rules! from_json {
    ($str:expr) => {
        serde_json::from_str($str).unwrap_or_else(|e| {
            eprintln!("Failed to deserialize '{}' as JSON: '{}'", $str, e);
            process::exit(1);
        })
    };
}

fn xprivs_from_json(json_array: &str) -> Vec<bip32::ExtendedPrivKey> {
    let keys: Vec<String> = from_json!(json_array);
    keys.into_iter()
        .map(|key_str| {
            bip32::ExtendedPrivKey::from_str(&key_str).unwrap_or_else(|e| {
                eprintln!("Failed to parse xpriv '{}': '{}'", &key_str, e);
                process::exit(1);
            })
        })
        .collect()
}

fn privkeys_from_json(json_array: &str) -> Vec<secp256k1::SecretKey> {
    let keys: Vec<String> = from_json!(json_array);
    keys.into_iter()
        .map(|key_str| {
            secp256k1::SecretKey::from_str(&key_str).unwrap_or_else(|e| {
                eprintln!("Failed to parse privkey '{}': '{}'", &key_str, e);
                process::exit(1);
            })
        })
        .collect()
}

fn emer_address_from_arg(arg: &str) -> EmergencyAddress {
    let address = Address::from_str(&arg).unwrap_or_else(|e| {
        eprintln!("Failed to parse Emergency address '{}': '{}'", &arg, e);
        process::exit(1);
    });
    EmergencyAddress::from(address).unwrap_or_else(|e| {
        eprintln!("Failed to parse Emergency address '{}': '{}'", &arg, e);
        process::exit(1);
    })
}

fn desc_san_check<P: MiniscriptKey>(
    desc: &Descriptor<P>,
) -> Result<(), revault_tx::miniscript::Error> {
    match desc {
        Descriptor::Wsh(wsh) => wsh.sanity_check(),
        _ => unreachable!(),
    }
}

fn sanity_checks(
    dep_desc: &DepositDescriptor,
    unv_desc: &UnvaultDescriptor,
    cpfp_desc: &CpfpDescriptor,
) {
    desc_san_check(dep_desc.clone().inner()).unwrap_or_else(|e| {
        eprintln!("Error sanity checking xpub Deposit descriptor: '{:?}'", e);
        process::exit(1);
    });
    desc_san_check(unv_desc.clone().inner()).unwrap_or_else(|e| {
        eprintln!("Error sanity checking xpub Unvault descriptor: '{:?}'", e);
        process::exit(1);
    });
    desc_san_check(cpfp_desc.clone().inner()).unwrap_or_else(|e| {
        eprintln!("Error sanity checking xpub CPFP descriptor: '{:?}'", e);
        process::exit(1);
    });

    let secp = secp256k1::Secp256k1::new();
    for i in &[0, 5, 10, 100, 1000] {
        desc_san_check(dep_desc.derive((*i).into(), &secp).inner()).unwrap_or_else(|e| {
            eprintln!(
                "Error sanity checking derived Deposit descriptor: '{:?}'",
                e
            );
            process::exit(1);
        });
        desc_san_check(unv_desc.derive((*i).into(), &secp).inner()).unwrap_or_else(|e| {
            eprintln!(
                "Error sanity checking derived Unvault descriptor: '{:?}'",
                e
            );
            process::exit(1);
        });
        desc_san_check(cpfp_desc.derive((*i).into(), &secp).inner()).unwrap_or_else(|e| {
            eprintln!("Error sanity checking derived CPFP descriptor: '{:?}'", e);
            process::exit(1);
        });
    }
}

fn sign<C: secp256k1::Signing + secp256k1::Verification>(
    psbt: &mut impl RevaultTransaction,
    privkeys: &[secp256k1::SecretKey],
    secp: &secp256k1::Secp256k1<C>,
) -> BTreeMap<String, String> {
    let mut sigs = BTreeMap::new();

    for privkey in privkeys.iter() {
        let sighash = psbt.signature_hash(0).unwrap();
        let sighash = secp256k1::Message::from_slice(&sighash).unwrap();
        let pubkey = secp256k1::PublicKey::from_secret_key(&secp, &privkey);
        let sig = secp.sign(&sighash, &privkey);
        psbt.add_signature(0, pubkey, sig, &secp)
            .unwrap_or_else(|e| {
                eprintln!("Failed to add signature to '{:?}': '{}'", &psbt, e);
                process::exit(1);
            });
        sigs.insert(pubkey.to_string(), sig.to_string());
    }

    psbt.finalize(secp).unwrap_or_else(|e| {
        eprintln!("Failed to finalize psbt '{:?}': '{}'", &psbt, e);
        process::exit(1);
    });

    sigs
}

fn main() {
    let args: Vec<String> = env::args().collect();
    if args.len() != 11 {
        eprintln!(
            "Usage: '{} <stakeholders xprivs as a JSON array> <mans xprivs> <cosig privkeys> \
            <deposit descriptor> <unvault_descriptor> <cpfp descriptor> <Emer address> \
            <deposit outpoint> <deposit value> <derivation index>'",
            args[0]
        );
        process::exit(1);
    }

    let secp = revault_tx::bitcoin::secp256k1::Secp256k1::new();

    let stk_xprivs = xprivs_from_json(&args[1]);
    let man_xprivs = xprivs_from_json(&args[2]);
    let cosig_privkeys = privkeys_from_json(&args[3]);
    let deposit_desc = DepositDescriptor::from_str(&args[4]).unwrap_or_else(|e| {
        eprintln!("Failed to parse deposit descriptor '{}': '{}'", args[2], e);
        process::exit(1);
    });
    let unvault_desc = UnvaultDescriptor::from_str(&args[5]).unwrap_or_else(|e| {
        eprintln!("Failed to parse unvault descriptor '{}': '{}'", args[3], e);
        process::exit(1);
    });
    let cpfp_desc = CpfpDescriptor::from_str(&args[6]).unwrap_or_else(|e| {
        eprintln!("Failed to parse CPFP descriptor '{}': '{}'", args[1], e);
        process::exit(1);
    });
    let emer_address = emer_address_from_arg(&args[7]);
    let deposit_outpoint = OutPoint::from_str(&args[8]).unwrap_or_else(|e| {
        eprintln!("Failed to parse deposit outpoint '{}': '{}'", &args[6], e);
        process::exit(1);
    });
    let deposit_value: u64 = from_json!(&args[9]);
    let derivation_index: u32 = from_json!(&args[10]);
    sanity_checks(&deposit_desc, &unvault_desc, &cpfp_desc);

    let (mut unvault_tx, cancel_batch, mut emer_tx, mut unemer_tx) =
        revault_tx::transactions::transaction_chain(
            deposit_outpoint,
            Amount::from_sat(deposit_value),
            &deposit_desc,
            &unvault_desc,
            &cpfp_desc,
            derivation_index.into(),
            emer_address,
            &secp,
        )
        .unwrap_or_else(|e| {
            eprintln!("Failed to derive transaction chain: '{}'", e);
            process::exit(1);
        });
    let mut cancel_tx = cancel_batch.into_feerate_20();
    let der_unvault_desc = unvault_desc.derive(derivation_index.into(), &secp);
    let unvault_txin = unvault_tx.spend_unvault_txin(&der_unvault_desc);
    let spend_txo = revault_tx::txouts::SpendTxOut::new(TxOut {
        value: unvault_txin.txout().txout().value - 100_000,
        script_pubkey: Script::from_str("00144314bbb53718d0508343375a6c580421d3108cd6").unwrap(),
    });
    let der_cpfp_desc = cpfp_desc.derive(derivation_index.into(), &secp);
    let mut spend_tx = revault_tx::transactions::SpendTransaction::new(
        vec![unvault_txin],
        vec![spend_txo],
        None,
        &der_cpfp_desc,
        0,
        true,
    )
    .unwrap_or_else(|e| {
        eprintln!("Failed to derive Spend transaction: '{}'", e);
        process::exit(1);
    });

    let stk_privkeys: Vec<secp256k1::SecretKey> = stk_xprivs
        .iter()
        .map(|xpriv| {
            xpriv
                .derive_priv(&secp, &[derivation_index.into()])
                .unwrap()
                .private_key
                .key
        })
        .collect();
    let unvault_sigs = sign(&mut unvault_tx, &stk_privkeys, &secp);
    let cancel_sigs = sign(&mut cancel_tx, &stk_privkeys, &secp);
    let emer_sigs = sign(&mut emer_tx, &stk_privkeys, &secp);
    let unemer_sigs = sign(&mut unemer_tx, &stk_privkeys, &secp);
    let spend_privkeys: Vec<secp256k1::SecretKey> = man_xprivs
        .iter()
        .map(|xpriv| {
            xpriv
                .derive_priv(&secp, &[derivation_index.into()])
                .unwrap()
                .private_key
                .key
        })
        .chain(cosig_privkeys.into_iter())
        .collect();
    sign(&mut spend_tx, &spend_privkeys, &secp);

    println!(
        "{:#}",
        serde_json::json!({
            "unvault": serde_json::json!({
                "tx": serialize_hex(&unvault_tx.into_tx()),
                "sigs": unvault_sigs,
            }),
            "cancel": serde_json::json!({
                "tx": serialize_hex(&cancel_tx.into_tx()),
                "sigs": cancel_sigs,
            }),
            "emer": serde_json::json!({
                "tx": serialize_hex(&emer_tx.into_tx()),
                "sigs": emer_sigs,
            }),
            "unemer": serde_json::json!({
                "tx": serialize_hex(&unemer_tx.into_tx()),
                "sigs": unemer_sigs,
            }),
            "spend": serde_json::json!({
                "tx": serialize_hex(&spend_tx.into_tx()),
            })
        })
    );
}
