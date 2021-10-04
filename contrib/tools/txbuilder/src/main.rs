use std::{collections::BTreeMap, env, process, str::FromStr};

use revault_tx::{
    bitcoin::{
        consensus::encode::serialize_hex, secp256k1, util::bip32, Address, Amount, OutPoint,
        SigHashType,
    },
    miniscript::{
        descriptor::{Descriptor, DescriptorTrait},
        MiniscriptKey,
    },
    scripts::{CpfpDescriptor, DepositDescriptor, EmergencyAddress, UnvaultDescriptor},
    transactions::RevaultTransaction,
};

macro_rules! from_json {
    ($str:expr) => {
        serde_json::from_str($str).unwrap_or_else(|e| {
            eprintln!("Failed to deserialize '{}' as JSON: '{}'", $str, e);
            process::exit(1);
        });
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

    let secp = secp256k1::Secp256k1::verification_only();
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
    sigtype: SigHashType,
    stk_xprivs: &[bip32::ExtendedPrivKey],
    derivation_index: u32,
    secp: &secp256k1::Secp256k1<C>,
) -> BTreeMap<String, String> {
    let mut sigs = BTreeMap::new();

    for xpriv in stk_xprivs.iter() {
        let privkey = xpriv
            .derive_priv(secp, &[derivation_index.into()])
            .unwrap()
            .private_key
            .key;
        let sighash = psbt.signature_hash(0, sigtype).unwrap();
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
    if args.len() != 9 {
        eprintln!(
            "Usage: '{} <stakeholders xprivs as a JSON array> <deposit descriptor> \
             <unvault_descriptor> <cpfp descriptor> <Emer address> <deposit outpoint> \
             <deposit value> <derivation index>'",
            args[0]
        );
        process::exit(1);
    }

    let secp = revault_tx::bitcoin::secp256k1::Secp256k1::new();

    let stk_xprivs = xprivs_from_json(&args[1]);
    let deposit_desc = DepositDescriptor::from_str(&args[2]).unwrap_or_else(|e| {
        eprintln!("Failed to parse deposit descriptor '{}': '{}'", args[2], e);
        process::exit(1);
    });
    let unvault_desc = UnvaultDescriptor::from_str(&args[3]).unwrap_or_else(|e| {
        eprintln!("Failed to parse unvault descriptor '{}': '{}'", args[3], e);
        process::exit(1);
    });
    let cpfp_desc = CpfpDescriptor::from_str(&args[4]).unwrap_or_else(|e| {
        eprintln!("Failed to parse CPFP descriptor '{}': '{}'", args[1], e);
        process::exit(1);
    });
    let emer_address = emer_address_from_arg(&args[5]);
    let deposit_outpoint = OutPoint::from_str(&args[6]).unwrap_or_else(|e| {
        eprintln!("Failed to parse deposit outpoint '{}': '{}'", &args[6], e);
        process::exit(1);
    });
    let deposit_value: u64 = from_json!(&args[7]);
    let derivation_index: u32 = from_json!(&args[8]);
    sanity_checks(&deposit_desc, &unvault_desc, &cpfp_desc);

    eprintln!(
        "{}",
        deposit_desc
            .derive(derivation_index.into(), &secp)
            .into_inner()
            .address(revault_tx::bitcoin::Network::Regtest)
            .unwrap()
    );

    let (mut unvault_tx, mut cancel_tx, mut emer_tx, mut unemer_tx) =
        revault_tx::transactions::transaction_chain(
            deposit_outpoint,
            Amount::from_sat(deposit_value),
            &deposit_desc,
            &unvault_desc,
            &cpfp_desc,
            derivation_index.into(),
            emer_address,
            0,
            &secp,
        )
        .unwrap_or_else(|e| {
            eprintln!("Failed to derive transaction chain: '{}'", e);
            process::exit(1);
        });

    let unvault_sigs = sign(
        &mut unvault_tx,
        SigHashType::All,
        &stk_xprivs,
        derivation_index,
        &secp,
    );
    let cancel_sigs = sign(
        &mut cancel_tx,
        SigHashType::AllPlusAnyoneCanPay,
        &stk_xprivs,
        derivation_index,
        &secp,
    );
    let emer_sigs = sign(
        &mut emer_tx,
        SigHashType::AllPlusAnyoneCanPay,
        &stk_xprivs,
        derivation_index,
        &secp,
    );
    let unemer_sigs = sign(
        &mut unemer_tx,
        SigHashType::AllPlusAnyoneCanPay,
        &stk_xprivs,
        derivation_index,
        &secp,
    );

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
        })
    );
}
