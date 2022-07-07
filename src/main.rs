mod bitcoind;
mod config;
mod coordinator;
mod daemonize;
mod database;
mod keys;
mod listener;
mod plugins;
mod poller;

use bitcoind::{load_watchonly_wallet, start_bitcoind, wait_bitcoind_synced};
use config::{config_folder_path, Config};
use daemonize::daemonize;
use database::setup_db;
use keys::read_or_create_noise_key;
use listener::listener_main;
use revault_net::sodiumoxide;
use revault_tx::bitcoin::{hashes::hex::ToHex, secp256k1};

use std::{env, fs, os::unix::fs::DirBuilderExt, panic, path, process, sync, thread, time};

const DATABASE_FILENAME: &str = "mirarod.sqlite3";
const VAULT_WATCHONLY_FILENAME: &str = "vault_watchonly";
const NOISE_KEY_FILENAME: &str = "noise_secret";
const PID_FILENAME: &str = "miradord.pid";
const LOG_FILENAME: &str = "log";

fn parse_args(args: Vec<String>) -> Option<path::PathBuf> {
    if args.len() == 1 {
        return None;
    }

    if args.len() != 3 {
        eprintln!("Unknown arguments '{:?}'.", args);
        eprintln!("Only '--conf <configuration file path>' is supported.");
        process::exit(1);
    }

    Some(path::PathBuf::from(args[2].to_owned()))
}

// We always log on stdout, it'll be piped if we are daemonized.
fn setup_logger(log_level: log::LevelFilter) -> Result<(), fern::InitError> {
    let dispatcher = fern::Dispatch::new()
        .format(|out, message, record| {
            out.finish(format_args!(
                "[{}][{}][{}] {}",
                time::SystemTime::now()
                    .duration_since(time::UNIX_EPOCH)
                    .unwrap_or_else(|e| {
                        println!("Can't get time since epoch: '{}'. Using a dummy value.", e);
                        time::Duration::from_secs(0)
                    })
                    .as_secs(),
                record.target(),
                record.level(),
                message
            ))
        })
        .level(log_level);

    dispatcher.chain(std::io::stdout()).apply()?;

    Ok(())
}

// A panic in any thread should stop the main thread, and print the panic with a backtrace.
fn setup_panic_hook() {
    panic::set_hook(Box::new(move |panic_info| {
        let file = panic_info
            .location()
            .map(|l| l.file())
            .unwrap_or("'unknown'");
        let line = panic_info
            .location()
            .map(|l| l.line().to_string())
            .unwrap_or_else(|| "'unknown'".to_string());

        let bt = backtrace::Backtrace::new();
        let info = panic_info
            .payload()
            .downcast_ref::<&str>()
            .map(|s| s.to_string())
            .or_else(|| panic_info.payload().downcast_ref::<String>().cloned());
        log::error!(
            "panic occurred at line {} of file {}: {:?}\n{:?}",
            line,
            file,
            info,
            bt
        );

        process::exit(1);
    }));
}

fn create_datadir(datadir_path: &path::Path) -> Result<(), std::io::Error> {
    let mut builder = fs::DirBuilder::new();
    builder.mode(0o700).recursive(true).create(datadir_path)
}

fn main() {
    #[cfg(not(unix))]
    {
        eprintln!("Only Unix is supported.");
        process::exit(1);
    }
    setup_panic_hook();

    let args = env::args().collect();
    let conf_file = parse_args(args);

    // We use libsodium for Noise keys and Noise channels (through revault_net)
    sodiumoxide::init().unwrap_or_else(|_| {
        eprintln!("Error init'ing libsodium");
        process::exit(1);
    });

    let config = Config::from_file(conf_file).unwrap_or_else(|e| {
        eprintln!("Error parsing config: {}", e);
        process::exit(1);
    });
    setup_logger(config.log_level).unwrap_or_else(|e| {
        eprintln!("Error setting up logger: {}", e);
        process::exit(1);
    });

    log::info!(
        "Currently registered plugins: {}",
        config
            .plugins
            .iter()
            .map(|p| p.path_str())
            .collect::<Vec<std::borrow::Cow<str>>>()
            .join(", "),
    );

    let mut data_dir = config.data_dir.clone().unwrap_or_else(|| {
        config_folder_path().unwrap_or_else(|e| {
            eprintln!("Error getting default data directory: '{}'.", e);
            process::exit(1);
        })
    });
    data_dir.push(config.bitcoind_config.network.to_string());
    log::info!("Using data directory at '{}'.", data_dir.to_string_lossy());
    if !data_dir.as_path().exists() {
        log::info!("Data directory doesn't exist, creating it.");
        create_datadir(&data_dir).unwrap_or_else(|e| {
            eprintln!("Error creating data directory: '{}'.", e);
            process::exit(1);
        });
    }
    data_dir = fs::canonicalize(data_dir).unwrap_or_else(|e| {
        eprintln!("Error canonicalizing data directory: '{}'.", e);
        process::exit(1);
    });

    log::info!("Setting up the database");
    let mut db_path = data_dir.clone();
    db_path.push(path::Path::new(DATABASE_FILENAME));
    setup_db(
        &db_path,
        &config.scripts_config.deposit_descriptor,
        &config.scripts_config.unvault_descriptor,
        &config.scripts_config.cpfp_descriptor,
        config.bitcoind_config.network,
    )
    .unwrap_or_else(|e| {
        log::error!("Error setting up database: '{}'", e);
        process::exit(1);
    });

    log::info!("Setting up bitcoind connection");
    let mut vault_watchonly_path = data_dir
        .to_str()
        .expect("Data dir must be valid unicode")
        .to_string();
    vault_watchonly_path.push_str(VAULT_WATCHONLY_FILENAME);
    let bitcoind = start_bitcoind(&config.bitcoind_config, vault_watchonly_path.clone())
        .unwrap_or_else(|e| {
            log::error!("Error setting up bitcoind RPC connection: '{}'", e);
            process::exit(1);
        });
    let bitcoind = sync::Arc::new(bitcoind);

    log::info!("Checking if bitcoind is synced");
    wait_bitcoind_synced(&bitcoind);
    log::info!("bitcoind now synced");

    load_watchonly_wallet(&bitcoind, vault_watchonly_path).unwrap_or_else(|e| {
        log::error!("Error loading vault watchonly wallet: '{}'", e);
        process::exit(1);
    });
    // TODO: load feebumping wallet too.

    let mut noise_secret_path = data_dir.clone();
    noise_secret_path.push(path::Path::new(NOISE_KEY_FILENAME));
    log::info!(
        "Reading or generating Noise key at '{:?}'",
        noise_secret_path
    );
    let noise_secret = read_or_create_noise_key(&noise_secret_path).unwrap_or_else(|e| {
        log::error!("Error reading or generating Noise key: '{}'", e);
        process::exit(1);
    });
    log::info!(
        "Using Noise key '{}'. Stakehodler Noise key '{}'",
        noise_secret.public_key().0.to_hex(),
        &config.stakeholder_noise_key.0.to_hex()
    );

    if config.daemon {
        let mut pid_file = data_dir.clone();
        pid_file.push(PID_FILENAME);

        let mut log_file = data_dir.clone();
        log_file.push(LOG_FILENAME);

        log::info!(
            "Daemonizing with root '{}', pid file '{}' and log file '{}'",
            data_dir.to_string_lossy(),
            pid_file.to_string_lossy(),
            log_file.to_string_lossy()
        );
        unsafe {
            daemonize(&data_dir, &pid_file, &log_file).unwrap_or_else(|e| {
                eprintln!("Error daemonizing: {}", e);
                // Duplicated as the error could happen after we fork and set stderr to /dev/null
                log::error!("Error daemonizing: {}", e);
                process::exit(1);
            });
        }
    }

    thread::spawn({
        let _db_path = db_path.clone();
        let _config = config.clone();
        let _bitcoind = bitcoind.clone();
        let noise_secret = noise_secret.clone();
        move || {
            listener_main(&_db_path, &_config, _bitcoind, &noise_secret).unwrap_or_else(|e| {
                log::error!("Error in listener loop: '{}'", e);
                process::exit(1);
            })
        }
    });

    log::info!("Started miradord.",);

    let secp_ctx = secp256k1::Secp256k1::verification_only();
    poller::main_loop(&db_path, &secp_ctx, &config, &bitcoind, noise_secret).unwrap_or_else(|e| {
        log::error!("Error in main loop: '{}'", e);
        process::exit(1);
    });
}
