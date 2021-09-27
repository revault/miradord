use revault_net::{noise::SecretKey as NoisePrivKey, sodiumoxide};

use std::{
    fs,
    io::{self, Read, Write},
    os::unix::fs::OpenOptionsExt,
    path::Path,
};

/// An error occuring while handling of our key files
#[derive(Debug)]
pub enum KeyError {
    Noise(io::Error),
}

impl std::fmt::Display for KeyError {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self {
            Self::Noise(e) => write!(f, "Noise key initialization error: '{}'", e),
        }
    }
}

impl std::error::Error for KeyError {}

// The communication keys are (for now) hot, so we just create it ourselves on first run.
pub fn read_or_create_noise_key(secret_file: &Path) -> Result<NoisePrivKey, KeyError> {
    let mut noise_secret = NoisePrivKey([0; 32]);

    if !secret_file.exists() {
        log::info!(
            "No Noise private key at '{:?}', generating a new one",
            secret_file
        );
        noise_secret = sodiumoxide::crypto::box_::gen_keypair().1;

        // We create it in read-only but open it in write only.
        let mut options = fs::OpenOptions::new();
        options = options.write(true).create_new(true).mode(0o400).clone();

        let mut fd = options.open(secret_file).map_err(KeyError::Noise)?;
        fd.write_all(&noise_secret.as_ref())
            .map_err(KeyError::Noise)?;
    } else {
        let mut noise_secret_fd = fs::File::open(secret_file).map_err(KeyError::Noise)?;
        noise_secret_fd
            .read_exact(&mut noise_secret.0)
            .map_err(KeyError::Noise)?;
    }

    // TODO: have a decent memory management and mlock() the key

    assert!(noise_secret.0 != [0; 32]);
    Ok(noise_secret)
}

#[cfg(test)]
mod tests {
    use super::read_or_create_noise_key;

    use std::{fs, path};

    #[test]
    fn noise_key_read() {
        let keyfile: path::PathBuf = "scratch_noisekey".into();
        // Any leftover?
        fs::remove_file(&keyfile).unwrap_or_else(|_| ());

        // No keyfile present, must create it
        let noise_key = read_or_create_noise_key(&keyfile).unwrap();
        assert!(keyfile.as_path().exists());

        // Now if we call it again, it should read the same key
        let sec_noise_key = read_or_create_noise_key(&keyfile).unwrap();
        assert_eq!(noise_key, sec_noise_key);
    }
}
