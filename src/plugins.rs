use std::{error, fmt, fs, os::unix::fs::MetadataExt, path};

#[derive(Debug, Eq, PartialEq)]
pub enum PluginError {
    NotFound(path::PathBuf),
    NotExecutable(path::PathBuf),
}

impl fmt::Display for PluginError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Self::NotFound(p) => write!(f, "Plugin not found at '{}'", p.to_string_lossy()),
            Self::NotExecutable(p) => {
                write!(f, "Plugin '{}' is not executable", p.to_string_lossy())
            }
        }
    }
}

impl error::Error for PluginError {}

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct Plugin {
    path: path::PathBuf,
    config: serde_json::Value,
}

impl Plugin {
    pub fn new(path: path::PathBuf, config: serde_json::Value) -> Result<Self, PluginError> {
        if !path.exists() || !path.is_file() {
            return Err(PluginError::NotFound(path));
        }

        match fs::metadata(&path).map(|metadata| (metadata.mode() & 0o111) != 0) {
            Ok(true) => {}
            _ => return Err(PluginError::NotExecutable(path)),
        };

        Ok(Self { path, config })
    }
}
