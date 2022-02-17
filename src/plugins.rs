use revault_tx::{
    bitcoin::{Amount, OutPoint},
    transactions::UnvaultTransaction,
};

use std::{
    borrow::Cow,
    error, fmt, fs,
    io::Write,
    os::unix::fs::MetadataExt,
    path,
    process::{Command, Stdio},
};

use serde::{Deserialize, Serialize, Serializer};

#[derive(Debug, Eq, PartialEq)]
pub enum PluginError {
    NotFound(path::PathBuf),
    NotExecutable(path::PathBuf),
    Exec(path::PathBuf, String), // String because io::Error isn't PartialEq..
    Write(path::PathBuf, String), // String because io::Error isn't PartialEq..
    Read(path::PathBuf, String), // Same
    Termination(path::PathBuf, Option<i32>, Vec<u8>),
    Deserialization(path::PathBuf, String), // String because de::Error isn't PartialEq..
}

impl fmt::Display for PluginError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Self::NotFound(p) => write!(f, "Plugin not found at '{}'", p.to_string_lossy()),
            Self::NotExecutable(p) => {
                write!(f, "Plugin '{}' is not executable", p.to_string_lossy())
            }
            Self::Exec(p, e) => write!(
                f,
                "Plugin '{}' execution error: '{}'",
                p.to_string_lossy(),
                e
            ),
            Self::Write(p, e) => write!(f, "Plugin '{}' write error: '{}'", p.to_string_lossy(), e),
            Self::Read(p, e) => write!(f, "Plugin '{}' read error: '{}'", p.to_string_lossy(), e),
            Self::Termination(p, c, stderr) => write!(
                f,
                "Plugin '{}' terminated with error code '{:?}', stderr: '{}'",
                p.to_string_lossy(),
                c,
                String::from_utf8_lossy(&stderr)
            ),
            Self::Deserialization(p, e) => write!(
                f,
                "Plugin '{}' stdout deserialization error: '{}'",
                p.to_string_lossy(),
                e
            ),
        }
    }
}

impl error::Error for PluginError {}

fn serialize_amount<S: Serializer>(amount: &Amount, serializer: S) -> Result<S::Ok, S::Error> {
    amount.as_sat().serialize(serializer)
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct Plugin {
    path: path::PathBuf,
    config: serde_json::Value,
}

/// Information we are passing to a plugin about a vault that was unvaulted.
#[derive(Debug, Clone, Serialize)]
pub struct VaultInfo {
    #[serde(serialize_with = "serialize_amount")]
    pub value: Amount,
    pub deposit_outpoint: OutPoint,
    pub unvault_tx: UnvaultTransaction,
    // TODO: Spend tx
}

/// Information we are passing to a plugin after a new block if there was any update.
#[derive(Debug, Clone, Serialize)]
pub struct NewBlockInfo {
    pub new_attempts: Vec<VaultInfo>,
    pub successful_attempts: Vec<OutPoint>,
    pub revaulted_attempts: Vec<OutPoint>,
}

/// Response we expect from the plugin, contains the identifier to vault we need to cancel.
#[derive(Debug, Clone, Deserialize)]
pub struct NewBlockResponse {
    revault: Vec<OutPoint>,
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

    pub fn path_str(&self) -> Cow<str> {
        self.path.to_string_lossy()
    }

    /// Takes updates about our vaults' status and returns which should be Canceled, if any.
    ///
    /// This will start a plugin process and write a JSON request to its stding containing:
    /// - the block height of the last block
    /// - the info of vaults that were unvaulted
    /// - the deposit outpoint of the vaults that were succesfully spent
    /// - the deposit outpoint of the unvaulted vaults that were revaulted
    /// It will then read a JSON response from its stdout containing a list of deposit outpoints
    /// of vaults that should be canceled, and expect the plugin process to terminate.
    pub fn poll(
        &self,
        block_height: i32,
        block_info: &NewBlockInfo,
    ) -> Result<Vec<OutPoint>, PluginError> {
        let query = serde_json::json!({
            "method": "new_block",
            "config": self.config,
            "block_height": block_height,
            "block_info": block_info,
        });
        let mut query_ser =
            serde_json::to_vec(&query).expect("No string in map and Serialize won't fail");
        query_ser.push(b'\n');
        log::trace!(
            "Sending to plugin '{:?}' request '{}'",
            self.path.as_path(),
            String::from_utf8_lossy(&query_ser)
        );

        let mut p = Command::new(&self.path)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .map_err(|e| PluginError::Exec(self.path.clone(), e.to_string()))?;
        {
            let mut stdin = p.stdin.take().unwrap();
            stdin
                .write_all(&mut query_ser)
                .map_err(|e| PluginError::Write(self.path.clone(), e.to_string()))?;
            stdin
                .flush()
                .map_err(|e| PluginError::Write(self.path.clone(), e.to_string()))?;
        }

        let output = p
            .wait_with_output()
            .map_err(|e| PluginError::Read(self.path.clone(), e.to_string()))?;
        if !output.status.success() {
            return Err(PluginError::Termination(
                self.path.clone(),
                output.status.code(),
                output.stderr,
            ));
        }
        log::trace!(
            "Got from plugin '{:?}' response '{}'",
            self.path.as_path(),
            String::from_utf8_lossy(&output.stdout)
        );
        let resp: NewBlockResponse = serde_json::from_slice(&output.stdout)
            .map_err(|e| PluginError::Deserialization(self.path.clone(), e.to_string()))?;

        Ok(resp.revault)
    }
}

#[cfg(test)]
mod tests {
    use super::{NewBlockInfo, Plugin, VaultInfo};
    use revault_tx::{
        bitcoin::{Amount, OutPoint},
        transactions::UnvaultTransaction,
    };
    use std::{convert::TryInto, fs, str::FromStr};

    #[test]
    fn plugin_large_request() {
        let plugin = Plugin::new(
            "test_data/revault_all_attempts.py".try_into().unwrap(),
            serde_json::Value::Null,
        )
        .unwrap();
        let deposit_outpoint = OutPoint::from_str(
            "d0767211aa9375237a49e821d655ae5060ffd889221cc09e93e7a87e6ba7c74e:0",
        )
        .unwrap();
        let unvault_tx = UnvaultTransaction::from_str("cHNidP8BAIkCAAAAAfmN22Yg3hsR6wgkPWJ3tSpO40wY5fgINkSlClxgasy7AAAAAAD9////AkANAwAAAAAAIgAgfPlPYs+3NKdo6gu1ITRhWGaZ77RL/0n3/rfdM0nHDKAwdQAAAAAAACIAIBqfyVGG6ozM3AZyeJhKeLNsjlt7AuXs89eFQSUEgx3xAAAAAAABASuIlAMAAAAAACIAIEpy7LLM5Gsjv384BJqpdhVyxzoC96snQbKN/Pl4yFqSAQjaBABHMEQCIG7ue0n/D+JrDMknOV2Up/NyLh06p2tQTHoEZAAYYoCfAiA0fZxErfzZFgLpSV/f1uvCArcXStNUnhConPYBvEmwcgFHMEQCIALfcLNVtS1zZ/AH/5JGVPlUyNGB4tAWOAvJm5DFCFkPAiAxw8oPariZ4OqNZH/PiSQytLInnsYMmzY8khNtDWS7WQFHUiED2l1MSok0kn+im8fepkDk9JJ4kmz7S7PJbLp2MHUScDshAqg1gjG67ft3qNh1U2hWCYumJvmnWsb96aAQU3BKIwiOUq4AIgICCu8X76xDyD8Eurt1XmKvjamdwezV7UxLGsoa8yfMj2cI/w6LrAoAAAAiAgKoNYIxuu37d6jYdVNoVgmLpib5p1rG/emgEFNwSiMIjgjAoMvqCgAAACICAulOlir/rBPSuqc9Z7mGFUE1ekHvzGRuDA2sjFgPGzZ+CDooLAQKAAAAIgIDncUagEr+XYCSpDykd7a6WrIa1q58GBTGSMVms8Dk/1YI0jxctQoAAAAiAgPaXUxKiTSSf6Kbx96mQOT0kniSbPtLs8lsunYwdRJwOwhMrobwCgAAAAAiAgOdxRqASv5dgJKkPKR3trpashrWrnwYFMZIxWazwOT/VgjSPFy1CgAAAAA=").unwrap();
        let new_attempts = (0..10000)
            .map(|_| VaultInfo {
                value: Amount::from_sat(567890),
                deposit_outpoint,
                unvault_tx: unvault_tx.clone(),
            })
            .collect();
        let many_outpoints: Vec<OutPoint> = (0..10000).map(|_| deposit_outpoint).collect();

        let new_block = NewBlockInfo {
            new_attempts,
            successful_attempts: many_outpoints.clone(),
            revaulted_attempts: many_outpoints.clone(),
        };
        assert_eq!(plugin.poll(1684527, &new_block).unwrap(), many_outpoints);
    }

    #[test]
    fn plugin_config() {
        let deposit_outpoint = OutPoint::from_str(
            "5de8acd1a4a81bbfcf1cede5c2721a2c1f0bbd02fc343add24852b885410aa2f:1001",
        )
        .unwrap();
        let config = serde_json::json!({
            "outpoint_to_revault": deposit_outpoint,
        });
        let plugin = Plugin::new(
            "test_data/revault_config_outpoint.py".try_into().unwrap(),
            config,
        )
        .unwrap();
        let unvault_tx = UnvaultTransaction::from_str("cHNidP8BAIkCAAAAAfmN22Yg3hsR6wgkPWJ3tSpO40wY5fgINkSlClxgasy7AAAAAAD9////AkANAwAAAAAAIgAgfPlPYs+3NKdo6gu1ITRhWGaZ77RL/0n3/rfdM0nHDKAwdQAAAAAAACIAIBqfyVGG6ozM3AZyeJhKeLNsjlt7AuXs89eFQSUEgx3xAAAAAAABASuIlAMAAAAAACIAIEpy7LLM5Gsjv384BJqpdhVyxzoC96snQbKN/Pl4yFqSAQjaBABHMEQCIG7ue0n/D+JrDMknOV2Up/NyLh06p2tQTHoEZAAYYoCfAiA0fZxErfzZFgLpSV/f1uvCArcXStNUnhConPYBvEmwcgFHMEQCIALfcLNVtS1zZ/AH/5JGVPlUyNGB4tAWOAvJm5DFCFkPAiAxw8oPariZ4OqNZH/PiSQytLInnsYMmzY8khNtDWS7WQFHUiED2l1MSok0kn+im8fepkDk9JJ4kmz7S7PJbLp2MHUScDshAqg1gjG67ft3qNh1U2hWCYumJvmnWsb96aAQU3BKIwiOUq4AIgICCu8X76xDyD8Eurt1XmKvjamdwezV7UxLGsoa8yfMj2cI/w6LrAoAAAAiAgKoNYIxuu37d6jYdVNoVgmLpib5p1rG/emgEFNwSiMIjgjAoMvqCgAAACICAulOlir/rBPSuqc9Z7mGFUE1ekHvzGRuDA2sjFgPGzZ+CDooLAQKAAAAIgIDncUagEr+XYCSpDykd7a6WrIa1q58GBTGSMVms8Dk/1YI0jxctQoAAAAiAgPaXUxKiTSSf6Kbx96mQOT0kniSbPtLs8lsunYwdRJwOwhMrobwCgAAAAAiAgOdxRqASv5dgJKkPKR3trpashrWrnwYFMZIxWazwOT/VgjSPFy1CgAAAAA=").unwrap();

        let vault_info = VaultInfo {
            value: Amount::from_sat(567890),
            deposit_outpoint: OutPoint::from_str(
                "d0767211aa9375237a49e821d655ae5060ffd889221cc09e93e7a87e6ba7c74e:0",
            )
            .unwrap(),
            unvault_tx: unvault_tx.clone(),
        };
        let new_block = NewBlockInfo {
            new_attempts: vec![vault_info],
            successful_attempts: vec![deposit_outpoint],
            revaulted_attempts: vec![deposit_outpoint],
        };
        assert_eq!(
            plugin.poll(1684527, &new_block).unwrap(),
            vec![deposit_outpoint]
        );
    }

    #[test]
    fn plugin_sanitycheck_maxvalueplugin() {
        let data_dir = "./maxvalueplugin_datadir";
        let deposit_outpoint = OutPoint::from_str(
            "5de8acd1a4a81bbfcf1cede5c2721a2c1f0bbd02fc343add24852b885410aa2f:1001",
        )
        .unwrap();
        let unvault_tx = UnvaultTransaction::from_str("cHNidP8BAIkCAAAAAfmN22Yg3hsR6wgkPWJ3tSpO40wY5fgINkSlClxgasy7AAAAAAD9////AkANAwAAAAAAIgAgfPlPYs+3NKdo6gu1ITRhWGaZ77RL/0n3/rfdM0nHDKAwdQAAAAAAACIAIBqfyVGG6ozM3AZyeJhKeLNsjlt7AuXs89eFQSUEgx3xAAAAAAABASuIlAMAAAAAACIAIEpy7LLM5Gsjv384BJqpdhVyxzoC96snQbKN/Pl4yFqSAQjaBABHMEQCIG7ue0n/D+JrDMknOV2Up/NyLh06p2tQTHoEZAAYYoCfAiA0fZxErfzZFgLpSV/f1uvCArcXStNUnhConPYBvEmwcgFHMEQCIALfcLNVtS1zZ/AH/5JGVPlUyNGB4tAWOAvJm5DFCFkPAiAxw8oPariZ4OqNZH/PiSQytLInnsYMmzY8khNtDWS7WQFHUiED2l1MSok0kn+im8fepkDk9JJ4kmz7S7PJbLp2MHUScDshAqg1gjG67ft3qNh1U2hWCYumJvmnWsb96aAQU3BKIwiOUq4AIgICCu8X76xDyD8Eurt1XmKvjamdwezV7UxLGsoa8yfMj2cI/w6LrAoAAAAiAgKoNYIxuu37d6jYdVNoVgmLpib5p1rG/emgEFNwSiMIjgjAoMvqCgAAACICAulOlir/rBPSuqc9Z7mGFUE1ekHvzGRuDA2sjFgPGzZ+CDooLAQKAAAAIgIDncUagEr+XYCSpDykd7a6WrIa1q58GBTGSMVms8Dk/1YI0jxctQoAAAAiAgPaXUxKiTSSf6Kbx96mQOT0kniSbPtLs8lsunYwdRJwOwhMrobwCgAAAAAiAgOdxRqASv5dgJKkPKR3trpashrWrnwYFMZIxWazwOT/VgjSPFy1CgAAAAA=").unwrap();
        let vault_info = VaultInfo {
            value: Amount::from_sat(567890),
            deposit_outpoint,
            unvault_tx: unvault_tx.clone(),
        };
        let new_block = NewBlockInfo {
            new_attempts: vec![vault_info],
            successful_attempts: vec![],
            revaulted_attempts: vec![],
        };

        // max_value is vault value -1, it tells to revault
        let config = serde_json::json!({
            "max_value": 567889,
            "data_dir": data_dir,
        });
        let plugin = Plugin::new(
            "tests/plugins/max_value_in_flight.py".try_into().unwrap(),
            config,
        )
        .unwrap();
        assert_eq!(plugin.poll(1, &new_block).unwrap(), vec![deposit_outpoint]);
        // max_value is vault value, it does not
        let config = serde_json::json!({
            "max_value": 567890,
            "data_dir": data_dir,
        });
        let plugin = Plugin::new(
            "tests/plugins/max_value_in_flight.py".try_into().unwrap(),
            config,
        )
        .unwrap();
        assert_eq!(plugin.poll(1, &new_block).unwrap(), vec![]);
        fs::remove_dir_all(data_dir).unwrap();
    }
}
