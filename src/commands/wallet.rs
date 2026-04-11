use serde::Serialize;
use std::fs;
use std::path::PathBuf;

use crate::error::BttError;

#[derive(Serialize)]
pub struct WalletList {
    pub wallets: Vec<WalletEntry>,
}

#[derive(Serialize)]
pub struct WalletEntry {
    pub name: String,
    pub coldkey: Option<KeyInfo>,
    pub hotkeys: Vec<KeyInfo>,
}

#[derive(Serialize)]
pub struct KeyInfo {
    pub name: String,
    pub ss58_address: Option<String>,
    pub path: String,
}

/// List wallets found in ~/.bittensor/wallets/.
/// Each wallet is a directory containing a `coldkeypub.txt` and `hotkeys/` subdirectory.
pub fn list() -> Result<WalletList, BttError> {
    let wallets_dir = wallets_path()?;

    if !wallets_dir.exists() {
        return Err(BttError::wallet_not_found(format!(
            "wallets directory not found: {}",
            wallets_dir.display()
        )));
    }

    let mut wallets = Vec::new();

    let entries = fs::read_dir(&wallets_dir)
        .map_err(|e| BttError::io(format!("failed to read wallets directory: {}", e)))?;

    for entry in entries {
        let entry = entry
            .map_err(|e| BttError::io(format!("failed to read directory entry: {}", e)))?;

        let path = entry.path();
        if !path.is_dir() {
            continue;
        }

        let wallet_name = entry
            .file_name()
            .to_string_lossy()
            .to_string();

        // Read coldkeypub.txt
        let coldkey_path = path.join("coldkeypub.txt");
        let coldkey = if coldkey_path.exists() {
            Some(read_key_file(&coldkey_path, "coldkeypub")?)
        } else {
            None
        };

        // Read hotkeys
        let hotkeys_dir = path.join("hotkeys");
        let mut hotkeys = Vec::new();
        if hotkeys_dir.exists() && hotkeys_dir.is_dir() {
            let hk_entries = fs::read_dir(&hotkeys_dir)
                .map_err(|e| BttError::io(format!("failed to read hotkeys directory: {}", e)))?;

            for hk_entry in hk_entries {
                let hk_entry = hk_entry
                    .map_err(|e| BttError::io(format!("failed to read hotkey entry: {}", e)))?;
                let hk_path = hk_entry.path();
                if hk_path.is_file() {
                    let hk_name = hk_entry
                        .file_name()
                        .to_string_lossy()
                        .to_string();
                    match read_key_file(&hk_path, &hk_name) {
                        Ok(ki) => hotkeys.push(ki),
                        Err(_) => {
                            // Skip malformed hotkey files
                            hotkeys.push(KeyInfo {
                                name: hk_name,
                                ss58_address: None,
                                path: hk_path.to_string_lossy().to_string(),
                            });
                        }
                    }
                }
            }
        }

        wallets.push(WalletEntry {
            name: wallet_name,
            coldkey,
            hotkeys,
        });
    }

    wallets.sort_by(|a, b| a.name.cmp(&b.name));

    Ok(WalletList { wallets })
}

/// Get the wallets directory path.
fn wallets_path() -> Result<PathBuf, BttError> {
    let home = std::env::var("HOME")
        .map_err(|_| BttError::io("HOME environment variable not set"))?;
    Ok(PathBuf::from(home).join(".bittensor").join("wallets"))
}

/// Read a Bittensor key file (JSON) and extract the SS58 address.
/// The format is typically: {"accountId": "0x...", "publicKey": "0x...", "secretPhrase": "...", "ss58Address": "5..."}
/// For public key files, it may just be the JSON with ss58Address.
fn read_key_file(path: &PathBuf, name: &str) -> Result<KeyInfo, BttError> {
    let content = fs::read_to_string(path)
        .map_err(|e| BttError::io(format!("failed to read {}: {}", path.display(), e)))?;

    let ss58 = extract_ss58_from_json(&content);

    Ok(KeyInfo {
        name: name.to_string(),
        ss58_address: ss58,
        path: path.to_string_lossy().to_string(),
    })
}

/// Try to extract ss58Address from a JSON string.
fn extract_ss58_from_json(content: &str) -> Option<String> {
    // Try to parse as JSON
    if let Ok(v) = serde_json::from_str::<serde_json::Value>(content) {
        // Check for "ss58Address" field
        if let Some(addr) = v.get("ss58Address").and_then(|v| v.as_str()) {
            return Some(addr.to_string());
        }
        // Some files use "SS58Address"
        if let Some(addr) = v.get("SS58Address").and_then(|v| v.as_str()) {
            return Some(addr.to_string());
        }
        // Try "address"
        if let Some(addr) = v.get("address").and_then(|v| v.as_str()) {
            return Some(addr.to_string());
        }
    }

    // Some coldkeypub.txt files are just the raw SS58 address
    let trimmed = content.trim();
    if trimmed.starts_with('5') && trimmed.len() >= 47 && trimmed.len() <= 49 {
        return Some(trimmed.to_string());
    }

    None
}
