use std::fs;
#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;

use serde::Serialize;
use sp_core::crypto::{Ss58Codec, Pair as TraitPair};
use sp_core::sr25519::{Pair, Public, Signature};
use zeroize::Zeroize;

use crate::error::BttError;

/// One TAO equals 1e9 RAO.
pub const RAO_PER_TAO: u64 = 1_000_000_000;

/// Convert a TAO amount (floating point) to RAO (integer).
/// Returns an error if the amount is negative, NaN, infinite, or overflows u64.
pub fn tao_to_rao(tao: f64) -> Result<u64, BttError> {
    if tao.is_nan() || tao.is_infinite() {
        return Err(BttError::invalid_amount("amount must be a finite number"));
    }
    if tao < 0.0 {
        return Err(BttError::invalid_amount("amount must be non-negative"));
    }
    let rao_f64 = tao * RAO_PER_TAO as f64;
    if rao_f64 > u64::MAX as f64 {
        return Err(BttError::invalid_amount("amount overflows u64 in RAO"));
    }
    Ok(rao_f64 as u64)
}

/// Convert RAO to a human-readable TAO string with up to 9 decimal places.
/// Trailing zeros are trimmed but at least one decimal place is kept.
pub fn rao_to_tao_string(rao: u64) -> String {
    let whole = rao / RAO_PER_TAO;
    let frac = rao % RAO_PER_TAO;
    if frac == 0 {
        format!("{whole}.0")
    } else {
        let raw = format!("{whole}.{frac:09}");
        let trimmed = raw.trim_end_matches('0');
        trimmed.to_string()
    }
}

/// Resolve a coldkey SS58 address from a wallet name.
/// Reads `~/.bittensor/wallets/<name>/coldkeypub.txt`.
pub fn resolve_coldkey_address(wallet_name: &str) -> Result<String, BttError> {
    let wdir = wallet_path(wallet_name)?;
    if !wdir.exists() {
        return Err(BttError::wallet_not_found(format!(
            "wallet '{wallet_name}' not found at {}",
            wdir.display()
        )));
    }
    let pubkey_path = wdir.join("coldkeypub.txt");

    if !pubkey_path.exists() {
        return Err(BttError::wallet_not_found(format!(
            "coldkeypub.txt not found for wallet '{wallet_name}'"
        )));
    }

    let content = fs::read_to_string(&pubkey_path)
        .map_err(|e| BttError::io(format!("failed to read coldkeypub.txt: {e}")))?;

    extract_ss58_from_content(&content).ok_or_else(|| {
        BttError::parse(format!(
            "could not extract SS58 address from coldkeypub.txt for wallet '{wallet_name}'"
        ))
    })
}

/// Decrypt the coldkey for a wallet and return an sr25519 keypair.
/// Uses the existing load_coldkey infrastructure; prompts for password.
pub fn decrypt_coldkey_interactive(wallet_name: &str) -> Result<Pair, BttError> {
    let wdir = wallet_path(wallet_name)?;
    if !wdir.exists() {
        return Err(BttError::wallet_not_found(format!(
            "wallet '{wallet_name}' not found at {}",
            wdir.display()
        )));
    }

    let coldkey_path = wdir.join("coldkey");
    if !coldkey_path.exists() {
        return Err(BttError::wallet_not_found(format!(
            "coldkey file not found for wallet '{wallet_name}'"
        )));
    }

    // Try reading as unencrypted JSON first (development/testing keys)
    if let Ok(content) = fs::read_to_string(&coldkey_path) {
        if let Ok(json) = serde_json::from_str::<serde_json::Value>(&content) {
            if let Ok(pair) = pair_from_key_json(&content) {
                return Ok(pair);
            }
            // Has JSON structure but no usable key fields -- fall through to encrypted path
            let _ = json;
        }
    }

    // Encrypted: prompt for password and decrypt
    let password = read_password("Enter coldkey password: ")?;
    let pair = load_coldkey(&wdir, &password)?;
    Ok(pair)
}

/// Extract an SS58 address from key file content.
fn extract_ss58_from_content(content: &str) -> Option<String> {
    if let Ok(v) = serde_json::from_str::<serde_json::Value>(content) {
        if let Some(addr) = v.get("ss58Address").and_then(|v| v.as_str()) {
            return Some(addr.to_string());
        }
        if let Some(addr) = v.get("SS58Address").and_then(|v| v.as_str()) {
            return Some(addr.to_string());
        }
        if let Some(addr) = v.get("address").and_then(|v| v.as_str()) {
            return Some(addr.to_string());
        }
    }

    let trimmed = content.trim();
    if trimmed.starts_with('5') && trimmed.len() >= 47 && trimmed.len() <= 49 {
        return Some(trimmed.to_string());
    }

    None
}

// btcli uses scrypt with n=2^18, r=8, p=1 for key derivation
const SCRYPT_LOG_N: u8 = 18;
const SCRYPT_R: u32 = 8;
const SCRYPT_P: u32 = 1;
const SCRYPT_DKLEN: usize = 32;

// NaCl secretbox nonce length
const NONCE_LEN: usize = 24;

// ── Output types ──────────────────────────────────────────────────────────

#[derive(Serialize)]
pub struct CreateResult {
    pub wallet_name: String,
    pub coldkey_ss58: String,
    pub hotkey_ss58: String,
    pub mnemonic: String,
}

#[derive(Serialize)]
pub struct NewColdkeyResult {
    pub wallet_name: String,
    pub ss58_address: String,
    pub mnemonic: String,
}

#[derive(Serialize)]
pub struct NewHotkeyResult {
    pub wallet_name: String,
    pub hotkey_name: String,
    pub ss58_address: String,
    pub mnemonic: String,
}

#[derive(Serialize)]
pub struct RegenResult {
    pub wallet_name: String,
    pub ss58_address: String,
}

#[derive(Serialize)]
pub struct RegenHotkeyResult {
    pub wallet_name: String,
    pub hotkey_name: String,
    pub ss58_address: String,
}

#[derive(Serialize)]
pub struct SignResult {
    pub signature: String,
    pub public_key: String,
    pub ss58_address: String,
}

#[derive(Serialize)]
pub struct VerifyResult {
    pub valid: bool,
}

// ── Key file JSON format (btcli-compatible) ───────────────────────────────

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct KeyFileData {
    account_id: String,
    public_key: String,
    secret_phrase: String,
    secret_seed: String,
    ss58_address: String,
}

// ── Public key file format ────────────────────────────────────────────────

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct PubKeyFileData {
    account_id: String,
    public_key: String,
    ss58_address: String,
}

// ── Core operations ───────────────────────────────────────────────────────

/// Create a new wallet with both coldkey and hotkey.
pub fn create(
    wallet_name: &str,
    hotkey_name: &str,
    n_words: u32,
    password: &str,
) -> Result<CreateResult, BttError> {
    validate_n_words(n_words)?;

    let (cold_pair, mut cold_phrase, mut cold_seed) = generate_keypair(n_words)?;
    let cold_ss58 = cold_pair.public().to_ss58check();
    let cold_seed_hex = format!("0x{}", hex::encode(cold_seed));

    // Build the JSON for the coldkey
    let cold_json = build_key_json(&cold_pair, &cold_phrase, &cold_seed_hex);
    let cold_json_str = serde_json::to_string(&cold_json)
        .map_err(|e| BttError::io(format!("failed to serialize coldkey: {}", e)))?;

    // Encrypt and write coldkey
    let wallet_dir = wallet_path(wallet_name)?;
    fs::create_dir_all(&wallet_dir)
        .map_err(|e| BttError::io(format!("failed to create wallet directory: {}", e)))?;

    let encrypted = encrypt_key_data(cold_json_str.as_bytes(), password)?;
    write_secure_file(&wallet_dir.join("coldkey"), &encrypted)?;

    // Write coldkeypub.txt (unencrypted public info)
    let pub_data = build_pub_key_json(&cold_pair);
    let pub_json_str = serde_json::to_string(&pub_data)
        .map_err(|e| BttError::io(format!("failed to serialize coldkeypub: {}", e)))?;
    fs::write(wallet_dir.join("coldkeypub.txt"), &pub_json_str)
        .map_err(|e| BttError::io(format!("failed to write coldkeypub.txt: {}", e)))?;

    // Generate hotkey
    let (hot_pair, mut hot_phrase, mut hot_seed) = generate_keypair(n_words)?;
    let hot_ss58 = hot_pair.public().to_ss58check();
    let hot_seed_hex = format!("0x{}", hex::encode(hot_seed));

    let hot_json = build_key_json(&hot_pair, &hot_phrase, &hot_seed_hex);
    let hot_json_str = serde_json::to_string(&hot_json)
        .map_err(|e| BttError::io(format!("failed to serialize hotkey: {}", e)))?;

    // Write hotkey (unencrypted)
    let hotkeys_dir = wallet_dir.join("hotkeys");
    fs::create_dir_all(&hotkeys_dir)
        .map_err(|e| BttError::io(format!("failed to create hotkeys directory: {}", e)))?;
    fs::write(hotkeys_dir.join(hotkey_name), &hot_json_str)
        .map_err(|e| BttError::io(format!("failed to write hotkey: {}", e)))?;

    let mnemonic_out = cold_phrase.clone();

    // Zeroize sensitive material
    cold_phrase.zeroize();
    cold_seed.zeroize();
    hot_phrase.zeroize();
    hot_seed.zeroize();

    Ok(CreateResult {
        wallet_name: wallet_name.to_string(),
        coldkey_ss58: cold_ss58,
        hotkey_ss58: hot_ss58,
        mnemonic: mnemonic_out,
    })
}

/// Generate only a new coldkey.
pub fn new_coldkey(
    wallet_name: &str,
    n_words: u32,
    password: &str,
) -> Result<NewColdkeyResult, BttError> {
    validate_n_words(n_words)?;

    let (pair, mut phrase, mut seed) = generate_keypair(n_words)?;
    let ss58 = pair.public().to_ss58check();
    let seed_hex = format!("0x{}", hex::encode(seed));

    let json = build_key_json(&pair, &phrase, &seed_hex);
    let json_str = serde_json::to_string(&json)
        .map_err(|e| BttError::io(format!("failed to serialize coldkey: {}", e)))?;

    let wallet_dir = wallet_path(wallet_name)?;
    fs::create_dir_all(&wallet_dir)
        .map_err(|e| BttError::io(format!("failed to create wallet directory: {}", e)))?;

    let encrypted = encrypt_key_data(json_str.as_bytes(), password)?;
    write_secure_file(&wallet_dir.join("coldkey"), &encrypted)?;

    let pub_data = build_pub_key_json(&pair);
    let pub_json_str = serde_json::to_string(&pub_data)
        .map_err(|e| BttError::io(format!("failed to serialize coldkeypub: {}", e)))?;
    fs::write(wallet_dir.join("coldkeypub.txt"), &pub_json_str)
        .map_err(|e| BttError::io(format!("failed to write coldkeypub.txt: {}", e)))?;

    let mnemonic_out = phrase.clone();

    phrase.zeroize();
    seed.zeroize();

    Ok(NewColdkeyResult {
        wallet_name: wallet_name.to_string(),
        ss58_address: ss58,
        mnemonic: mnemonic_out,
    })
}

/// Generate a new hotkey for an existing wallet.
pub fn new_hotkey(
    wallet_name: &str,
    hotkey_name: &str,
    n_words: u32,
) -> Result<NewHotkeyResult, BttError> {
    validate_n_words(n_words)?;

    let wallet_dir = wallet_path(wallet_name)?;
    if !wallet_dir.exists() {
        return Err(BttError::wallet_not_found(format!(
            "wallet '{}' not found at {}",
            wallet_name,
            wallet_dir.display()
        )));
    }

    let (pair, mut phrase, mut seed) = generate_keypair(n_words)?;
    let ss58 = pair.public().to_ss58check();
    let seed_hex = format!("0x{}", hex::encode(seed));

    let json = build_key_json(&pair, &phrase, &seed_hex);
    let json_str = serde_json::to_string(&json)
        .map_err(|e| BttError::io(format!("failed to serialize hotkey: {}", e)))?;

    let hotkeys_dir = wallet_dir.join("hotkeys");
    fs::create_dir_all(&hotkeys_dir)
        .map_err(|e| BttError::io(format!("failed to create hotkeys directory: {}", e)))?;
    fs::write(hotkeys_dir.join(hotkey_name), &json_str)
        .map_err(|e| BttError::io(format!("failed to write hotkey: {}", e)))?;

    let mnemonic_out = phrase.clone();

    phrase.zeroize();
    seed.zeroize();

    Ok(NewHotkeyResult {
        wallet_name: wallet_name.to_string(),
        hotkey_name: hotkey_name.to_string(),
        ss58_address: ss58,
        mnemonic: mnemonic_out,
    })
}

/// Restore a coldkey from mnemonic or seed.
pub fn regen_coldkey(
    wallet_name: &str,
    mnemonic: Option<&str>,
    seed_hex: Option<&str>,
    password: &str,
) -> Result<RegenResult, BttError> {
    let (pair, phrase, seed) = recover_keypair(mnemonic, seed_hex)?;
    let ss58 = pair.public().to_ss58check();
    let seed_hex_str = format!("0x{}", hex::encode(seed));

    let json = build_key_json(&pair, &phrase, &seed_hex_str);
    let json_str = serde_json::to_string(&json)
        .map_err(|e| BttError::io(format!("failed to serialize coldkey: {}", e)))?;

    let wallet_dir = wallet_path(wallet_name)?;
    fs::create_dir_all(&wallet_dir)
        .map_err(|e| BttError::io(format!("failed to create wallet directory: {}", e)))?;

    let encrypted = encrypt_key_data(json_str.as_bytes(), password)?;
    write_secure_file(&wallet_dir.join("coldkey"), &encrypted)?;

    let pub_data = build_pub_key_json(&pair);
    let pub_json_str = serde_json::to_string(&pub_data)
        .map_err(|e| BttError::io(format!("failed to serialize coldkeypub: {}", e)))?;
    fs::write(wallet_dir.join("coldkeypub.txt"), &pub_json_str)
        .map_err(|e| BttError::io(format!("failed to write coldkeypub.txt: {}", e)))?;

    Ok(RegenResult {
        wallet_name: wallet_name.to_string(),
        ss58_address: ss58,
    })
}

/// Restore a hotkey from mnemonic or seed.
pub fn regen_hotkey(
    wallet_name: &str,
    hotkey_name: &str,
    mnemonic: Option<&str>,
    seed_hex: Option<&str>,
) -> Result<RegenHotkeyResult, BttError> {
    let wallet_dir = wallet_path(wallet_name)?;
    if !wallet_dir.exists() {
        return Err(BttError::wallet_not_found(format!(
            "wallet '{}' not found at {}",
            wallet_name,
            wallet_dir.display()
        )));
    }

    let (pair, phrase, seed) = recover_keypair(mnemonic, seed_hex)?;
    let ss58 = pair.public().to_ss58check();
    let seed_hex_str = format!("0x{}", hex::encode(seed));

    let json = build_key_json(&pair, &phrase, &seed_hex_str);
    let json_str = serde_json::to_string(&json)
        .map_err(|e| BttError::io(format!("failed to serialize hotkey: {}", e)))?;

    let hotkeys_dir = wallet_dir.join("hotkeys");
    fs::create_dir_all(&hotkeys_dir)
        .map_err(|e| BttError::io(format!("failed to create hotkeys directory: {}", e)))?;
    fs::write(hotkeys_dir.join(hotkey_name), &json_str)
        .map_err(|e| BttError::io(format!("failed to write hotkey: {}", e)))?;

    Ok(RegenHotkeyResult {
        wallet_name: wallet_name.to_string(),
        hotkey_name: hotkey_name.to_string(),
        ss58_address: ss58,
    })
}

/// Sign a message with a key from the wallet.
pub fn sign(
    wallet_name: &str,
    hotkey_name: &str,
    message: &str,
    use_hotkey: bool,
    password: Option<&str>,
) -> Result<SignResult, BttError> {
    let wallet_dir = wallet_path(wallet_name)?;
    if !wallet_dir.exists() {
        return Err(BttError::wallet_not_found(format!(
            "wallet '{}' not found at {}",
            wallet_name,
            wallet_dir.display()
        )));
    }

    let pair = if use_hotkey {
        load_hotkey(&wallet_dir, hotkey_name)?
    } else {
        let pw = password
            .ok_or_else(|| BttError::invalid_input("password required to decrypt coldkey"))?;
        load_coldkey(&wallet_dir, pw)?
    };

    let sig = <Pair as TraitPair>::sign(&pair, message.as_bytes());
    let public = pair.public();
    let ss58 = public.to_ss58check();

    Ok(SignResult {
        signature: format!("0x{}", hex::encode(sig.0)),
        public_key: format!("0x{}", hex::encode(public.0)),
        ss58_address: ss58,
    })
}

/// Verify a signature against a message and SS58 address.
pub fn verify(message: &str, signature_hex: &str, ss58: &str) -> Result<VerifyResult, BttError> {
    let public = Public::from_ss58check(ss58)
        .map_err(|e| BttError::invalid_address(format!("invalid SS58 address: {:?}", e)))?;

    let sig_bytes = parse_hex_bytes(signature_hex)?;
    if sig_bytes.len() != 64 {
        return Err(BttError::invalid_input(format!(
            "signature must be 64 bytes, got {}",
            sig_bytes.len()
        )));
    }

    let mut sig_arr = [0u8; 64];
    sig_arr.copy_from_slice(&sig_bytes);
    let signature = Signature::from(sig_arr);

    let valid = <Pair as TraitPair>::verify(&signature, message.as_bytes(), &public);

    Ok(VerifyResult { valid })
}

// ── Internal helpers ──────────────────────────────────────────────────────

fn validate_n_words(n: u32) -> Result<(), BttError> {
    if n != 12 && n != 24 {
        return Err(BttError::invalid_input(
            "n-words must be 12 or 24",
        ));
    }
    Ok(())
}

fn wallet_path(name: &str) -> Result<PathBuf, BttError> {
    let home =
        std::env::var("HOME").map_err(|_| BttError::io("HOME environment variable not set"))?;
    Ok(PathBuf::from(home)
        .join(".bittensor")
        .join("wallets")
        .join(name))
}

/// Generate an sr25519 keypair with a BIP39 mnemonic of the specified word count.
fn generate_keypair(n_words: u32) -> Result<(Pair, String, [u8; 32]), BttError> {
    let mnemonic = bip39::Mnemonic::generate(n_words as usize)
        .map_err(|e| BttError::crypto(format!("failed to generate mnemonic: {}", e)))?;
    let phrase = mnemonic.words().collect::<Vec<_>>().join(" ");

    let (pair, seed) = Pair::from_phrase(&phrase, None)
        .map_err(|e| BttError::crypto(format!("failed to derive keypair from mnemonic: {:?}", e)))?;

    Ok((pair, phrase, seed))
}

/// Recover a keypair from either a mnemonic phrase or a hex seed.
fn recover_keypair(
    mnemonic: Option<&str>,
    seed_hex: Option<&str>,
) -> Result<(Pair, String, [u8; 32]), BttError> {
    match (mnemonic, seed_hex) {
        (Some(phrase), None) => {
            let (pair, seed) = Pair::from_phrase(phrase, None).map_err(|e| {
                BttError::crypto(format!("failed to derive keypair from mnemonic: {:?}", e))
            })?;
            Ok((pair, phrase.to_string(), seed))
        }
        (None, Some(hex_str)) => {
            let seed_bytes = parse_hex_bytes(hex_str)?;
            if seed_bytes.len() != 32 {
                return Err(BttError::invalid_input(format!(
                    "seed must be 32 bytes, got {}",
                    seed_bytes.len()
                )));
            }
            let mut seed = [0u8; 32];
            seed.copy_from_slice(&seed_bytes);
            let pair = Pair::from_seed(&seed);
            Ok((pair, String::new(), seed))
        }
        (Some(_), Some(_)) => Err(BttError::invalid_input(
            "provide either --mnemonic or --seed, not both",
        )),
        (None, None) => Err(BttError::invalid_input(
            "provide either --mnemonic or --seed",
        )),
    }
}

/// Parse a hex string (with optional 0x prefix) into bytes.
fn parse_hex_bytes(s: &str) -> Result<Vec<u8>, BttError> {
    let stripped = s.strip_prefix("0x").unwrap_or(s);
    hex::decode(stripped).map_err(|e| BttError::parse(format!("invalid hex: {}", e)))
}

/// Build the btcli-compatible key JSON structure.
fn build_key_json(pair: &Pair, phrase: &str, seed_hex: &str) -> KeyFileData {
    let public = pair.public();
    KeyFileData {
        account_id: format!("0x{}", hex::encode(public.0)),
        public_key: format!("0x{}", hex::encode(public.0)),
        secret_phrase: phrase.to_string(),
        secret_seed: seed_hex.to_string(),
        ss58_address: public.to_ss58check(),
    }
}

/// Build public key JSON (for coldkeypub.txt).
fn build_pub_key_json(pair: &Pair) -> PubKeyFileData {
    let public = pair.public();
    PubKeyFileData {
        account_id: format!("0x{}", hex::encode(public.0)),
        public_key: format!("0x{}", hex::encode(public.0)),
        ss58_address: public.to_ss58check(),
    }
}

/// Encrypt key data using NaCl secretbox (XSalsa20-Poly1305) with
/// password-derived key via scrypt. Matches btcli's encryption format.
fn encrypt_key_data(plaintext: &[u8], password: &str) -> Result<Vec<u8>, BttError> {
    use rand::RngCore;
    use scrypt::scrypt;
    use xsalsa20poly1305::aead::Aead;
    use xsalsa20poly1305::{KeyInit, XSalsa20Poly1305};

    // Derive key from password using scrypt
    let mut salt = [0u8; 16];
    rand::thread_rng().fill_bytes(&mut salt);

    let params = scrypt::Params::new(SCRYPT_LOG_N, SCRYPT_R, SCRYPT_P, SCRYPT_DKLEN)
        .map_err(|e| BttError::crypto(format!("invalid scrypt parameters: {}", e)))?;

    let mut key = [0u8; SCRYPT_DKLEN];
    scrypt(password.as_bytes(), &salt, &params, &mut key)
        .map_err(|e| BttError::crypto(format!("scrypt key derivation failed: {}", e)))?;

    // Generate nonce
    let mut nonce_bytes = [0u8; NONCE_LEN];
    rand::thread_rng().fill_bytes(&mut nonce_bytes);
    let nonce = xsalsa20poly1305::Nonce::from(nonce_bytes);

    // Encrypt
    let cipher = XSalsa20Poly1305::new(xsalsa20poly1305::Key::from_slice(&key));
    let ciphertext = cipher
        .encrypt(&nonce, plaintext)
        .map_err(|e| BttError::crypto(format!("encryption failed: {}", e)))?;

    // Format: salt (16) || nonce (24) || ciphertext
    let mut output = Vec::with_capacity(salt.len() + NONCE_LEN + ciphertext.len());
    output.extend_from_slice(&salt);
    output.extend_from_slice(&nonce_bytes);
    output.extend_from_slice(&ciphertext);

    key.zeroize();

    Ok(output)
}

/// Decrypt key data encrypted with encrypt_key_data.
fn decrypt_key_data(encrypted: &[u8], password: &str) -> Result<Vec<u8>, BttError> {
    use scrypt::scrypt;
    use xsalsa20poly1305::aead::Aead;
    use xsalsa20poly1305::{KeyInit, XSalsa20Poly1305};

    let min_len = 16 + NONCE_LEN + 16; // salt + nonce + poly1305 tag
    if encrypted.len() < min_len {
        return Err(BttError::crypto("encrypted data too short"));
    }

    let salt = &encrypted[..16];
    let nonce_bytes = &encrypted[16..16 + NONCE_LEN];
    let ciphertext = &encrypted[16 + NONCE_LEN..];

    let params = scrypt::Params::new(SCRYPT_LOG_N, SCRYPT_R, SCRYPT_P, SCRYPT_DKLEN)
        .map_err(|e| BttError::crypto(format!("invalid scrypt parameters: {}", e)))?;

    let mut key = [0u8; SCRYPT_DKLEN];
    scrypt(password.as_bytes(), salt, &params, &mut key)
        .map_err(|e| BttError::crypto(format!("scrypt key derivation failed: {}", e)))?;

    let nonce = xsalsa20poly1305::Nonce::from_slice(nonce_bytes);
    let cipher = XSalsa20Poly1305::new(xsalsa20poly1305::Key::from_slice(&key));

    let plaintext = cipher
        .decrypt(nonce, ciphertext)
        .map_err(|_| BttError::crypto("decryption failed — wrong password or corrupted file"))?;

    key.zeroize();

    Ok(plaintext)
}

/// Write a file and set permissions to 0600 on unix.
fn write_secure_file(path: &PathBuf, data: &[u8]) -> Result<(), BttError> {
    fs::write(path, data)
        .map_err(|e| BttError::io(format!("failed to write {}: {}", path.display(), e)))?;

    #[cfg(unix)]
    {
        let perms = std::fs::Permissions::from_mode(0o600);
        fs::set_permissions(path, perms)
            .map_err(|e| BttError::io(format!("failed to set permissions on {}: {}", path.display(), e)))?;
    }

    Ok(())
}

/// Load and decrypt a coldkey from a wallet directory.
fn load_coldkey(wallet_dir: &std::path::Path, password: &str) -> Result<Pair, BttError> {
    let coldkey_path = wallet_dir.join("coldkey");
    if !coldkey_path.exists() {
        return Err(BttError::wallet_not_found("coldkey file not found"));
    }

    let encrypted = fs::read(&coldkey_path)
        .map_err(|e| BttError::io(format!("failed to read coldkey: {}", e)))?;

    let decrypted = decrypt_key_data(&encrypted, password)?;
    let json_str = String::from_utf8(decrypted)
        .map_err(|_| BttError::crypto("decrypted coldkey is not valid UTF-8"))?;

    pair_from_key_json(&json_str)
}

/// Load a hotkey (unencrypted) from a wallet directory.
fn load_hotkey(wallet_dir: &std::path::Path, hotkey_name: &str) -> Result<Pair, BttError> {
    let hotkey_path = wallet_dir.join("hotkeys").join(hotkey_name);
    if !hotkey_path.exists() {
        return Err(BttError::wallet_not_found(format!(
            "hotkey '{}' not found",
            hotkey_name
        )));
    }

    let json_str = fs::read_to_string(&hotkey_path)
        .map_err(|e| BttError::io(format!("failed to read hotkey: {}", e)))?;

    pair_from_key_json(&json_str)
}

/// Recover a Pair from a btcli-format key JSON string.
/// Tries secretPhrase first (mnemonic), then secretSeed.
fn pair_from_key_json(json_str: &str) -> Result<Pair, BttError> {
    let v: serde_json::Value = serde_json::from_str(json_str)
        .map_err(|e| BttError::parse(format!("invalid key JSON: {}", e)))?;

    // Try mnemonic first
    if let Some(phrase) = v.get("secretPhrase").and_then(|v| v.as_str()) {
        if !phrase.is_empty() {
            let (pair, _seed) = Pair::from_phrase(phrase, None).map_err(|e| {
                BttError::crypto(format!("failed to recover from mnemonic: {:?}", e))
            })?;
            return Ok(pair);
        }
    }

    // Fall back to seed
    if let Some(seed_str) = v.get("secretSeed").and_then(|v| v.as_str()) {
        if !seed_str.is_empty() {
            let seed_bytes = parse_hex_bytes(seed_str)?;
            if seed_bytes.len() != 32 {
                return Err(BttError::parse("secretSeed must be 32 bytes"));
            }
            let mut seed = [0u8; 32];
            seed.copy_from_slice(&seed_bytes);
            let pair = Pair::from_seed(&seed);
            seed.zeroize();
            return Ok(pair);
        }
    }

    Err(BttError::parse(
        "key file contains neither secretPhrase nor secretSeed",
    ))
}

/// Read password from terminal with no echo.
pub fn read_password(prompt: &str) -> Result<String, BttError> {
    rpassword::prompt_password_stdout(prompt)
        .map_err(|e| BttError::io(format!("failed to read password: {}", e)))
}

// ── Tests ─────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use sp_core::Pair as TraitPairAlias;

    #[test]
    fn generate_12_word_keypair() {
        let (pair, phrase, seed) = generate_keypair(12).expect("12-word generation should work");
        let words: Vec<&str> = phrase.split_whitespace().collect();
        assert_eq!(words.len(), 12);
        assert!(!seed.iter().all(|&b| b == 0), "seed should not be all zeros");
        let ss58 = pair.public().to_ss58check();
        assert!(ss58.starts_with('5'), "SS58 address should start with 5");
    }

    #[test]
    fn generate_24_word_keypair() {
        let (pair, phrase, _seed) = generate_keypair(24).expect("24-word generation should work");
        let words: Vec<&str> = phrase.split_whitespace().collect();
        assert_eq!(words.len(), 24);
        let ss58 = pair.public().to_ss58check();
        assert!(ss58.starts_with('5'), "SS58 address should start with 5");
    }

    #[test]
    fn invalid_n_words_rejected() {
        assert!(validate_n_words(11).is_err());
        assert!(validate_n_words(12).is_ok());
        assert!(validate_n_words(24).is_ok());
        assert!(validate_n_words(25).is_err());
    }

    #[test]
    fn mnemonic_recovery_roundtrip() {
        let (original, phrase, _seed) =
            generate_keypair(12).expect("generation should work");

        let (recovered, _recovered_phrase, _recovered_seed) =
            recover_keypair(Some(&phrase), None).expect("recovery should work");

        assert_eq!(
            original.public(),
            recovered.public(),
            "recovered key should match original"
        );
    }

    #[test]
    fn seed_recovery_roundtrip() {
        let (_pair, _phrase, seed) = generate_keypair(12).expect("generation should work");
        let seed_hex = format!("0x{}", hex::encode(seed));

        let (recovered, _, recovered_seed) =
            recover_keypair(None, Some(&seed_hex)).expect("seed recovery should work");

        assert_eq!(seed, recovered_seed, "recovered seed should match");
        let pair_from_seed = Pair::from_seed(&seed);
        assert_eq!(
            pair_from_seed.public(),
            recovered.public(),
            "recovered key should match"
        );
    }

    #[test]
    fn sign_verify_roundtrip() {
        let (pair, _phrase, _seed) = generate_keypair(12).expect("generation should work");
        let message = b"test message for signing";

        let sig = <Pair as TraitPairAlias>::sign(&pair, message);
        let valid =
            <Pair as TraitPairAlias>::verify(&sig, &message[..], &pair.public());
        assert!(valid, "signature should verify");

        // Wrong message should fail
        let bad_valid =
            <Pair as TraitPairAlias>::verify(&sig, b"wrong message", &pair.public());
        assert!(!bad_valid, "wrong message should not verify");
    }

    #[test]
    fn encrypt_decrypt_roundtrip() {
        let plaintext = b"sensitive key material here";
        let password = "test-password-123";

        let encrypted = encrypt_key_data(plaintext, password).expect("encryption should work");
        assert_ne!(&encrypted[..], plaintext, "ciphertext should differ from plaintext");

        let decrypted = decrypt_key_data(&encrypted, password).expect("decryption should work");
        assert_eq!(&decrypted[..], plaintext, "decrypted should match original");
    }

    #[test]
    fn decrypt_wrong_password_fails() {
        let plaintext = b"sensitive key material";
        let encrypted = encrypt_key_data(plaintext, "correct").expect("encryption should work");
        let result = decrypt_key_data(&encrypted, "wrong");
        assert!(result.is_err(), "wrong password should fail");
    }

    #[test]
    fn key_json_format() {
        let (pair, phrase, seed) = generate_keypair(12).expect("generation should work");
        let seed_hex = format!("0x{}", hex::encode(seed));
        let json = build_key_json(&pair, &phrase, &seed_hex);
        let json_str =
            serde_json::to_string(&json).expect("should serialize");

        let v: serde_json::Value =
            serde_json::from_str(&json_str).expect("should parse");
        assert!(v.get("accountId").is_some());
        assert!(v.get("publicKey").is_some());
        assert!(v.get("secretPhrase").is_some());
        assert!(v.get("secretSeed").is_some());
        assert!(v.get("ss58Address").is_some());

        // Verify we can recover from the JSON
        let recovered = pair_from_key_json(&json_str).expect("should recover");
        assert_eq!(pair.public(), recovered.public());
    }

    #[test]
    fn parse_hex_with_prefix() {
        let bytes = parse_hex_bytes("0xdeadbeef").expect("should parse");
        assert_eq!(bytes, vec![0xde, 0xad, 0xbe, 0xef]);
    }

    #[test]
    fn parse_hex_without_prefix() {
        let bytes = parse_hex_bytes("deadbeef").expect("should parse");
        assert_eq!(bytes, vec![0xde, 0xad, 0xbe, 0xef]);
    }

    #[test]
    fn verify_command_valid_signature() {
        let (pair, _phrase, _seed) = generate_keypair(12).expect("generation should work");
        let message = "hello world";
        let sig = <Pair as TraitPairAlias>::sign(&pair, message.as_bytes());
        let sig_hex = format!("0x{}", hex::encode(sig.0));
        let ss58 = pair.public().to_ss58check();

        let result = verify(message, &sig_hex, &ss58).expect("verify should work");
        assert!(result.valid, "valid signature should verify");
    }

    #[test]
    fn verify_command_invalid_signature() {
        let (pair, _phrase, _seed) = generate_keypair(12).expect("generation should work");
        let ss58 = pair.public().to_ss58check();

        let result =
            verify("hello", "0x00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000", &ss58)
                .expect("verify should work even with bad sig");
        assert!(!result.valid, "invalid signature should not verify");
    }

    #[test]
    fn create_wallet_roundtrip() {
        // Use a temp directory to avoid polluting ~/.bittensor
        let tmp = std::env::temp_dir().join(format!("btt-test-{}", std::process::id()));
        let wallet_name = "test-wallet";
        let _wallet_dir = tmp.join(wallet_name);

        // Override HOME for this test
        let original_home = std::env::var("HOME").ok();
        let _bittensor_dir = tmp.clone();
        // We need to set up the path structure: tmp/.bittensor/wallets/test-wallet
        let wallets_parent = tmp.join(".bittensor").join("wallets");
        std::fs::create_dir_all(&wallets_parent).expect("create temp dir");

        std::env::set_var("HOME", tmp.to_str().expect("valid path"));

        let password = "test-password";
        let result = create(wallet_name, "default", 12, password);

        // Restore HOME
        if let Some(h) = original_home {
            std::env::set_var("HOME", &h);
        }

        // Cleanup
        let _ = std::fs::remove_dir_all(&tmp);

        let result = result.expect("create should work");
        assert_eq!(result.wallet_name, wallet_name);
        assert!(result.coldkey_ss58.starts_with('5'));
        assert!(result.hotkey_ss58.starts_with('5'));
        let words: Vec<&str> = result.mnemonic.split_whitespace().collect();
        assert_eq!(words.len(), 12);
    }

    // -- TAO/RAO conversion tests --

    #[test]
    fn tao_to_rao_whole_number() {
        assert_eq!(tao_to_rao(1.0).expect("1 TAO"), 1_000_000_000);
    }

    #[test]
    fn tao_to_rao_fractional() {
        assert_eq!(tao_to_rao(0.5).expect("0.5 TAO"), 500_000_000);
    }

    #[test]
    fn tao_to_rao_zero() {
        assert_eq!(tao_to_rao(0.0).expect("0 TAO"), 0);
    }

    #[test]
    fn tao_to_rao_large_amount() {
        let rao = tao_to_rao(21_000_000.0).expect("21M TAO");
        assert_eq!(rao, 21_000_000_000_000_000);
    }

    #[test]
    fn tao_to_rao_negative_fails() {
        assert!(tao_to_rao(-1.0).is_err());
    }

    #[test]
    fn tao_to_rao_nan_fails() {
        assert!(tao_to_rao(f64::NAN).is_err());
    }

    #[test]
    fn tao_to_rao_infinity_fails() {
        assert!(tao_to_rao(f64::INFINITY).is_err());
    }

    #[test]
    fn rao_to_tao_string_whole() {
        assert_eq!(rao_to_tao_string(1_000_000_000), "1.0");
    }

    #[test]
    fn rao_to_tao_string_fractional() {
        assert_eq!(rao_to_tao_string(1_500_000_000), "1.5");
    }

    #[test]
    fn rao_to_tao_string_zero() {
        assert_eq!(rao_to_tao_string(0), "0.0");
    }

    #[test]
    fn rao_to_tao_string_small() {
        assert_eq!(rao_to_tao_string(1), "0.000000001");
    }

    #[test]
    fn rao_to_tao_string_precise() {
        assert_eq!(rao_to_tao_string(100_500_000_000), "100.5");
    }

    #[test]
    fn extract_ss58_from_json_content() {
        let json = r#"{"ss58Address": "5GrwvaEF5zXb26Fz9rcQpDWS57CtERHpNehXCPcNoHGKutQY"}"#;
        let addr = extract_ss58_from_content(json);
        assert_eq!(
            addr,
            Some("5GrwvaEF5zXb26Fz9rcQpDWS57CtERHpNehXCPcNoHGKutQY".to_string())
        );
    }

    #[test]
    fn extract_ss58_from_raw_content() {
        let raw = "5GrwvaEF5zXb26Fz9rcQpDWS57CtERHpNehXCPcNoHGKutQY\n";
        let addr = extract_ss58_from_content(raw);
        assert_eq!(
            addr,
            Some("5GrwvaEF5zXb26Fz9rcQpDWS57CtERHpNehXCPcNoHGKutQY".to_string())
        );
    }

    #[test]
    fn extract_ss58_from_empty_returns_none() {
        assert!(extract_ss58_from_content("").is_none());
    }

    #[test]
    fn create_and_sign_roundtrip() {
        let tmp = std::env::temp_dir().join(format!("btt-test-sign-{}", std::process::id()));
        let wallet_name = "sign-test";

        let original_home = std::env::var("HOME").ok();
        let wallets_parent = tmp.join(".bittensor").join("wallets");
        std::fs::create_dir_all(&wallets_parent).expect("create temp dir");

        std::env::set_var("HOME", tmp.to_str().expect("valid path"));

        let password = "sign-test-pw";
        let cr = create(wallet_name, "default", 12, password).expect("create should work");

        // Sign with coldkey
        let sign_result =
            sign(wallet_name, "default", "hello", false, Some(password)).expect("sign coldkey");
        assert_eq!(sign_result.ss58_address, cr.coldkey_ss58);

        // Verify the coldkey signature
        let vr = verify("hello", &sign_result.signature, &sign_result.ss58_address)
            .expect("verify coldkey sig");
        assert!(vr.valid);

        // Sign with hotkey
        let hk_sign = sign(wallet_name, "default", "hello", true, None).expect("sign hotkey");
        assert_eq!(hk_sign.ss58_address, cr.hotkey_ss58);

        // Verify the hotkey signature
        let hk_vr = verify("hello", &hk_sign.signature, &hk_sign.ss58_address)
            .expect("verify hotkey sig");
        assert!(hk_vr.valid);

        if let Some(h) = original_home {
            std::env::set_var("HOME", &h);
        }
        let _ = std::fs::remove_dir_all(&tmp);
    }

    #[test]
    fn regen_coldkey_from_mnemonic() {
        let tmp = std::env::temp_dir().join(format!("btt-test-regen-{}", std::process::id()));
        let wallet_name = "regen-test";

        let original_home = std::env::var("HOME").ok();
        let wallets_parent = tmp.join(".bittensor").join("wallets");
        std::fs::create_dir_all(&wallets_parent).expect("create temp dir");

        std::env::set_var("HOME", tmp.to_str().expect("valid path"));

        let password = "regen-pw";
        let cr = create(wallet_name, "default", 12, password).expect("create should work");

        // Regenerate the coldkey from the mnemonic
        let regen = regen_coldkey(wallet_name, Some(&cr.mnemonic), None, password)
            .expect("regen should work");
        assert_eq!(regen.ss58_address, cr.coldkey_ss58);

        // Sign with the regenerated coldkey and verify
        let sign_result =
            sign(wallet_name, "default", "regen-msg", false, Some(password)).expect("sign regen");
        let vr = verify("regen-msg", &sign_result.signature, &sign_result.ss58_address)
            .expect("verify regen sig");
        assert!(vr.valid);
        assert_eq!(sign_result.ss58_address, cr.coldkey_ss58);

        if let Some(h) = original_home {
            std::env::set_var("HOME", &h);
        }
        let _ = std::fs::remove_dir_all(&tmp);
    }
}
