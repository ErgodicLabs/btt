use std::fs;
use std::io::Write;
#[cfg(unix)]
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use sp_core::crypto::{Pair as TraitPair, Ss58Codec};
use sp_core::sr25519::{Pair, Public, Signature};
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

use crate::commands::paths;
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
/// Reads `<config_dir>/wallets/<name>/coldkeypub.txt` — see
/// [`crate::commands::paths::config_dir`] for the per-OS location.
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

    // Try reading as unencrypted JSON first (development/testing keys).
    // The plaintext contents still hold a mnemonic, so funnel it through
    // a `Zeroizing<Vec<u8>>` instead of `fs::read_to_string`, which would
    // leak the bytes to an unscrubbed `String` allocation.
    //
    // We skip the old `serde_json::Value` pre-check (which itself would
    // allocate unscrubbed owned `String`s for every JSON string node) and
    // go straight to `pair_from_key_json`, which routes the data through
    // the zeroizing `LoadedKeyFile`. On an encrypted `$NACL` envelope the
    // UTF-8 check fails and we fall through to the decrypt branch.
    if let Ok(raw) = fs::read(&coldkey_path) {
        let raw: Zeroizing<Vec<u8>> = Zeroizing::new(raw);
        if let Ok(content) = std::str::from_utf8(&raw) {
            if let Ok(pair) = pair_from_key_json(content) {
                return Ok(pair);
            }
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

// btcli / btwallet on-disk envelope for encrypted coldkeys.
//
// Format: b"$NACL" || nonce (24 bytes) || secretbox_ciphertext
//
// KDF: libsodium `pwhash::argon2i13::derive_key` with
//   OPSLIMIT_SENSITIVE = 8, MEMLIMIT_SENSITIVE = 512 MiB, salt = NACL_SALT.
// Mapped onto the RustCrypto `argon2` crate as
//   Algorithm = Argon2i, Version = V0x13, t_cost = 8, m_cost = 524288 KiB,
//   parallelism = 1, output = 32 bytes.
//
// Reference: opentensor/btwallet src/keyfile.rs (NACL_SALT, derive_key,
// encrypt_keyfile_data, decrypt_keyfile_data).
const NACL_SALT: &[u8; 16] = b"\x13q\x83\xdf\xf1Z\t\xbc\x9c\x90\xb5Q\x879\xe9\xb1";
const NACL_MAGIC: &[u8; 5] = b"$NACL";
const NACL_KEY_LEN: usize = 32;
const NACL_NONCE_LEN: usize = 24;
const ARGON2_T_COST: u32 = 8;
const ARGON2_M_COST_KIB: u32 = 524_288; // 512 MiB
const ARGON2_PARALLELISM: u32 = 1;

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

// ── Load-path deserialization target ──────────────────────────────────────
//
// When decrypting a coldkey (or reading an unencrypted hotkey), the JSON
// blob is parsed into this struct instead of a free-form `serde_json::Value`.
// `Value` owns `String`s for every string node and does NOT scrub them on
// drop, so routing the decrypted material through it would leave the
// mnemonic and raw seed floating in freed heap chunks until reuse.
//
// `LoadedKeyFile` holds exactly the secret-bearing fields we consume and
// derives `Zeroize` + `ZeroizeOnDrop`, so every `String` byte is overwritten
// with zero before the allocation is returned to the allocator. Non-secret
// hint fields from the on-disk format (accountId, publicKey, ss58Address)
// are intentionally ignored — they carry no value the caller cannot
// rederive from the keypair itself, and omitting them keeps the zeroized
// footprint minimal.
#[derive(Deserialize, Zeroize, ZeroizeOnDrop, Default)]
#[serde(rename_all = "camelCase")]
struct LoadedKeyFile {
    #[serde(default)]
    secret_phrase: Option<String>,
    #[serde(default)]
    secret_seed: Option<String>,
}

// ── Core operations ───────────────────────────────────────────────────────

/// Refuse to overwrite an existing key file unless `force` is set.
///
/// `label` is a short human-readable tag for the key type ("coldkey",
/// "hotkey") used both in the error message and the stderr warning. If
/// the file does not exist, this is a no-op. If it exists and `force` is
/// false, returns a `wallet_not_found`-adjacent `invalid_input` error
/// naming the file and instructing the caller to delete or pass
/// `--force`. If it exists and `force` is true, emits a one-line stderr
/// warning naming the file being destroyed and returns `Ok`. The actual
/// removal is performed atomically by `write_secure_file`.
fn guard_overwrite(path: &Path, label: &str, force: bool) -> Result<(), BttError> {
    if !path.exists() {
        return Ok(());
    }
    if !force {
        return Err(BttError::invalid_input(format!(
            "{label} file already exists at {}: refusing to overwrite. \
             Delete the file or pass --force to destroy and replace it.",
            path.display()
        )));
    }
    let _ = writeln!(
        std::io::stderr(),
        "btt: --force: destroying existing {label} at {}",
        path.display()
    );
    Ok(())
}

/// Refuse to overwrite an existing wallet from `wallet create` unless
/// `force` is set.
///
/// Semantically distinct from `guard_overwrite`: `wallet create` mints a
/// fresh mnemonic for both coldkey and hotkey, so a `--force` run destroys
/// the entire wallet (not just a single key file) without any way to
/// reconstruct it from the command's own inputs. The error is therefore
/// louder, names the wallet, and explicitly warns about irreversibility.
///
/// If neither file exists, this is a no-op. If either file exists and
/// `force` is false, returns an `invalid_input` error naming the wallet
/// and the offending path. If either exists and `force` is true, emits
/// one stderr warning per existing file and returns `Ok` — the actual
/// removal is performed atomically by `write_secure_file`.
fn guard_create_overwrite(
    wallet_name: &str,
    coldkey_path: &Path,
    hotkey_path: &Path,
    force: bool,
) -> Result<(), BttError> {
    let cold_exists = coldkey_path.exists();
    let hot_exists = hotkey_path.exists();
    if !cold_exists && !hot_exists {
        return Ok(());
    }
    if !force {
        // Report the coldkey path preferentially — it is the irreplaceable
        // half of the wallet. If only the hotkey exists, name it instead.
        let (label, path) = if cold_exists {
            ("coldkey", coldkey_path)
        } else {
            ("hotkey", hotkey_path)
        };
        return Err(BttError::invalid_input(format!(
            "refusing to overwrite existing wallet '{}' ({} at {}). \
             Pass --force to destroy the existing wallet and create a new one. \
             THIS IS IRREVERSIBLE — back up the existing mnemonic first if you have not.",
            wallet_name,
            label,
            path.display()
        )));
    }
    if cold_exists {
        let _ = writeln!(
            std::io::stderr(),
            "btt: --force: destroying existing coldkey at {}",
            coldkey_path.display()
        );
    }
    if hot_exists {
        let _ = writeln!(
            std::io::stderr(),
            "btt: --force: destroying existing hotkey at {}",
            hotkey_path.display()
        );
    }
    Ok(())
}

/// Create a new wallet with both coldkey and hotkey.
///
/// Refuses to run if either `<wallet>/coldkey` or
/// `<wallet>/hotkeys/<hotkey_name>` already exists, unless `force` is set.
/// The guard runs before any secret material is generated, so the refusal
/// path never touches the on-disk wallet and never leaves fresh secret
/// bytes on the heap.
///
/// Issue #19: prior to this guard, `write_secure_file` unlinked the target
/// before re-creating it, which defeated the `O_CREAT|O_EXCL` atomicity
/// and caused a second invocation of `wallet create --name <same>` to
/// silently destroy an irrecoverable wallet. See also PR #18 (issue #7)
/// for the same fix on `new-coldkey` / `new-hotkey` / `regen-*`.
pub fn create(
    wallet_name: &str,
    hotkey_name: &str,
    n_words: u32,
    password: &str,
    force: bool,
) -> Result<CreateResult, BttError> {
    validate_n_words(n_words)?;

    // Resolve paths and refuse overwrite BEFORE generating key material.
    // We check both the coldkey and the hotkey file: either one existing
    // indicates a wallet the user might lose. The error names the wallet
    // and the specific path, and explicitly warns about irreversibility —
    // wallet create generates a new mnemonic, so --force destroys the old
    // wallet entirely. See issue #19.
    let wallet_dir = wallet_path(wallet_name)?;
    let coldkey_path = wallet_dir.join("coldkey");
    let hotkey_path = wallet_dir.join("hotkeys").join(hotkey_name);
    guard_create_overwrite(wallet_name, &coldkey_path, &hotkey_path, force)?;

    let (cold_pair, mut cold_phrase, mut cold_seed) = generate_keypair(n_words)?;
    let cold_ss58 = cold_pair.public().to_ss58check();
    let cold_seed_hex = format!("0x{}", hex::encode(cold_seed));

    // Build the JSON for the coldkey
    let cold_json = build_key_json(&cold_pair, &cold_phrase, &cold_seed_hex);
    let mut cold_json_str = serde_json::to_string(&cold_json)
        .map_err(|e| BttError::io(format!("failed to serialize coldkey: {}", e)))?;

    // Encrypt and write coldkey into a 0700 wallet directory
    ensure_wallets_root()?;
    ensure_secure_dir(&wallet_dir)?;

    let mut encrypted = encrypt_key_data(cold_json_str.as_bytes(), password)?;
    write_secure_file(&coldkey_path, &encrypted)?;
    encrypted.zeroize();
    cold_json_str.zeroize();

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
    let mut hot_json_str = serde_json::to_string(&hot_json)
        .map_err(|e| BttError::io(format!("failed to serialize hotkey: {}", e)))?;

    // Write hotkey as an unencrypted file with 0600 perms inside a 0700 dir.
    let hotkeys_dir = wallet_dir.join("hotkeys");
    ensure_secure_dir(&hotkeys_dir)?;
    write_secure_file(&hotkey_path, hot_json_str.as_bytes())?;
    hot_json_str.zeroize();

    let mnemonic_out = cold_phrase.clone();

    // Zeroize sensitive material that will not be returned to the caller.
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
///
/// Refuses to run if `<wallet>/coldkey` already exists unless `force` is set.
pub fn new_coldkey(
    wallet_name: &str,
    n_words: u32,
    password: &str,
    force: bool,
) -> Result<NewColdkeyResult, BttError> {
    validate_n_words(n_words)?;

    // Resolve the target path and refuse overwrite before generating key
    // material. This keeps us from spending CPU on argon2 only to throw
    // the result away, and avoids any window where fresh secret bytes
    // live on the heap alongside a caller-visible error.
    let wallet_dir = wallet_path(wallet_name)?;
    let coldkey_path = wallet_dir.join("coldkey");
    guard_overwrite(&coldkey_path, "coldkey", force)?;

    let (pair, mut phrase, mut seed) = generate_keypair(n_words)?;
    let ss58 = pair.public().to_ss58check();
    let seed_hex = format!("0x{}", hex::encode(seed));

    let json = build_key_json(&pair, &phrase, &seed_hex);
    let mut json_str = serde_json::to_string(&json)
        .map_err(|e| BttError::io(format!("failed to serialize coldkey: {}", e)))?;

    ensure_wallets_root()?;
    ensure_secure_dir(&wallet_dir)?;

    let mut encrypted = encrypt_key_data(json_str.as_bytes(), password)?;
    write_secure_file(&coldkey_path, &encrypted)?;
    encrypted.zeroize();
    json_str.zeroize();

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
///
/// Refuses to run if `<wallet>/hotkeys/<hotkey_name>` already exists unless
/// `force` is set.
pub fn new_hotkey(
    wallet_name: &str,
    hotkey_name: &str,
    n_words: u32,
    force: bool,
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

    // Refuse overwrite before generating fresh key material.
    let hotkey_path = wallet_dir.join("hotkeys").join(hotkey_name);
    guard_overwrite(&hotkey_path, "hotkey", force)?;

    let (pair, mut phrase, mut seed) = generate_keypair(n_words)?;
    let ss58 = pair.public().to_ss58check();
    let seed_hex = format!("0x{}", hex::encode(seed));

    let json = build_key_json(&pair, &phrase, &seed_hex);
    let mut json_str = serde_json::to_string(&json)
        .map_err(|e| BttError::io(format!("failed to serialize hotkey: {}", e)))?;

    let hotkeys_dir = wallet_dir.join("hotkeys");
    ensure_secure_dir(&hotkeys_dir)?;
    write_secure_file(&hotkey_path, json_str.as_bytes())?;
    json_str.zeroize();

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
///
/// Refuses to run if `<wallet>/coldkey` already exists unless `force` is set.
pub fn regen_coldkey(
    wallet_name: &str,
    mnemonic: Option<&str>,
    seed_hex: Option<&str>,
    password: &str,
    force: bool,
) -> Result<RegenResult, BttError> {
    // Resolve and guard before deriving any key material from the user's
    // mnemonic/seed. An error here must not leak a partial recovery state.
    let wallet_dir = wallet_path(wallet_name)?;
    let coldkey_path = wallet_dir.join("coldkey");
    guard_overwrite(&coldkey_path, "coldkey", force)?;

    let (pair, mut phrase, mut seed) = recover_keypair(mnemonic, seed_hex)?;
    let ss58 = pair.public().to_ss58check();
    let seed_hex_str = format!("0x{}", hex::encode(seed));

    let json = build_key_json(&pair, &phrase, &seed_hex_str);
    let mut json_str = serde_json::to_string(&json)
        .map_err(|e| BttError::io(format!("failed to serialize coldkey: {}", e)))?;

    ensure_wallets_root()?;
    ensure_secure_dir(&wallet_dir)?;

    let mut encrypted = encrypt_key_data(json_str.as_bytes(), password)?;
    write_secure_file(&coldkey_path, &encrypted)?;
    encrypted.zeroize();
    json_str.zeroize();
    phrase.zeroize();
    seed.zeroize();

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
///
/// Refuses to run if `<wallet>/hotkeys/<hotkey_name>` already exists unless
/// `force` is set.
pub fn regen_hotkey(
    wallet_name: &str,
    hotkey_name: &str,
    mnemonic: Option<&str>,
    seed_hex: Option<&str>,
    force: bool,
) -> Result<RegenHotkeyResult, BttError> {
    let wallet_dir = wallet_path(wallet_name)?;
    if !wallet_dir.exists() {
        return Err(BttError::wallet_not_found(format!(
            "wallet '{}' not found at {}",
            wallet_name,
            wallet_dir.display()
        )));
    }

    // Refuse overwrite before deriving any key material.
    let hotkey_path = wallet_dir.join("hotkeys").join(hotkey_name);
    guard_overwrite(&hotkey_path, "hotkey", force)?;

    let (pair, mut phrase, mut seed) = recover_keypair(mnemonic, seed_hex)?;
    let ss58 = pair.public().to_ss58check();
    let seed_hex_str = format!("0x{}", hex::encode(seed));

    let json = build_key_json(&pair, &phrase, &seed_hex_str);
    let mut json_str = serde_json::to_string(&json)
        .map_err(|e| BttError::io(format!("failed to serialize hotkey: {}", e)))?;

    let hotkeys_dir = wallet_dir.join("hotkeys");
    ensure_secure_dir(&hotkeys_dir)?;
    write_secure_file(&hotkey_path, json_str.as_bytes())?;
    json_str.zeroize();
    phrase.zeroize();
    seed.zeroize();

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
    // sp-core's `generate_with_phrase` is fixed at 12 words. 24-word support
    // previously relied on a direct `bip39` dep which has been removed per
    // dependency-discipline review; it will return in a follow-up PR.
    if n != 12 {
        return Err(BttError::invalid_input(
            "n-words must be 12 (24-word support pending follow-up)",
        ));
    }
    Ok(())
}

fn wallet_path(name: &str) -> Result<PathBuf, BttError> {
    paths::wallet_dir(name)
}

/// Ensure the config directory and its `wallets/` subdirectory exist at
/// mode 0700. The exact path is OS-dependent — see
/// [`crate::commands::paths::config_dir`].
fn ensure_wallets_root() -> Result<(), BttError> {
    let root = paths::config_dir()?;
    ensure_secure_dir(&root)?;
    ensure_secure_dir(&root.join("wallets"))?;
    Ok(())
}

/// Generate an sr25519 keypair with a BIP39 mnemonic.
/// Uses `sp_core::sr25519::Pair::generate_with_phrase`, which drives BIP39 via
/// the transitive `substrate-bip39` / `parity-bip39` crates — no direct `bip39`
/// dep required. sp-core only exposes 12-word generation; 24-word generation
/// was removed in this PR pending a follow-up that doesn't require pulling a
/// bip39 crate back in for wordlist access.
fn generate_keypair(_n_words: u32) -> Result<(Pair, String, [u8; 32]), BttError> {
    let (pair, phrase, seed) = <Pair as TraitPair>::generate_with_phrase(None);
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
///
/// The returned buffer is wrapped in `Zeroizing` because every current
/// caller uses it to reconstruct secret key material (raw seeds on the
/// load / regen paths). Callers that feed in non-secret hex get a
/// harmlessly-scrubbed buffer; callers that feed in secret hex get a
/// guaranteed scrub on drop.
fn parse_hex_bytes(s: &str) -> Result<Zeroizing<Vec<u8>>, BttError> {
    let stripped = s.strip_prefix("0x").unwrap_or(s);
    hex::decode(stripped)
        .map(Zeroizing::new)
        .map_err(|e| BttError::parse(format!("invalid hex: {}", e)))
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

/// Derive a 32-byte NaCl secretbox key from a password using libsodium's
/// `argon2i13::derive_key` parameters (Argon2i, v0x13, t=8, m=512 MiB, p=1,
/// hardcoded `NACL_SALT`). Byte-for-byte compatible with btwallet/btcli.
fn derive_key(password: &[u8]) -> Result<Zeroizing<[u8; NACL_KEY_LEN]>, BttError> {
    use argon2::{Algorithm, Argon2, Params, Version};

    let params = Params::new(
        ARGON2_M_COST_KIB,
        ARGON2_T_COST,
        ARGON2_PARALLELISM,
        Some(NACL_KEY_LEN),
    )
    .map_err(|e| BttError::crypto(format!("invalid argon2 parameters: {}", e)))?;
    let argon2 = Argon2::new(Algorithm::Argon2i, Version::V0x13, params);

    let mut key = Zeroizing::new([0u8; NACL_KEY_LEN]);
    argon2
        .hash_password_into(password, NACL_SALT, key.as_mut_slice())
        .map_err(|e| BttError::crypto(format!("argon2 key derivation failed: {}", e)))?;
    Ok(key)
}

/// Encrypt key data with the btwallet NaCl envelope:
///   b"$NACL" || nonce (24 bytes) || secretbox_seal(plaintext, nonce, key)
fn encrypt_key_data(plaintext: &[u8], password: &str) -> Result<Vec<u8>, BttError> {
    use rand::RngCore;
    use xsalsa20poly1305::aead::Aead;
    use xsalsa20poly1305::{KeyInit, XSalsa20Poly1305};

    let key = derive_key(password.as_bytes())?;

    let mut nonce_bytes = [0u8; NACL_NONCE_LEN];
    rand::thread_rng().fill_bytes(&mut nonce_bytes);
    let nonce = xsalsa20poly1305::Nonce::from(nonce_bytes);

    let cipher = XSalsa20Poly1305::new(xsalsa20poly1305::Key::from_slice(key.as_slice()));
    let ciphertext = cipher
        .encrypt(&nonce, plaintext)
        .map_err(|e| BttError::crypto(format!("encryption failed: {}", e)))?;

    let mut output = Vec::with_capacity(NACL_MAGIC.len() + NACL_NONCE_LEN + ciphertext.len());
    output.extend_from_slice(NACL_MAGIC);
    output.extend_from_slice(&nonce_bytes);
    output.extend_from_slice(&ciphertext);
    Ok(output)
}

/// Decrypt a btwallet-format NaCl envelope.
///
/// The returned plaintext is wrapped in `Zeroizing<Vec<u8>>` so the decrypted
/// bytes — which, for a real coldkey, contain the JSON-serialized mnemonic
/// and raw seed — are scrubbed when the caller drops the return value. A
/// plain `Vec<u8>` here would rely on `Vec::drop` returning the allocation
/// to the allocator without touching the bytes, leaving the secret sitting
/// in the freed chunk until something else happens to allocate over it.
fn decrypt_key_data(encrypted: &[u8], password: &str) -> Result<Zeroizing<Vec<u8>>, BttError> {
    use xsalsa20poly1305::aead::Aead;
    use xsalsa20poly1305::{KeyInit, XSalsa20Poly1305};

    if !encrypted.starts_with(NACL_MAGIC) {
        return Err(BttError::crypto(
            "unrecognized keyfile format (missing $NACL magic)",
        ));
    }
    let body = &encrypted[NACL_MAGIC.len()..];
    if body.len() < NACL_NONCE_LEN + 16 {
        return Err(BttError::crypto("encrypted data too short"));
    }
    let (nonce_bytes, ciphertext) = body.split_at(NACL_NONCE_LEN);

    let key = derive_key(password.as_bytes())?;

    let nonce = xsalsa20poly1305::Nonce::from_slice(nonce_bytes);
    let cipher = XSalsa20Poly1305::new(xsalsa20poly1305::Key::from_slice(key.as_slice()));

    let plaintext = cipher
        .decrypt(nonce, ciphertext)
        .map_err(|_| BttError::crypto("decryption failed — wrong password or corrupted file"))?;
    Ok(Zeroizing::new(plaintext))
}

/// Create a file at `path` with mode 0600 (unix) atomically via `O_CREAT|O_EXCL`,
/// write `data`, fsync, and close. Fails if the file already exists unless the
/// existing file can be removed first (callers that intend to overwrite should
/// delete first). No TOCTOU window at 0644.
fn write_secure_file(path: &Path, data: &[u8]) -> Result<(), BttError> {
    // If the file exists, remove it first; we want to replace atomically.
    if path.exists() {
        fs::remove_file(path)
            .map_err(|e| BttError::io(format!("failed to remove {}: {}", path.display(), e)))?;
    }

    let mut opts = fs::OpenOptions::new();
    opts.write(true).create_new(true);
    #[cfg(unix)]
    {
        opts.mode(0o600);
    }
    let mut f = opts
        .open(path)
        .map_err(|e| BttError::io(format!("failed to create {}: {}", path.display(), e)))?;
    f.write_all(data)
        .map_err(|e| BttError::io(format!("failed to write {}: {}", path.display(), e)))?;
    f.sync_all()
        .map_err(|e| BttError::io(format!("failed to sync {}: {}", path.display(), e)))?;
    Ok(())
}

/// Create (or tighten) a directory at `path` with mode 0700 on unix.
fn ensure_secure_dir(path: &Path) -> Result<(), BttError> {
    fs::create_dir_all(path)
        .map_err(|e| BttError::io(format!("failed to create directory {}: {}", path.display(), e)))?;
    #[cfg(unix)]
    {
        let perms = fs::Permissions::from_mode(0o700);
        fs::set_permissions(path, perms).map_err(|e| {
            BttError::io(format!(
                "failed to set permissions on {}: {}",
                path.display(),
                e
            ))
        })?;
    }
    Ok(())
}

/// Load and decrypt a coldkey from a wallet directory.
///
/// The decrypted plaintext never leaves this function as an owned unscoped
/// buffer: the decrypt step hands back a `Zeroizing<Vec<u8>>`, we view it
/// as a UTF-8 slice without a second allocation, and `pair_from_key_json`
/// funnels the bytes into a `LoadedKeyFile` that zeroes itself on drop.
/// When this function returns, every heap region that held the mnemonic
/// or the raw seed has been overwritten with zero.
fn load_coldkey(wallet_dir: &std::path::Path, password: &str) -> Result<Pair, BttError> {
    let coldkey_path = wallet_dir.join("coldkey");
    if !coldkey_path.exists() {
        return Err(BttError::wallet_not_found("coldkey file not found"));
    }

    let encrypted = fs::read(&coldkey_path)
        .map_err(|e| BttError::io(format!("failed to read coldkey: {}", e)))?;

    let decrypted: Zeroizing<Vec<u8>> = decrypt_key_data(&encrypted, password)?;
    // Borrow the plaintext as &str instead of moving it into an owned
    // `String`. An owned `String` here would double the secret footprint
    // and, unlike the `Zeroizing<Vec<u8>>` backing store, would not be
    // scrubbed on drop.
    let json_str = std::str::from_utf8(&decrypted)
        .map_err(|_| BttError::crypto("decrypted coldkey is not valid UTF-8"))?;

    pair_from_key_json(json_str)
}

/// Load a hotkey (unencrypted) from a wallet directory.
///
/// Even though the hotkey file is stored without encryption, its contents
/// still contain a mnemonic / raw seed. Read it as bytes into a
/// `Zeroizing<Vec<u8>>` and view it as a slice, rather than calling
/// `fs::read_to_string` which returns an unscrubbed `String`.
fn load_hotkey(wallet_dir: &std::path::Path, hotkey_name: &str) -> Result<Pair, BttError> {
    let hotkey_path = wallet_dir.join("hotkeys").join(hotkey_name);
    if !hotkey_path.exists() {
        return Err(BttError::wallet_not_found(format!(
            "hotkey '{}' not found",
            hotkey_name
        )));
    }

    let raw: Zeroizing<Vec<u8>> = Zeroizing::new(
        fs::read(&hotkey_path)
            .map_err(|e| BttError::io(format!("failed to read hotkey: {}", e)))?,
    );
    let json_str = std::str::from_utf8(&raw)
        .map_err(|_| BttError::parse("hotkey file is not valid UTF-8"))?;

    pair_from_key_json(json_str)
}

/// Recover a Pair from a btcli-format key JSON string.
/// Tries `secretPhrase` first (mnemonic), then `secretSeed`.
///
/// Deserialization targets `LoadedKeyFile` (which derives
/// `Zeroize + ZeroizeOnDrop`) so that the intermediate owned `String`s are
/// overwritten with zero when this function returns — regardless of
/// whether the recovery succeeds or errors out.
fn pair_from_key_json(json_str: &str) -> Result<Pair, BttError> {
    let loaded: LoadedKeyFile = serde_json::from_str(json_str)
        .map_err(|e| BttError::parse(format!("invalid key JSON: {}", e)))?;

    // Try mnemonic first.
    if let Some(phrase) = loaded.secret_phrase.as_deref() {
        if !phrase.is_empty() {
            // `Pair::from_phrase` returns `(Pair, Seed)`. The seed is a
            // fixed-size array; scrub it immediately on the way out.
            let (pair, mut seed) = Pair::from_phrase(phrase, None).map_err(|e| {
                BttError::crypto(format!("failed to recover from mnemonic: {:?}", e))
            })?;
            seed.zeroize();
            return Ok(pair);
        }
    }

    // Fall back to seed.
    if let Some(seed_str) = loaded.secret_seed.as_deref() {
        if !seed_str.is_empty() {
            // `parse_hex_bytes` now returns `Zeroizing<Vec<u8>>`; the
            // intermediate hex decode is scrubbed on drop.
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

/// Read password from terminal with no echo. Writes the prompt to stderr so
/// that stdout remains a clean JSON channel (`btt wallet create | jq .` works).
/// Backed by `rpassword::prompt_password`, which reads from the controlling
/// TTY when one is available.
pub fn read_password(prompt: &str) -> Result<Zeroizing<String>, BttError> {
    use std::io::Write as _;
    let mut stderr = std::io::stderr();
    let _ = stderr.write_all(prompt.as_bytes());
    let _ = stderr.flush();
    let pw = rpassword::prompt_password("")
        .map_err(|e| BttError::io(format!("failed to read password: {}", e)))?;
    Ok(Zeroizing::new(pw))
}

// ── Tests ─────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::commands::paths::ENV_LOCK;
    use sp_core::Pair as TraitPairAlias;

    // Tests that mutate the config-dir env vars cannot run in parallel
    // because env vars are process-global. `HOME_LOCK` is an alias onto
    // the shared `paths::ENV_LOCK` so we serialize against the resolver
    // tests in `paths::tests` as well.
    static HOME_LOCK: &std::sync::Mutex<()> = &ENV_LOCK;

    /// Pin the btt config directory to `<tmp>` for the duration of the
    /// currently running test. Sets the per-OS env vars that
    /// [`crate::commands::paths::config_dir`] consults so the resolver
    /// returns a path inside `tmp`, and ensures the directory tree exists
    /// so the legacy-fallback branch is never taken.
    ///
    /// Returns the `<tmp>/.../wallets` path — i.e., exactly the parent of
    /// `<wallet_name>` that `wallet_path(name)` will produce.
    ///
    /// Caller must hold `HOME_LOCK`.
    fn seat_home_env(tmp: &std::path::Path) -> PathBuf {
        // Always set HOME (macOS resolver needs it, linux fallback needs
        // it, and some surrounding test code reads it directly).
        std::env::set_var("HOME", tmp.to_str().expect("valid path"));

        // On linux (and BSDs, via the fallback arm), pin
        // XDG_CONFIG_HOME inside tmp so the resolver never looks at the
        // real `$HOME/.config`.
        #[cfg(any(
            target_os = "linux",
            not(any(target_os = "macos", target_os = "windows"))
        ))]
        {
            let xdg = tmp.join("xdg");
            std::env::set_var("XDG_CONFIG_HOME", xdg.to_str().expect("valid path"));
        }

        // On windows, pin APPDATA inside tmp.
        #[cfg(target_os = "windows")]
        {
            let appdata = tmp.join("AppData").join("Roaming");
            std::env::set_var("APPDATA", appdata.to_str().expect("valid path"));
        }

        // Compute what `paths::config_dir()` will now return, and make
        // sure it exists so the legacy-fallback branch (which checks for
        // `$HOME/.bittensor`) is never taken.
        let parent = test_wallets_parent(tmp);
        std::fs::create_dir_all(&parent).expect("create wallets parent");
        parent
    }

    /// Compute the `wallets/` parent dir that `paths::config_dir()` will
    /// resolve to for a given test tmp root, on the host OS.
    fn test_wallets_parent(tmp: &std::path::Path) -> PathBuf {
        #[cfg(target_os = "linux")]
        {
            tmp.join("xdg").join("btt").join("wallets")
        }
        #[cfg(target_os = "macos")]
        {
            tmp.join("Library")
                .join("Application Support")
                .join("btt")
                .join("wallets")
        }
        #[cfg(target_os = "windows")]
        {
            tmp.join("AppData").join("Roaming").join("btt").join("wallets")
        }
        #[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
        {
            tmp.join("xdg").join("btt").join("wallets")
        }
    }

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
    fn only_12_word_supported() {
        assert!(validate_n_words(11).is_err());
        assert!(validate_n_words(12).is_ok());
        // 24-word support deferred with bip39 dep removal; see generate_keypair.
        assert!(validate_n_words(24).is_err());
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
        assert!(
            encrypted.starts_with(b"$NACL"),
            "encrypted blob should start with btwallet magic $NACL"
        );
        assert_ne!(&encrypted[..], plaintext, "ciphertext should differ from plaintext");

        let decrypted = decrypt_key_data(&encrypted, password).expect("decryption should work");
        assert_eq!(decrypted.as_slice(), plaintext, "decrypted should match original");
    }

    #[test]
    fn derive_key_matches_libsodium_reference() {
        // Reference vector computed with pynacl:
        //   nacl.pwhash.argon2i.kdf(
        //     32, b"hello-btcli", NACL_SALT,
        //     opslimit=OPSLIMIT_SENSITIVE, memlimit=MEMLIMIT_SENSITIVE)
        // This test pins the argon2i13 parameters to libsodium's SENSITIVE
        // profile. If it ever fails, the btwallet on-disk format will have
        // silently diverged.
        let key = derive_key(b"hello-btcli").expect("argon2 derive");
        let expected =
            hex::decode("39272631c10c56896024d406eef497421dcb6a6be0f2fb71adb7ae39f42456cd")
                .expect("hex");
        assert_eq!(key.as_slice(), expected.as_slice());
    }

    #[test]
    fn decrypts_btwallet_reference_vector() {
        // Fixed reference blob produced by pynacl (libsodium) using exactly
        // the btwallet format:
        //
        //   import nacl.pwhash.argon2i as a, nacl.secret
        //   salt = NACL_SALT
        //   key  = a.kdf(32, b"correct horse battery staple", salt,
        //                opslimit=a.OPSLIMIT_SENSITIVE,
        //                memlimit=a.MEMLIMIT_SENSITIVE)
        //   box  = nacl.secret.SecretBox(key)
        //   ct   = bytes(box.encrypt(plaintext, nonce=bytes(24)))
        //   blob = b"$NACL" + ct
        //
        // The all-zero nonce is chosen only so the vector is reproducible;
        // production encryption uses random nonces. If this test fails, the
        // on-disk envelope has drifted from btwallet.
        let plaintext_hex =
            "7b226163636f756e744964223a2230786465616462656566222c\
             227373353841646472657373223a223546616b6541646472227d";
        let blob_hex = "244e41434c000000000000000000000000000000000000000000000000\
                        fc80b605e3f8a4e8ac1fe620d424cf239c6806fed7365d1bb2142107c6\
                        fa3ed8f7bbc7af9b1e2c3e67f1cb90e58945e8520b7bb1006532a43e77\
                        75d7c439db6f5fc337df";
        let expected_plain =
            hex::decode(plaintext_hex.replace(|c: char| c.is_whitespace(), "")).expect("hex");
        let blob =
            hex::decode(blob_hex.replace(|c: char| c.is_whitespace(), "")).expect("hex");
        let password = "correct horse battery staple";

        // btwallet -> btt: we must be able to decrypt the external blob.
        let decoded = decrypt_key_data(&blob, password).expect("decrypt external blob");
        assert_eq!(decoded.as_slice(), expected_plain.as_slice());

        // btt -> btt round trip: sanity check shape of our own output.
        let enc = encrypt_key_data(&expected_plain, password).expect("encrypt");
        assert!(enc.starts_with(b"$NACL"));
        assert_eq!(enc.len(), 5 + 24 + expected_plain.len() + 16);
        let dec = decrypt_key_data(&enc, password).expect("decrypt");
        assert_eq!(dec.as_slice(), expected_plain.as_slice());
    }

    #[test]
    #[ignore = "helper for producing hex blobs consumed by external libsodium"]
    fn dump_blob_for_python() {
        let pt = b"btt-to-btwallet-interop-check";
        let enc = encrypt_key_data(pt, "roundtrip-pw").expect("encrypt");
        eprintln!("BTT_ENC_BLOB={}", hex::encode(&enc));
    }

    #[test]
    fn decrypt_rejects_missing_magic() {
        // Without the $NACL prefix, decrypt must refuse.
        let fake = vec![0u8; 100];
        assert!(decrypt_key_data(&fake, "pw").is_err());
    }

    #[cfg(unix)]
    #[test]
    fn create_writes_secure_file_perms() {
        use std::os::unix::fs::PermissionsExt;

        let _guard = HOME_LOCK.lock().expect("home lock");
        let tmp = std::env::temp_dir().join(format!("btt-perm-{}", std::process::id()));
        let wallet_name = "perm-test";

        let original_home = std::env::var("HOME").ok();
        let _ = std::fs::create_dir_all(&tmp);
        let wallets_parent = seat_home_env(&tmp);

        let result = create(wallet_name, "default", 12, "perm-pw", false);

        // Capture paths before cleanup
        let wdir = wallets_parent.join(wallet_name);
        let coldkey = wdir.join("coldkey");
        let hotkey = wdir.join("hotkeys").join("default");

        let coldkey_mode = std::fs::metadata(&coldkey).map(|m| m.permissions().mode() & 0o777);
        let hotkey_mode = std::fs::metadata(&hotkey).map(|m| m.permissions().mode() & 0o777);
        let wdir_mode = std::fs::metadata(&wdir).map(|m| m.permissions().mode() & 0o777);

        // Read first bytes of coldkey to confirm $NACL framing
        let coldkey_bytes = std::fs::read(&coldkey).ok();

        if let Some(h) = original_home {
            std::env::set_var("HOME", &h);
        }
        let _ = std::fs::remove_dir_all(&tmp);

        result.expect("create should work");
        assert_eq!(coldkey_mode.expect("coldkey stat"), 0o600);
        assert_eq!(hotkey_mode.expect("hotkey stat"), 0o600);
        assert_eq!(wdir_mode.expect("wallet dir stat"), 0o700);
        let bytes = coldkey_bytes.expect("coldkey read");
        assert!(
            bytes.starts_with(b"$NACL"),
            "coldkey file should start with $NACL magic"
        );
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

    // ── Load-path zeroization tests (issue #8) ─────────────────────────
    //
    // These assertions are defense-in-depth checks, not end-to-end memory
    // dumps. We verify the types that hold decrypted secret material
    // actually call `.zeroize()` on their backing buffers. The runtime
    // check is necessarily indirect — once a `String` has been dropped
    // the allocator is free to reuse or return the pages — so we invoke
    // `Zeroize::zeroize` manually and inspect the struct afterward.

    #[test]
    fn loaded_key_file_zeroizes_fields() {
        let json = r#"{
            "secretPhrase": "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about",
            "secretSeed": "0x1111111111111111111111111111111111111111111111111111111111111111"
        }"#;

        let mut loaded: LoadedKeyFile =
            serde_json::from_str(json).expect("LoadedKeyFile should deserialize");

        // Sanity: the fields are populated before the scrub.
        assert!(loaded
            .secret_phrase
            .as_deref()
            .expect("secret_phrase deserialized")
            .contains("abandon"));
        assert!(loaded
            .secret_seed
            .as_deref()
            .expect("secret_seed deserialized")
            .starts_with("0x1111"));

        // Manually invoke the scrub and confirm both fields are wiped.
        // `Zeroize for Option<String>` zeros the inner `String` buffer,
        // drops it, and then volatile-writes the `Option` discriminant
        // back to `None`. So after this call both fields are `None`.
        loaded.zeroize();
        assert!(loaded.secret_phrase.is_none());
        assert!(loaded.secret_seed.is_none());
    }

    #[test]
    fn decrypt_key_data_returns_zeroizing_buffer() {
        // Pin the decrypt return type: any refactor that weakens the
        // scrub guarantee (e.g. reverting to `Vec<u8>`) will fail to
        // compile this test.
        fn assert_zeroizing(_: &Zeroizing<Vec<u8>>) {}

        let password = "load-zeroize-test-pw";
        let plaintext = b"{\"secretPhrase\":\"abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about\"}";
        let encrypted = encrypt_key_data(plaintext, password).expect("encrypt");
        let decrypted = decrypt_key_data(&encrypted, password).expect("decrypt");
        assert_zeroizing(&decrypted);
        assert_eq!(decrypted.as_slice(), plaintext.as_slice());
    }

    #[test]
    fn parse_hex_bytes_returns_zeroizing_buffer() {
        // Same story as `decrypt_key_data`: pin the return type so a
        // future refactor cannot silently strip the scrub.
        fn assert_zeroizing(_: &Zeroizing<Vec<u8>>) {}
        let bytes = parse_hex_bytes("0xdeadbeef").expect("parse");
        assert_zeroizing(&bytes);
    }

    #[test]
    fn pair_from_key_json_load_roundtrip() {
        // End-to-end correctness check for the load path: the same
        // mnemonic produced by `generate_keypair` must reconstruct the
        // same public key when routed back through `pair_from_key_json`
        // (which now goes via the zeroizing `LoadedKeyFile`).
        let (original, phrase, seed) = generate_keypair(12).expect("generate");
        let seed_hex = format!("0x{}", hex::encode(seed));
        let json = build_key_json(&original, &phrase, &seed_hex);
        let json_str = serde_json::to_string(&json).expect("serialize");

        // Mnemonic branch.
        let via_phrase = pair_from_key_json(&json_str).expect("recover via phrase");
        assert_eq!(via_phrase.public(), original.public());

        // Seed branch: strip the phrase so the fallback is exercised.
        let seed_only = serde_json::json!({
            "secretPhrase": "",
            "secretSeed": seed_hex,
        });
        let via_seed =
            pair_from_key_json(&seed_only.to_string()).expect("recover via seed");
        assert_eq!(via_seed.public(), original.public());
    }

    #[test]
    fn load_coldkey_roundtrip_via_create() {
        // The highest-value load-path test: drive the full pipeline
        // (generate → write → decrypt → load → sign) and confirm the
        // ss58 matches the create-time ss58. This exercises
        // `decrypt_key_data`, `load_coldkey`, and `pair_from_key_json`
        // on the zeroized code path.
        let _guard = HOME_LOCK.lock().expect("home lock");
        let tmp = std::env::temp_dir().join(format!("btt-load-zeroize-{}", std::process::id()));
        let wallet_name = "load-zero-test";

        let original_home = std::env::var("HOME").ok();
        std::fs::create_dir_all(&tmp).expect("create tmp root");
        let _wallets_parent = seat_home_env(&tmp);

        let password = "load-zero-pw";
        let cr = create(wallet_name, "default", 12, password, false).expect("create");

        // load_coldkey is private; invoke it indirectly via `sign`.
        let sr =
            sign(wallet_name, "default", "hi", false, Some(password)).expect("sign coldkey");

        if let Some(h) = original_home {
            std::env::set_var("HOME", &h);
        }
        let _ = std::fs::remove_dir_all(&tmp);

        assert_eq!(
            sr.ss58_address, cr.coldkey_ss58,
            "load_coldkey must reproduce the create-time ss58"
        );
    }

    #[test]
    fn parse_hex_with_prefix() {
        let bytes = parse_hex_bytes("0xdeadbeef").expect("should parse");
        assert_eq!(bytes.as_slice(), [0xde, 0xad, 0xbe, 0xef].as_slice());
    }

    #[test]
    fn parse_hex_without_prefix() {
        let bytes = parse_hex_bytes("deadbeef").expect("should parse");
        assert_eq!(bytes.as_slice(), [0xde, 0xad, 0xbe, 0xef].as_slice());
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
        let _guard = HOME_LOCK.lock().expect("home lock");
        // Use a temp directory to avoid polluting the real config dir.
        let tmp = std::env::temp_dir().join(format!("btt-test-{}", std::process::id()));
        let wallet_name = "test-wallet";
        let _wallet_dir = tmp.join(wallet_name);

        // Override the config-dir env vars for this test.
        let original_home = std::env::var("HOME").ok();
        std::fs::create_dir_all(&tmp).expect("create tmp root");
        let _wallets_parent = seat_home_env(&tmp);

        let password = "test-password";
        let result = create(wallet_name, "default", 12, password, false);

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
        let _guard = HOME_LOCK.lock().expect("home lock");
        let tmp = std::env::temp_dir().join(format!("btt-test-sign-{}", std::process::id()));
        let wallet_name = "sign-test";

        let original_home = std::env::var("HOME").ok();
        std::fs::create_dir_all(&tmp).expect("create tmp root");
        let _wallets_parent = seat_home_env(&tmp);

        let password = "sign-test-pw";
        let cr = create(wallet_name, "default", 12, password, false).expect("create should work");

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

    // ── --force / overwrite guard tests ───────────────────────────────
    //
    // These tests share the same shape as the other HOME-mutating tests:
    // take HOME_LOCK, point HOME at a fresh temp directory, exercise the
    // command, then restore HOME and blow the temp directory away. They
    // cover the three interesting points of the guard_overwrite matrix
    // for each subcommand:
    //
    //   1. no flag + no existing file → success (baseline)
    //   2. no flag + existing file    → error (issue #7 root cause)
    //   3. --force  + existing file   → success with a new ss58
    //
    // The fourth point (--force + no existing file) is implicitly
    // covered by case 3 — guard_overwrite short-circuits when the file
    // is absent regardless of the force flag.

    /// Helper: seat the config-dir env vars at a fresh temp dir and
    /// return the temp path. The caller is responsible for restoring
    /// HOME and removing the dir.
    fn seat_home(tag: &str) -> (PathBuf, Option<String>) {
        let tmp = std::env::temp_dir().join(format!(
            "btt-force-{}-{}-{}",
            tag,
            std::process::id(),
            // Distinct-per-test nonce: we never want two tests to alias
            // each other's wallet dir if HOME_LOCK is ever relaxed.
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_nanos())
                .unwrap_or(0)
        ));
        let original_home = std::env::var("HOME").ok();
        std::fs::create_dir_all(&tmp).expect("create tmp root");
        let _ = seat_home_env(&tmp);
        (tmp, original_home)
    }

    fn restore_home(tmp: PathBuf, original: Option<String>) {
        if let Some(h) = original {
            std::env::set_var("HOME", &h);
        }
        let _ = std::fs::remove_dir_all(&tmp);
    }

    /// Pull the error out of a `Result<T, BttError>` without requiring
    /// `T: Debug` (which our public result types deliberately do not
    /// implement — they carry secret_phrase/secret_seed). Panics with a
    /// custom message if the result is `Ok`.
    fn unwrap_err<T>(r: Result<T, BttError>, ctx: &str) -> BttError {
        match r {
            Ok(_) => panic!("{ctx}: expected error, got Ok"),
            Err(e) => e,
        }
    }

    #[test]
    fn new_coldkey_no_flag_no_file_succeeds() {
        let _guard = HOME_LOCK.lock().expect("home lock");
        let (tmp, original) = seat_home("nc-ok");

        let result = new_coldkey("w", 12, "pw", false);

        restore_home(tmp, original);
        let result = result.expect("no existing file → should succeed");
        assert!(result.ss58_address.starts_with('5'));
    }

    #[test]
    fn new_coldkey_no_flag_existing_file_errors() {
        let _guard = HOME_LOCK.lock().expect("home lock");
        let (tmp, original) = seat_home("nc-refuse");

        let first = new_coldkey("w", 12, "pw", false).expect("first create");
        // Second call without --force must refuse and must not touch the
        // existing file. We verify the error is an invalid_input naming
        // the target path, then re-read the wallet dir and confirm the
        // original ss58 is untouched.
        let second = new_coldkey("w", 12, "pw", false);

        let wdir = test_wallets_parent(&tmp).join("w");
        let coldkey_exists = wdir.join("coldkey").exists();
        let pub_after = std::fs::read_to_string(wdir.join("coldkeypub.txt")).ok();

        restore_home(tmp, original);
        assert!(coldkey_exists, "refusal path must preserve existing coldkey");
        let err = unwrap_err(second, "existing file + no force");
        let msg = format!("{err:?}");
        assert!(
            msg.contains("coldkey"),
            "error message should mention coldkey, got: {msg}"
        );
        assert!(
            msg.contains("--force"),
            "error message should mention --force, got: {msg}"
        );
        // coldkeypub.txt should still point at the first key (its JSON
        // content will contain the first ss58).
        let pub_after = pub_after.expect("coldkeypub.txt preserved");
        assert!(
            pub_after.contains(&first.ss58_address),
            "pubkey file should still contain the original ss58"
        );
    }

    #[test]
    fn new_coldkey_force_replaces_existing() {
        let _guard = HOME_LOCK.lock().expect("home lock");
        let (tmp, original) = seat_home("nc-force");

        let first = new_coldkey("w", 12, "pw", false).expect("first create");
        let second = new_coldkey("w", 12, "pw", true);

        restore_home(tmp, original);
        let second = second.expect("--force + existing file → should succeed");
        assert_ne!(
            first.ss58_address, second.ss58_address,
            "force must yield a fresh keypair"
        );
        assert!(second.ss58_address.starts_with('5'));
    }

    #[test]
    fn new_hotkey_no_flag_no_file_succeeds() {
        let _guard = HOME_LOCK.lock().expect("home lock");
        let (tmp, original) = seat_home("nh-ok");

        // new_hotkey needs the wallet dir to exist, so bootstrap with a
        // coldkey first.
        let _cr = new_coldkey("w", 12, "pw", false).expect("bootstrap coldkey");
        let result = new_hotkey("w", "default", 12, false);

        restore_home(tmp, original);
        let result = result.expect("no existing hotkey → should succeed");
        assert!(result.ss58_address.starts_with('5'));
    }

    #[test]
    fn new_hotkey_no_flag_existing_file_errors() {
        let _guard = HOME_LOCK.lock().expect("home lock");
        let (tmp, original) = seat_home("nh-refuse");

        let _cr = new_coldkey("w", 12, "pw", false).expect("bootstrap coldkey");
        let first = new_hotkey("w", "default", 12, false).expect("first hotkey");
        let second = new_hotkey("w", "default", 12, false);

        let wdir = test_wallets_parent(&tmp).join("w");
        let hotkey_file = wdir.join("hotkeys").join("default");
        let preserved = std::fs::read_to_string(&hotkey_file).ok();

        restore_home(tmp, original);
        let err = unwrap_err(second, "existing hotkey + no force");
        let msg = format!("{err:?}");
        assert!(msg.contains("hotkey"), "error should mention hotkey: {msg}");
        assert!(msg.contains("--force"), "error should mention --force: {msg}");
        // The on-disk hotkey JSON must still carry the original ss58.
        let preserved = preserved.expect("hotkey file preserved");
        assert!(
            preserved.contains(&first.ss58_address),
            "refusal path must preserve the original hotkey"
        );
    }

    #[test]
    fn new_hotkey_force_replaces_existing() {
        let _guard = HOME_LOCK.lock().expect("home lock");
        let (tmp, original) = seat_home("nh-force");

        let _cr = new_coldkey("w", 12, "pw", false).expect("bootstrap coldkey");
        let first = new_hotkey("w", "default", 12, false).expect("first hotkey");
        let second = new_hotkey("w", "default", 12, true);

        restore_home(tmp, original);
        let second = second.expect("--force + existing hotkey → should succeed");
        assert_ne!(
            first.ss58_address, second.ss58_address,
            "force must yield a fresh hotkey"
        );
    }

    #[test]
    fn regen_coldkey_no_flag_existing_file_errors() {
        let _guard = HOME_LOCK.lock().expect("home lock");
        let (tmp, original) = seat_home("rc-refuse");

        let first = new_coldkey("w", 12, "pw", false).expect("first create");
        // Use the freshly generated mnemonic to drive regen; we don't care
        // about the identity it produces, only that regen refuses.
        let phrase = first.mnemonic.clone();
        let second = regen_coldkey("w", Some(&phrase), None, "pw", false);

        restore_home(tmp, original);
        let err = unwrap_err(second, "existing coldkey + no force (regen)");
        let msg = format!("{err:?}");
        assert!(msg.contains("coldkey"), "error should mention coldkey: {msg}");
        assert!(msg.contains("--force"), "error should mention --force: {msg}");
    }

    #[test]
    fn regen_coldkey_force_replaces_existing() {
        let _guard = HOME_LOCK.lock().expect("home lock");
        let (tmp, original) = seat_home("rc-force");

        let first = new_coldkey("w", 12, "pw", false).expect("first create");
        // Regen from the *same* mnemonic under --force and assert the
        // operation succeeds and reproduces the same ss58 (mnemonic is
        // deterministic). This is also a lightweight sanity check that
        // the force path is not accidentally generating a different key.
        let regen = regen_coldkey("w", Some(&first.mnemonic), None, "pw", true);

        restore_home(tmp, original);
        let regen = regen.expect("--force + existing coldkey → should succeed");
        assert_eq!(
            regen.ss58_address, first.ss58_address,
            "regen from same mnemonic should reproduce the ss58"
        );
    }

    #[test]
    fn regen_coldkey_no_flag_no_file_succeeds() {
        let _guard = HOME_LOCK.lock().expect("home lock");
        let (tmp, original) = seat_home("rc-ok");

        // Produce a mnemonic outside the HOME-scoped wallet dir so we can
        // drive regen without having first written a coldkey.
        let (_pair, phrase, _seed) = generate_keypair(12).expect("gen");

        let result = regen_coldkey("w", Some(&phrase), None, "pw", false);

        restore_home(tmp, original);
        let _result = result.expect("no existing file + no force → should succeed");
    }

    #[test]
    fn regen_hotkey_no_flag_existing_file_errors() {
        let _guard = HOME_LOCK.lock().expect("home lock");
        let (tmp, original) = seat_home("rh-refuse");

        let _cr = new_coldkey("w", 12, "pw", false).expect("bootstrap coldkey");
        let first = new_hotkey("w", "default", 12, false).expect("first hotkey");
        let second = regen_hotkey("w", "default", Some(&first.mnemonic), None, false);

        restore_home(tmp, original);
        let err = unwrap_err(second, "existing hotkey + no force (regen)");
        let msg = format!("{err:?}");
        assert!(msg.contains("hotkey"), "error should mention hotkey: {msg}");
        assert!(msg.contains("--force"), "error should mention --force: {msg}");
    }

    #[test]
    fn regen_hotkey_force_replaces_existing() {
        let _guard = HOME_LOCK.lock().expect("home lock");
        let (tmp, original) = seat_home("rh-force");

        let _cr = new_coldkey("w", 12, "pw", false).expect("bootstrap coldkey");
        let first = new_hotkey("w", "default", 12, false).expect("first hotkey");
        let regen = regen_hotkey("w", "default", Some(&first.mnemonic), None, true);

        restore_home(tmp, original);
        let regen = regen.expect("--force + existing hotkey → should succeed");
        assert_eq!(
            regen.ss58_address, first.ss58_address,
            "regen from same mnemonic should reproduce the hotkey ss58"
        );
    }

    #[test]
    fn regen_hotkey_no_flag_no_file_succeeds() {
        let _guard = HOME_LOCK.lock().expect("home lock");
        let (tmp, original) = seat_home("rh-ok");

        let _cr = new_coldkey("w", 12, "pw", false).expect("bootstrap coldkey");
        // Bootstrap wallet dir exists via new_coldkey; no hotkey yet.
        let (_pair, phrase, _seed) = generate_keypair(12).expect("gen");
        let result = regen_hotkey("w", "default", Some(&phrase), None, false);

        restore_home(tmp, original);
        let _result = result.expect("no existing hotkey → should succeed");
    }

    // ── wallet create --force / overwrite guard tests (issue #19) ─────
    //
    // Before this guard, `wallet create` silently destroyed an existing
    // wallet at the target path because `write_secure_file` unlinks
    // before re-creating. These three tests cover the same matrix as the
    // single-key guards above, plus a byte-for-byte preservation check
    // on the refusal path — a user who mis-types a wallet name must not
    // lose key material.

    #[test]
    fn wallet_create_no_flag_no_file_succeeds() {
        let _guard = HOME_LOCK.lock().expect("home lock");
        let (tmp, original) = seat_home("wc-ok");

        let result = create("w", "default", 12, "pw", false);

        restore_home(tmp, original);
        let result = result.expect("no existing wallet → should succeed");
        assert!(result.coldkey_ss58.starts_with('5'));
        assert!(result.hotkey_ss58.starts_with('5'));
    }

    #[test]
    fn wallet_create_no_flag_existing_wallet_errors_and_preserves_bytes() {
        let _guard = HOME_LOCK.lock().expect("home lock");
        let (tmp, original) = seat_home("wc-refuse");

        let first = create("w", "default", 12, "pw", false).expect("first create");

        // Snapshot the on-disk wallet files BEFORE the second call so we
        // can prove byte-for-byte preservation if the guard fires.
        let wdir = test_wallets_parent(&tmp).join("w");
        let coldkey_path = wdir.join("coldkey");
        let hotkey_path = wdir.join("hotkeys").join("default");
        let pub_path = wdir.join("coldkeypub.txt");
        let coldkey_before = std::fs::read(&coldkey_path).expect("read coldkey");
        let hotkey_before = std::fs::read(&hotkey_path).expect("read hotkey");
        let pub_before = std::fs::read(&pub_path).expect("read pub");

        // Second call without --force must refuse.
        let second = create("w", "default", 12, "pw", false);

        // Re-read the files and compare byte-for-byte.
        let coldkey_after = std::fs::read(&coldkey_path).expect("re-read coldkey");
        let hotkey_after = std::fs::read(&hotkey_path).expect("re-read hotkey");
        let pub_after = std::fs::read(&pub_path).expect("re-read pub");

        restore_home(tmp, original);
        let err = unwrap_err(second, "existing wallet + no force");
        let msg = format!("{err:?}");
        assert!(
            msg.contains("refusing to overwrite existing wallet"),
            "error should name the refusal, got: {msg}"
        );
        assert!(
            msg.contains("'w'"),
            "error should quote the wallet name, got: {msg}"
        );
        assert!(
            msg.contains("coldkey"),
            "error should name the coldkey file, got: {msg}"
        );
        assert!(
            msg.contains("--force"),
            "error should mention --force, got: {msg}"
        );
        assert!(
            msg.contains("IRREVERSIBLE"),
            "error should warn about irreversibility, got: {msg}"
        );
        // Byte-for-byte preservation: the refusal path must not have
        // modified the on-disk wallet in any way.
        assert_eq!(
            coldkey_before, coldkey_after,
            "coldkey must be preserved byte-for-byte across refusal"
        );
        assert_eq!(
            hotkey_before, hotkey_after,
            "hotkey must be preserved byte-for-byte across refusal"
        );
        assert_eq!(
            pub_before, pub_after,
            "coldkeypub.txt must be preserved byte-for-byte across refusal"
        );
        // And the original ss58 must still be recoverable from the
        // preserved pub file.
        let pub_str = String::from_utf8(pub_after).expect("utf8 pub");
        assert!(
            pub_str.contains(&first.coldkey_ss58),
            "preserved coldkeypub must still carry the original ss58"
        );
    }

    #[test]
    fn wallet_create_force_replaces_existing() {
        let _guard = HOME_LOCK.lock().expect("home lock");
        let (tmp, original) = seat_home("wc-force");

        let first = create("w", "default", 12, "pw", false).expect("first create");
        let second = create("w", "default", 12, "pw", true);

        restore_home(tmp, original);
        let second = second.expect("--force + existing wallet → should succeed");
        assert_ne!(
            first.coldkey_ss58, second.coldkey_ss58,
            "force must yield a fresh coldkey"
        );
        assert_ne!(
            first.hotkey_ss58, second.hotkey_ss58,
            "force must yield a fresh hotkey"
        );
        assert_ne!(
            first.mnemonic, second.mnemonic,
            "force must yield a fresh mnemonic"
        );
        assert!(second.coldkey_ss58.starts_with('5'));
        assert!(second.hotkey_ss58.starts_with('5'));
    }

    #[test]
    fn wallet_create_no_flag_existing_hotkey_only_errors() {
        // Edge case: if only the hotkey file exists (e.g. a partial
        // wallet from an aborted new-hotkey run, or user-side tampering)
        // the guard must still fire. This documents that `wallet create`
        // refuses on ANY pre-existing key file, not just a coldkey.
        let _guard = HOME_LOCK.lock().expect("home lock");
        let (tmp, original) = seat_home("wc-hotonly");

        // Bootstrap: make a wallet dir with only a hotkey, no coldkey.
        let _cr = new_coldkey("w", 12, "pw", false).expect("bootstrap coldkey");
        let _hk = new_hotkey("w", "default", 12, false).expect("bootstrap hotkey");
        // Delete the coldkey so only the hotkey remains.
        let wdir = test_wallets_parent(&tmp).join("w");
        std::fs::remove_file(wdir.join("coldkey")).expect("rm coldkey");
        std::fs::remove_file(wdir.join("coldkeypub.txt")).expect("rm coldkeypub");

        let second = create("w", "default", 12, "pw", false);

        restore_home(tmp, original);
        let err = unwrap_err(second, "existing hotkey only + no force");
        let msg = format!("{err:?}");
        assert!(
            msg.contains("hotkey"),
            "error should name the hotkey file, got: {msg}"
        );
        assert!(
            msg.contains("--force"),
            "error should mention --force, got: {msg}"
        );
    }

    #[test]
    fn regen_coldkey_from_mnemonic() {
        let _guard = HOME_LOCK.lock().expect("home lock");
        let tmp = std::env::temp_dir().join(format!("btt-test-regen-{}", std::process::id()));
        let wallet_name = "regen-test";

        let original_home = std::env::var("HOME").ok();
        std::fs::create_dir_all(&tmp).expect("create tmp root");
        let _wallets_parent = seat_home_env(&tmp);

        let password = "regen-pw";
        let cr = create(wallet_name, "default", 12, password, false).expect("create should work");

        // Regenerate the coldkey from the mnemonic. The wallet dir already
        // holds a `coldkey` file from `create` above, so we must pass
        // force=true or the guard would (correctly) refuse.
        let regen = regen_coldkey(wallet_name, Some(&cr.mnemonic), None, password, true)
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
