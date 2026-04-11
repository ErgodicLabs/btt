use serde::Serialize;
use subxt::dynamic::{At, Value};

use crate::error::BttError;
use crate::rpc;

#[derive(Serialize)]
pub struct ChainInfo {
    pub chain: String,
    pub runtime_version: u32,
    pub transaction_version: u32,
    pub block_number: u64,
}

#[derive(Serialize)]
pub struct BalanceInfo {
    pub address: String,
    pub free: String,
    pub reserved: String,
}

/// Fetch chain info: chain name, runtime version, current block number.
pub async fn info(endpoint: &str) -> Result<ChainInfo, BttError> {
    let api = rpc::connect(endpoint).await?;
    let legacy = rpc::legacy_rpc(endpoint).await?;

    // Get chain name via legacy RPC
    let chain = legacy
        .system_chain()
        .await
        .map_err(|e| BttError::query(format!("failed to get chain name: {}", e)))?;

    // Runtime version from the client
    let runtime_version = api.runtime_version();
    let spec_version = runtime_version.spec_version;
    let transaction_version = runtime_version.transaction_version;
    // spec_name not directly available on subxt RuntimeVersion; use chain name
    // Current block number
    let block = api
        .blocks()
        .at_latest()
        .await
        .map_err(|e| BttError::query(format!("failed to fetch latest block: {}", e)))?;
    let block_number: u64 = block.number().into();

    Ok(ChainInfo {
        chain,
        runtime_version: spec_version,
        transaction_version,
        block_number,
    })
}

/// Query free balance for an SS58 address using the dynamic API.
pub async fn balance(endpoint: &str, address: &str) -> Result<BalanceInfo, BttError> {
    let api = rpc::connect(endpoint).await?;

    // Decode the SS58 address to an AccountId32
    let account_id = parse_ss58(address)?;

    // Build a dynamic storage query for System.Account
    let storage_query = subxt::dynamic::storage(
        "System",
        "Account",
        vec![Value::from_bytes(account_id)],
    );

    let result = api
        .storage()
        .at_latest()
        .await
        .map_err(|e| BttError::query(format!("failed to get storage: {}", e)))?
        .fetch(&storage_query)
        .await
        .map_err(|e| BttError::query(format!("failed to fetch account info: {}", e)))?;

    match result {
        Some(value) => {
            let decoded = value
                .to_value()
                .map_err(|e| BttError::parse(format!("failed to decode account info: {}", e)))?;

            let free = extract_balance_field(&decoded, "data", "free");
            let reserved = extract_balance_field(&decoded, "data", "reserved");

            Ok(BalanceInfo {
                address: address.to_string(),
                free,
                reserved,
            })
        }
        None => {
            // Account not found on chain — zero balances
            Ok(BalanceInfo {
                address: address.to_string(),
                free: "0".to_string(),
                reserved: "0".to_string(),
            })
        }
    }
}

/// Parse an SS58-encoded address into a 32-byte account ID.
fn parse_ss58(address: &str) -> Result<Vec<u8>, BttError> {
    let decoded = bs58_decode(address)
        .map_err(|e| BttError::invalid_address(format!("invalid SS58 address: {}", e)))?;

    // SS58 can have 1 or 2 prefix bytes
    // Simple prefix: < 64 => 1 byte prefix
    // Two-byte prefix: >= 64
    if decoded.len() < 35 {
        return Err(BttError::invalid_address("SS58 address too short"));
    }

    let prefix_len = if decoded[0] < 64 { 1 } else { 2 };

    if decoded.len() < prefix_len + 32 + 2 {
        return Err(BttError::invalid_address("SS58 address has invalid length"));
    }

    let account_id = decoded[prefix_len..prefix_len + 32].to_vec();
    Ok(account_id)
}

/// Minimal base58 decoder (Bitcoin alphabet).
fn bs58_decode(input: &str) -> Result<Vec<u8>, String> {
    const ALPHABET: &[u8] = b"123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

    let mut result: Vec<u8> = vec![0u8; input.len()];
    let mut length = 0;

    for &c in input.as_bytes() {
        let mut carry = ALPHABET
            .iter()
            .position(|&a| a == c)
            .ok_or_else(|| format!("invalid base58 character: {}", c as char))?;

        for byte in result[..length].iter_mut().rev() {
            carry += 58 * (*byte as usize);
            *byte = (carry % 256) as u8;
            carry /= 256;
        }

        while carry > 0 {
            length += 1;
            if length > result.len() {
                result.insert(0, 0);
                length = result.len();
            }
            let idx = result.len() - length;
            result[idx] = (carry % 256) as u8;
            carry /= 256;
        }
    }

    // Count leading '1's (base58 zero)
    let leading_zeros = input.bytes().take_while(|&b| b == b'1').count();

    let start = result.len() - length;
    let mut out = vec![0u8; leading_zeros];
    out.extend_from_slice(&result[start..]);
    Ok(out)
}

/// Extract a balance field from a decoded dynamic Value.
/// The System.Account storage returns a struct with a "data" field containing
/// an AccountData struct with "free", "reserved", etc.
fn extract_balance_field(
    value: &Value<u32>,
    outer_field: &str,
    inner_field: &str,
) -> String {
    // Navigate: value -> outer_field (e.g., "data") -> inner_field (e.g., "free")
    if let Some(outer) = value.at(outer_field) {
        let outer_val: &Value<u32> = outer;
        if let Some(inner) = outer_val.at(inner_field) {
            let inner_val: &Value<u32> = inner;
            // The balance is typically a u128 encoded as a Value::U128
            if let Some(n) = inner_val.as_u128() {
                return n.to_string();
            }
        }
    }
    "0".to_string()
}
