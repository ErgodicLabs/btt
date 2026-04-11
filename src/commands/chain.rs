use std::time::Duration;

use serde::Serialize;
use sp_core::crypto::{AccountId32, Ss58Codec};
use subxt::dynamic::{At, Value};

use crate::error::BttError;
use crate::rpc;

/// Timeout for individual RPC operations.
const RPC_TIMEOUT: Duration = rpc::RPC_TIMEOUT;

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
    let chain = tokio::time::timeout(RPC_TIMEOUT, legacy.system_chain())
        .await
        .map_err(|_| BttError::query("system_chain RPC call timed out"))?
        .map_err(|e| BttError::query(format!("failed to get chain name: {}", e)))?;

    // Runtime version from the client
    let runtime_version = api.runtime_version();
    let spec_version = runtime_version.spec_version;
    let transaction_version = runtime_version.transaction_version;

    // Current block number
    let block = tokio::time::timeout(RPC_TIMEOUT, api.blocks().at_latest())
        .await
        .map_err(|_| BttError::query("fetch latest block timed out"))?
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

    // Decode and validate the SS58 address, then re-encode to canonical form
    let (account_id_bytes, canonical_address) = parse_ss58(address)?;

    // Build a dynamic storage query for System.Account
    let storage_query = subxt::dynamic::storage(
        "System",
        "Account",
        vec![Value::from_bytes(account_id_bytes)],
    );

    let storage = tokio::time::timeout(
        RPC_TIMEOUT,
        api.storage().at_latest(),
    )
    .await
    .map_err(|_| BttError::query("storage query timed out"))?
    .map_err(|e| BttError::query(format!("failed to get storage: {}", e)))?;

    let result = tokio::time::timeout(
        RPC_TIMEOUT,
        storage.fetch(&storage_query),
    )
    .await
    .map_err(|_| BttError::query("account info fetch timed out"))?
    .map_err(|e| BttError::query(format!("failed to fetch account info: {}", e)))?;

    match result {
        Some(value) => {
            let decoded = value
                .to_value()
                .map_err(|e| BttError::parse(format!("failed to decode account info: {}", e)))?;

            let free = extract_balance_field(&decoded, "data", "free")?;
            let reserved = extract_balance_field(&decoded, "data", "reserved")?;

            Ok(BalanceInfo {
                address: canonical_address,
                free,
                reserved,
            })
        }
        None => {
            // Account not found on chain -- zero balances
            Ok(BalanceInfo {
                address: canonical_address,
                free: "0".to_string(),
                reserved: "0".to_string(),
            })
        }
    }
}

/// Parse an SS58-encoded address into a 32-byte account ID and canonical SS58 string.
/// Uses sp-core for proper checksum verification.
fn parse_ss58(address: &str) -> Result<(Vec<u8>, String), BttError> {
    let account_id = AccountId32::from_ss58check(address)
        .map_err(|e| BttError::invalid_address(format!("invalid SS58 address: {:?}", e)))?;

    let canonical = account_id.to_ss58check();
    let bytes: &[u8] = account_id.as_ref();
    let bytes = bytes.to_vec();

    Ok((bytes, canonical))
}

/// Extract a balance field from a decoded dynamic Value.
/// Returns an error if the field cannot be found or parsed.
fn extract_balance_field(
    value: &Value<u32>,
    outer_field: &str,
    inner_field: &str,
) -> Result<String, BttError> {
    let outer = value.at(outer_field).ok_or_else(|| {
        BttError::parse(format!(
            "missing '{}' field in account data",
            outer_field
        ))
    })?;

    let inner: &Value<u32> = outer;
    let inner_val = inner.at(inner_field).ok_or_else(|| {
        BttError::parse(format!(
            "missing '{}.{}' field in account data",
            outer_field, inner_field
        ))
    })?;

    let inner_ref: &Value<u32> = inner_val;
    inner_ref.as_u128().map(|n| n.to_string()).ok_or_else(|| {
        BttError::parse(format!(
            "'{}.{}' is not a valid u128 balance",
            outer_field, inner_field
        ))
    })
}
