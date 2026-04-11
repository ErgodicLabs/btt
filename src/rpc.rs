use std::time::Duration;

use subxt::backend::rpc::RpcClient;
use subxt::backend::legacy::LegacyRpcMethods;
use subxt::{OnlineClient, PolkadotConfig};

use crate::error::BttError;

/// Default Bittensor Finney endpoint.
pub const DEFAULT_ENDPOINT: &str = "wss://entrypoint-finney.opentensor.ai:443";

/// Endpoint for testnet.
pub const TEST_ENDPOINT: &str = "wss://test.finney.opentensor.ai:443";

/// Endpoint for local node.
pub const LOCAL_ENDPOINT: &str = "ws://127.0.0.1:9944";

/// Connection timeout duration.
const CONNECT_TIMEOUT: Duration = Duration::from_secs(30);

/// RPC call timeout duration.
pub const RPC_TIMEOUT: Duration = Duration::from_secs(30);

/// Resolve a URL from explicit --url or --network shorthand.
/// Returns an error for unrecognized network names or invalid URL schemes.
pub fn resolve_endpoint(url: Option<&str>, network: Option<&str>) -> Result<String, BttError> {
    if let Some(u) = url {
        validate_url(u)?;
        return Ok(u.to_string());
    }
    match network {
        Some("finney") => Ok(DEFAULT_ENDPOINT.to_string()),
        Some("test") => Ok(TEST_ENDPOINT.to_string()),
        Some("local") => Ok(LOCAL_ENDPOINT.to_string()),
        Some(other) => Err(BttError::connection(format!(
            "unrecognized network '{}'. valid options: finney, test, local",
            other
        ))),
        None => Ok(DEFAULT_ENDPOINT.to_string()),
    }
}

/// Validate that a URL uses ws:// or wss:// scheme.
fn validate_url(url: &str) -> Result<(), BttError> {
    if !url.starts_with("ws://") && !url.starts_with("wss://") {
        return Err(BttError::connection(
            "endpoint URL must use ws:// or wss:// scheme",
        ));
    }
    Ok(())
}

/// Connect to a substrate node and return an OnlineClient.
/// Applies a connection timeout.
pub async fn connect(endpoint: &str) -> Result<OnlineClient<PolkadotConfig>, BttError> {
    tokio::time::timeout(
        CONNECT_TIMEOUT,
        OnlineClient::<PolkadotConfig>::from_url(endpoint),
    )
    .await
    .map_err(|_| BttError::connection(format!("connection to {} timed out after {}s", endpoint, CONNECT_TIMEOUT.as_secs())))?
    .map_err(|e| BttError::connection(format!("failed to connect to {}: {}", endpoint, e)))
}

/// Get legacy RPC methods for lower-level queries.
/// Applies a connection timeout.
pub async fn legacy_rpc(endpoint: &str) -> Result<LegacyRpcMethods<PolkadotConfig>, BttError> {
    let rpc_client = tokio::time::timeout(
        CONNECT_TIMEOUT,
        RpcClient::from_url(endpoint),
    )
    .await
    .map_err(|_| BttError::connection(format!("connection to {} timed out after {}s", endpoint, CONNECT_TIMEOUT.as_secs())))?
    .map_err(|e| BttError::connection(format!("failed to connect to {}: {}", endpoint, e)))?;
    Ok(LegacyRpcMethods::new(rpc_client))
}
