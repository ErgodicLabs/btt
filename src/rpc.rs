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

/// Resolve a URL from explicit --url or --network shorthand.
pub fn resolve_endpoint(url: Option<&str>, network: Option<&str>) -> String {
    if let Some(u) = url {
        return u.to_string();
    }
    match network {
        Some("test") => TEST_ENDPOINT.to_string(),
        Some("local") => LOCAL_ENDPOINT.to_string(),
        _ => DEFAULT_ENDPOINT.to_string(),
    }
}

/// Connect to a substrate node and return an OnlineClient.
pub async fn connect(endpoint: &str) -> Result<OnlineClient<PolkadotConfig>, BttError> {
    OnlineClient::<PolkadotConfig>::from_url(endpoint)
        .await
        .map_err(|e| BttError::connection(format!("failed to connect to {}: {}", endpoint, e)))
}

/// Get legacy RPC methods for lower-level queries.
pub async fn legacy_rpc(endpoint: &str) -> Result<LegacyRpcMethods<PolkadotConfig>, BttError> {
    let rpc_client = RpcClient::from_url(endpoint)
        .await
        .map_err(|e| BttError::connection(format!("failed to connect to {}: {}", endpoint, e)))?;
    Ok(LegacyRpcMethods::new(rpc_client))
}
