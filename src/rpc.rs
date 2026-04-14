use std::time::Duration;

use subxt::config::RpcConfigFor;
use subxt::rpcs::{LegacyRpcMethods, RpcClient};
use subxt::{OnlineClient, PolkadotConfig};

/// Legacy RPC methods bound to the `PolkadotConfig` chain types.
///
/// subxt 0.50 separated [`subxt::Config`] (used by online-client types) from
/// [`subxt_rpcs::RpcConfig`] (used by the legacy RPC helpers). The
/// [`RpcConfigFor<T>`] phantom type bridges the two so we can still talk to
/// a `PolkadotConfig`-flavoured chain via the legacy method set.
pub type LegacyRpc = LegacyRpcMethods<RpcConfigFor<PolkadotConfig>>;

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
pub fn validate_url(url: &str) -> Result<(), BttError> {
    if !url.starts_with("ws://") && !url.starts_with("wss://") {
        return Err(BttError::connection(
            "endpoint URL must use ws:// or wss:// scheme",
        ));
    }
    Ok(())
}

/// Connect to a substrate node and return an OnlineClient.
/// Applies a connection timeout.
///
/// Uses [`OnlineClient::from_insecure_url`] because the `local` network
/// shorthand points at a plain `ws://127.0.0.1:9944`; subxt 0.50's
/// `from_url` rejects non-TLS endpoints outright. Scheme validation for
/// explicit user input is enforced by [`validate_url`] above.
pub async fn connect(endpoint: &str) -> Result<OnlineClient<PolkadotConfig>, BttError> {
    tokio::time::timeout(
        CONNECT_TIMEOUT,
        OnlineClient::<PolkadotConfig>::from_insecure_url(endpoint),
    )
    .await
    .map_err(|_| BttError::connection(format!("connection to {} timed out after {}s", endpoint, CONNECT_TIMEOUT.as_secs())))?
    .map_err(|e| BttError::connection(format!("failed to connect to {}: {}", endpoint, e)))
}

/// Connect once and return both an OnlineClient and LegacyRpcMethods sharing
/// the same underlying WebSocket transport.
pub async fn connect_full(
    endpoint: &str,
) -> Result<(OnlineClient<PolkadotConfig>, LegacyRpc), BttError> {
    // See note on `connect`: we accept `ws://` for the `local` shorthand
    // and validate scheme ourselves in `validate_url`.
    let rpc_client = tokio::time::timeout(
        CONNECT_TIMEOUT,
        RpcClient::from_insecure_url(endpoint),
    )
    .await
    .map_err(|_| BttError::connection(format!("connection to {} timed out after {}s", endpoint, CONNECT_TIMEOUT.as_secs())))?
    .map_err(|e| BttError::connection(format!("failed to connect to {}: {}", endpoint, e)))?;

    let legacy = LegacyRpcMethods::new(rpc_client.clone());
    let api = OnlineClient::<PolkadotConfig>::from_rpc_client(rpc_client)
        .await
        .map_err(|e| BttError::connection(format!("failed to initialize client from {}: {}", endpoint, e)))?;

    Ok((api, legacy))
}

#[cfg(test)]
mod tests {
    use super::*;

    // -- resolve_endpoint tests --

    #[test]
    fn resolve_endpoint_finney_returns_finney_url() {
        let url = resolve_endpoint(None, Some("finney")).expect("finney should resolve");
        assert_eq!(url, DEFAULT_ENDPOINT);
    }

    #[test]
    fn resolve_endpoint_test_returns_test_url() {
        let url = resolve_endpoint(None, Some("test")).expect("test should resolve");
        assert_eq!(url, TEST_ENDPOINT);
    }

    #[test]
    fn resolve_endpoint_local_returns_local_url() {
        let url = resolve_endpoint(None, Some("local")).expect("local should resolve");
        assert_eq!(url, LOCAL_ENDPOINT);
    }

    #[test]
    fn resolve_endpoint_unknown_network_returns_error() {
        let result = resolve_endpoint(None, Some("potato"));
        assert!(result.is_err(), "unrecognized network should fail");
    }

    #[test]
    fn resolve_endpoint_none_defaults_to_finney() {
        let url = resolve_endpoint(None, None).expect("default should resolve");
        assert_eq!(url, DEFAULT_ENDPOINT);
    }

    #[test]
    fn resolve_endpoint_explicit_url_overrides_network() {
        let url = resolve_endpoint(Some("wss://custom.example.com"), Some("test"))
            .expect("explicit URL should take precedence");
        assert_eq!(url, "wss://custom.example.com");
    }

    // -- validate_url tests --

    #[test]
    fn validate_url_wss_is_ok() {
        assert!(validate_url("wss://example.com").is_ok());
    }

    #[test]
    fn validate_url_ws_localhost_is_ok() {
        assert!(validate_url("ws://localhost:9944").is_ok());
    }

    #[test]
    fn validate_url_http_returns_error() {
        assert!(validate_url("http://example.com").is_err());
    }

    #[test]
    fn validate_url_empty_returns_error() {
        assert!(validate_url("").is_err());
    }

    #[test]
    fn validate_url_https_returns_error() {
        assert!(validate_url("https://example.com").is_err());
    }
}
