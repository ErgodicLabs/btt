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

/// Validate that a URL uses `wss://` or a loopback `ws://` endpoint.
///
/// Policy:
/// - `wss://<any host>` is accepted.
/// - `ws://<loopback host>` is accepted. Loopback means `localhost`,
///   any IP in the `127.0.0.0/8` block, or `::1` / `[::1]`.
/// - `ws://<remote host>` is REJECTED. Users who want plaintext to a
///   non-loopback host must opt in via the explicit `local` network
///   shorthand or fix their config to use `wss://`.
/// - Any other scheme (http, https, file, ...) is REJECTED.
/// - Malformed URLs are REJECTED via `url::Url::parse`.
///
/// This closes the scheme-only gap documented in #69, left over from the
/// PR #57 subxt 0.50 upgrade and the PR #68 defense-in-depth pass.
pub fn validate_url(url: &str) -> Result<(), BttError> {
    let parsed = url::Url::parse(url)
        .map_err(|e| BttError::connection(format!("endpoint URL is not a valid URL: {}", e)))?;
    match parsed.scheme() {
        "wss" => Ok(()),
        "ws" => {
            let host = parsed.host_str().unwrap_or("");
            // Only accept ws:// for loopback hosts; require wss:// for remote.
            if is_loopback_host(host) {
                Ok(())
            } else {
                Err(BttError::connection(format!(
                    "plaintext ws:// is only allowed for loopback hosts; use wss:// for remote connections (got host {:?})",
                    host
                )))
            }
        }
        other => Err(BttError::connection(format!(
            "endpoint URL must use ws:// or wss:// scheme (got {:?})",
            other
        ))),
    }
}

/// Is `host` a loopback host?
///
/// Matches:
/// - `localhost` (case-insensitive)
/// - Any IPv4 in `127.0.0.0/8` (RFC-5735 loopback block)
/// - IPv6 `::1`, including the `[::1]` bracketed form that `url::Url`
///   returns from `host_str()` for IPv6 literals.
///
/// The check is structural: it operates on the parsed host, not a
/// substring of the raw URL, so hostile inputs like
/// `ws://localhost.attacker.com` are rejected.
fn is_loopback_host(host: &str) -> bool {
    let lower = host.to_ascii_lowercase();
    if lower == "localhost" {
        return true;
    }
    // IPv4 / IPv6 literal: delegate to std's is_loopback.
    if let Ok(ip) = lower.parse::<std::net::IpAddr>() {
        return ip.is_loopback();
    }
    // url::Url::host_str() returns IPv6 literals wrapped in brackets,
    // e.g. "[::1]". Strip brackets and re-parse.
    if lower.starts_with('[') && lower.ends_with(']') && lower.len() >= 2 {
        let inner = &lower[1..lower.len() - 1];
        if let Ok(ip) = inner.parse::<std::net::IpAddr>() {
            return ip.is_loopback();
        }
    }
    false
}

/// Connect to a substrate node and return an OnlineClient.
/// Applies a connection timeout.
///
/// Uses [`OnlineClient::from_insecure_url`] because the `local` network
/// shorthand points at a plain `ws://127.0.0.1:9944`; subxt 0.50's
/// `from_url` rejects non-TLS endpoints outright.
///
/// This function calls [`validate_url`] as belt-and-suspenders for callers
/// that bypass [`resolve_endpoint`]. The policy is host-aware: remote
/// hosts require `wss://`, and plaintext `ws://` is only accepted for
/// loopback targets. See [`validate_url`] for the full policy.
pub async fn connect(endpoint: &str) -> Result<OnlineClient<PolkadotConfig>, BttError> {
    // Host-aware defense-in-depth: rejects non-ws(s) schemes, malformed
    // URLs, and plaintext ws:// to any non-loopback host.
    validate_url(endpoint)?;
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
    // See note on `connect`: the validate_url guard is host-aware. It
    // rejects non-ws(s) schemes, malformed URLs, and plaintext ws:// to
    // any non-loopback host, closing the downgrade gap from #69.
    validate_url(endpoint)?;
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

    #[test]
    fn validate_url_ws_to_remote_host_rejects() {
        // The flipped version of the old by-design test. `ws://` to a
        // remote host is now rejected; the host-aware policy (#69) closes
        // the plaintext-to-mainnet gap that the scheme-only check left
        // open.
        let err = validate_url("ws://entrypoint-finney.opentensor.ai")
            .expect_err("ws:// to a remote host must be rejected");
        let msg = format!("{}", err);
        assert!(
            msg.contains("loopback"),
            "error should explain the loopback policy, got: {}",
            msg
        );
    }

    #[test]
    fn validate_url_wss_to_remote_host_accepts() {
        assert!(validate_url("wss://entrypoint-finney.opentensor.ai").is_ok());
    }

    #[test]
    fn validate_url_ws_127_loopback_accepts() {
        assert!(validate_url("ws://127.0.0.1:9944").is_ok());
    }

    #[test]
    fn validate_url_ws_127_non_canonical_loopback_accepts() {
        // RFC-5735 declares the entire 127.0.0.0/8 block as loopback, not
        // only 127.0.0.1. An admin who has bound a local node to
        // 127.0.0.42 for whatever reason should still be able to connect.
        assert!(validate_url("ws://127.0.0.42:9944").is_ok());
    }

    #[test]
    fn validate_url_ws_ipv6_loopback_accepts() {
        assert!(validate_url("ws://[::1]:9944").is_ok());
    }

    #[test]
    fn validate_url_ws_uppercase_localhost_accepts() {
        // Belt-and-suspenders: url::Url::parse lowercases the host for us,
        // but we still normalize case in `is_loopback_host` so that any
        // future path that skips the url crate stays consistent.
        assert!(validate_url("ws://LOCALHOST:9944").is_ok());
    }

    #[test]
    fn validate_url_ws_malicious_subdomain_rejects() {
        // Structural host match, not substring. `localhost.attacker.com`
        // must NOT slip through because its host string happens to start
        // with "localhost".
        assert!(
            validate_url("ws://localhost.attacker.com:9944").is_err(),
            "host match must be structural, not substring"
        );
    }

    #[test]
    fn validate_url_malformed_returns_error() {
        // url::Url::parse rejects strings with no scheme / no authority.
        assert!(validate_url("not a url").is_err());
    }

    // -- connect/connect_full defense-in-depth tests --
    //
    // These tests lock the guarantee that `rpc::connect*` reject non-ws/wss
    // URLs *before* handing them to subxt. The check is redundant with
    // `resolve_endpoint` for user-facing paths, but is the last line of
    // TLS-enforcement defense for any internal caller that constructs a
    // raw string (see issue #59). The test is synchronous because the
    // guard fires before any network I/O.

    #[test]
    fn connect_rejects_http_scheme_without_network_io() {
        // Build a tokio runtime locally so we can drive the async fn to
        // completion. The validate_url guard runs before any socket is
        // touched, so this is network-free.
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("runtime");
        let result = rt.block_on(connect("http://untrusted.example.com"));
        assert!(
            result.is_err(),
            "connect must reject non-ws/wss schemes via validate_url"
        );
    }

    #[test]
    fn connect_full_rejects_http_scheme_without_network_io() {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("runtime");
        let result = rt.block_on(connect_full("https://untrusted.example.com"));
        assert!(
            result.is_err(),
            "connect_full must reject non-ws/wss schemes via validate_url"
        );
    }
}
