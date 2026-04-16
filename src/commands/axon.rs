use std::net::IpAddr;
use std::time::Duration;

use serde::Serialize;
use sp_core::Pair as PairTrait;
use subxt::ext::scale_value::Value as SValue;

use crate::commands::stake::Sr25519Signer;
use crate::commands::wallet_keys::load_hotkey_pair;
use crate::error::BttError;
use crate::rpc;

#[derive(Serialize)]
pub struct AxonResult {
    pub tx_hash: String,
    pub block: String,
    pub action: String,
    pub hotkey: String,
    pub netuid: u16,
}

pub struct AxonParams<'a> {
    pub wallet: &'a str,
    pub hotkey: &'a str,
    pub netuid: u16,
    pub ip: &'a str,
    pub port: u16,
    pub ip_type: u8,
    pub protocol: u8,
    pub version: u32,
}

pub async fn set(endpoint: &str, params: AxonParams<'_>) -> Result<AxonResult, BttError> {
    let parsed_ip: IpAddr = params.ip
        .parse()
        .map_err(|e| BttError::invalid_input(format!("invalid IP address: {e}")))?;

    let ip_as_u128 = match parsed_ip {
        IpAddr::V4(v4) => u128::from(u32::from(v4)),
        IpAddr::V6(v6) => u128::from(v6),
    };

    let actual_ip_type = match parsed_ip {
        IpAddr::V4(_) => 4u8,
        IpAddr::V6(_) => 6u8,
    };
    let ip_type = if params.ip_type == 0 { actual_ip_type } else { params.ip_type };

    let pair = load_hotkey_pair(params.wallet, params.hotkey)?;
    let hotkey_ss58 = sp_core::crypto::AccountId32::from(PairTrait::public(&pair)).to_string();
    let signer = Sr25519Signer::new(pair);

    let api = rpc::connect(endpoint).await?;

    let tx = subxt::dynamic::tx(
        "SubtensorModule",
        "serve_axon",
        vec![
            SValue::u128(params.netuid as u128),
            SValue::u128(params.version as u128),
            SValue::u128(ip_as_u128),
            SValue::u128(params.port as u128),
            SValue::u128(ip_type as u128),
            SValue::u128(params.protocol as u128),
        ],
    );

    let mut tx_client = tokio::time::timeout(Duration::from_secs(120), api.tx())
        .await
        .map_err(|_| BttError::submission_failed("resolving transaction client timed out"))?
        .map_err(|e| {
            BttError::submission_failed(format!("failed to resolve transaction client: {e}"))
        })?;

    let progress = tokio::time::timeout(
        Duration::from_secs(120),
        tx_client.sign_and_submit_then_watch_default(&tx, &signer),
    )
    .await
    .map_err(|_| BttError::submission_failed("transaction submission timed out"))?
    .map_err(|e| BttError::submission_failed(format!("failed to submit transaction: {e}")))?;

    let tx_hash = format!("{:?}", progress.extrinsic_hash());

    let in_block = tokio::time::timeout(Duration::from_secs(120), progress.wait_for_finalized())
        .await
        .map_err(|_| BttError::submission_failed("waiting for finalization timed out"))?
        .map_err(|e| BttError::submission_failed(format!("transaction failed: {e}")))?;

    let block_hash = format!("{:?}", in_block.block_hash());

    in_block
        .wait_for_success()
        .await
        .map_err(|e| BttError::submission_failed(format!("extrinsic failed: {e}")))?;

    Ok(AxonResult {
        tx_hash,
        block: block_hash,
        action: "serve_axon".to_string(),
        hotkey: hotkey_ss58,
        netuid: params.netuid,
    })
}

pub async fn reset(
    endpoint: &str,
    wallet: &str,
    hotkey_name: &str,
    netuid: u16,
) -> Result<AxonResult, BttError> {
    let pair = load_hotkey_pair(wallet, hotkey_name)?;
    let hotkey_ss58 = sp_core::crypto::AccountId32::from(PairTrait::public(&pair)).to_string();
    let signer = Sr25519Signer::new(pair);

    let api = rpc::connect(endpoint).await?;

    let tx = subxt::dynamic::tx(
        "SubtensorModule",
        "serve_axon",
        vec![
            SValue::u128(netuid as u128),
            SValue::u128(0u128),
            SValue::u128(0u128),
            SValue::u128(0u128),
            SValue::u128(0u128),
            SValue::u128(0u128),
        ],
    );

    let mut tx_client = tokio::time::timeout(Duration::from_secs(120), api.tx())
        .await
        .map_err(|_| BttError::submission_failed("resolving transaction client timed out"))?
        .map_err(|e| {
            BttError::submission_failed(format!("failed to resolve transaction client: {e}"))
        })?;

    let progress = tokio::time::timeout(
        Duration::from_secs(120),
        tx_client.sign_and_submit_then_watch_default(&tx, &signer),
    )
    .await
    .map_err(|_| BttError::submission_failed("transaction submission timed out"))?
    .map_err(|e| BttError::submission_failed(format!("failed to submit transaction: {e}")))?;

    let tx_hash = format!("{:?}", progress.extrinsic_hash());

    let in_block = tokio::time::timeout(Duration::from_secs(120), progress.wait_for_finalized())
        .await
        .map_err(|_| BttError::submission_failed("waiting for finalization timed out"))?
        .map_err(|e| BttError::submission_failed(format!("transaction failed: {e}")))?;

    let block_hash = format!("{:?}", in_block.block_hash());

    in_block
        .wait_for_success()
        .await
        .map_err(|e| BttError::submission_failed(format!("extrinsic failed: {e}")))?;

    Ok(AxonResult {
        tx_hash,
        block: block_hash,
        action: "reset_axon".to_string(),
        hotkey: hotkey_ss58,
        netuid,
    })
}

#[cfg(test)]
mod tests {
    use std::net::IpAddr;

    #[test]
    fn ipv4_to_u128() {
        let ip: IpAddr = "192.168.1.1".parse().expect("valid IPv4");
        let n = match ip {
            IpAddr::V4(v4) => u128::from(u32::from(v4)),
            IpAddr::V6(v6) => u128::from(v6),
        };
        assert_eq!(n, 0xC0A80101);
    }

    #[test]
    fn ipv6_to_u128() {
        let ip: IpAddr = "::1".parse().expect("valid IPv6");
        let n = match ip {
            IpAddr::V4(v4) => u128::from(u32::from(v4)),
            IpAddr::V6(v6) => u128::from(v6),
        };
        assert_eq!(n, 1);
    }
}
