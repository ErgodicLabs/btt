use std::time::Duration;

use serde::Serialize;
use sp_core::Pair as PairTrait;
use subxt::dynamic::At;
use subxt::ext::scale_value::Value as SValue;

use crate::commands::chain::parse_ss58;
use crate::commands::dynamic_decode::value_to_u64;
use crate::commands::stake::Sr25519Signer;
use crate::commands::wallet_keys::load_hotkey_pair;
use crate::error::BttError;
use crate::rpc;

const RPC_TIMEOUT: Duration = Duration::from_secs(30);

#[derive(Serialize)]
pub struct ChildHotkeyTxResult {
    pub tx_hash: String,
    pub block: String,
    pub action: String,
    pub hotkey: String,
    pub netuid: u16,
}

async fn submit_hotkey_tx(
    endpoint: &str,
    wallet: &str,
    hotkey_name: &str,
    tx: subxt::tx::DynamicPayload<Vec<SValue>>,
    action: &str,
    netuid: u16,
) -> Result<ChildHotkeyTxResult, BttError> {
    let pair = load_hotkey_pair(wallet, hotkey_name)?;
    let hotkey_ss58 = sp_core::crypto::AccountId32::from(PairTrait::public(&pair)).to_string();
    let signer = Sr25519Signer::new(pair);

    let api = rpc::connect(endpoint).await?;

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

    Ok(ChildHotkeyTxResult {
        tx_hash,
        block: block_hash,
        action: action.to_string(),
        hotkey: hotkey_ss58,
        netuid,
    })
}

pub async fn set_child(
    endpoint: &str,
    wallet: &str,
    hotkey_name: &str,
    child_ss58: &str,
    netuid: u16,
    proportion: u64,
) -> Result<ChildHotkeyTxResult, BttError> {
    let child_bytes = parse_ss58(child_ss58)?;

    let tx = subxt::dynamic::tx(
        "SubtensorModule",
        "set_children",
        vec![
            SValue::u128(netuid as u128),
            SValue::unnamed_composite([SValue::unnamed_composite([
                SValue::u128(proportion as u128),
                SValue::from_bytes(child_bytes),
            ])]),
        ],
    );

    submit_hotkey_tx(endpoint, wallet, hotkey_name, tx, "set_children", netuid).await
}

pub async fn revoke_child(
    endpoint: &str,
    wallet: &str,
    hotkey_name: &str,
    netuid: u16,
) -> Result<ChildHotkeyTxResult, BttError> {
    let tx = subxt::dynamic::tx(
        "SubtensorModule",
        "set_children",
        vec![
            SValue::u128(netuid as u128),
            SValue::unnamed_composite(std::iter::empty::<SValue>()),
        ],
    );

    submit_hotkey_tx(endpoint, wallet, hotkey_name, tx, "revoke_children", netuid).await
}

pub async fn set_childkey_take(
    endpoint: &str,
    wallet: &str,
    hotkey_name: &str,
    netuid: u16,
    take: u16,
) -> Result<ChildHotkeyTxResult, BttError> {
    let tx = subxt::dynamic::tx(
        "SubtensorModule",
        "set_childkey_take",
        vec![
            SValue::u128(netuid as u128),
            SValue::u128(take as u128),
        ],
    );

    submit_hotkey_tx(endpoint, wallet, hotkey_name, tx, "set_childkey_take", netuid).await
}

#[derive(Serialize)]
pub struct ChildInfo {
    pub child_hotkey: String,
    pub proportion: u64,
}

#[derive(Serialize)]
pub struct GetChildrenResult {
    pub hotkey: String,
    pub netuid: u16,
    pub children: Vec<ChildInfo>,
}

pub async fn get_children(
    endpoint: &str,
    hotkey_ss58: &str,
    netuid: u16,
) -> Result<GetChildrenResult, BttError> {
    let hotkey_bytes = parse_ss58(hotkey_ss58)?;

    let api = rpc::connect(endpoint).await?;

    let storage_query =
        subxt::dynamic::storage::<Vec<SValue>, SValue>("SubtensorModule", "ChildKeys");

    let at_block = tokio::time::timeout(RPC_TIMEOUT, api.at_current_block())
        .await
        .map_err(|_| BttError::query("storage query timed out"))?
        .map_err(|e| BttError::query(format!("failed to get block: {e}")))?;

    let storage = at_block.storage();

    let result = tokio::time::timeout(
        RPC_TIMEOUT,
        storage.try_fetch(
            &storage_query,
            vec![
                SValue::from_bytes(hotkey_bytes),
                SValue::u128(netuid as u128),
            ],
        ),
    )
    .await
    .map_err(|_| BttError::query("children fetch timed out"))?
    .map_err(|e| BttError::query(format!("failed to fetch children: {e}")))?;

    let children = match result {
        Some(value) => {
            let decoded = value
                .decode()
                .map_err(|e| BttError::parse(format!("failed to decode children: {e}")))?;

            let mut out = Vec::new();
            let mut idx = 0usize;
            while let Some(entry) = decoded.at(idx) {
                let proportion = entry
                    .at(0)
                    .and_then(value_to_u64)
                    .unwrap_or(0);
                let child_bytes = entry.at(1);
                let child_ss58 = child_bytes
                    .map(|v| {
                        let mut bytes = Vec::new();
                        let mut j = 0usize;
                        while let Some(b) = v.at(j) {
                            if let Some(n) = value_to_u64(b) {
                                bytes.push(n as u8);
                            }
                            j += 1;
                        }
                        if bytes.len() == 32 {
                            sp_core::crypto::AccountId32::from(
                                <[u8; 32]>::try_from(bytes.as_slice()).expect("len checked"),
                            )
                            .to_string()
                        } else {
                            format!("0x{}", hex::encode(&bytes))
                        }
                    })
                    .unwrap_or_default();
                out.push(ChildInfo {
                    child_hotkey: child_ss58,
                    proportion,
                });
                idx += 1;
            }
            out
        }
        None => Vec::new(),
    };

    Ok(GetChildrenResult {
        hotkey: hotkey_ss58.to_string(),
        netuid,
        children,
    })
}
