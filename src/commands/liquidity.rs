use std::time::Duration;

use serde::Serialize;
use sp_core::crypto::{AccountId32, Ss58Codec};
use sp_core::Pair as PairTrait;
use subxt::dynamic::At;
use subxt::ext::scale_value::Value as SValue;

use crate::commands::chain::parse_ss58;
use crate::commands::dynamic_decode::{compact_value_to_u128, value_to_u64};
use crate::commands::stake::Sr25519Signer;
use crate::commands::wallet_keys::{decrypt_coldkey_interactive, rao_to_tao_string, tao_to_rao};
use crate::error::BttError;
use crate::rpc;

const RPC_TIMEOUT: Duration = Duration::from_secs(30);

#[derive(Serialize)]
pub struct LiquidityTxResult {
    pub tx_hash: String,
    pub block: String,
    pub action: String,
    pub coldkey: String,
    pub netuid: u16,
}

async fn submit_coldkey_tx(
    api: &subxt::OnlineClient<subxt::PolkadotConfig>,
    tx: &subxt::tx::DynamicPayload<Vec<SValue>>,
    signer: &Sr25519Signer,
) -> Result<(String, String), BttError> {
    let mut tx_client = tokio::time::timeout(Duration::from_secs(120), api.tx())
        .await
        .map_err(|_| BttError::submission_failed("resolving transaction client timed out"))?
        .map_err(|e| {
            BttError::submission_failed(format!("failed to resolve transaction client: {e}"))
        })?;

    let progress = tokio::time::timeout(
        Duration::from_secs(120),
        tx_client.sign_and_submit_then_watch_default(tx, signer),
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

    Ok((tx_hash, block_hash))
}

pub struct AddLiquidityParams<'a> {
    pub wallet: &'a str,
    pub hotkey: &'a str,
    pub netuid: u16,
    pub tick_low: i32,
    pub tick_high: i32,
    pub amount_tao: f64,
}

pub async fn add_liquidity(
    endpoint: &str,
    params: AddLiquidityParams<'_>,
) -> Result<LiquidityTxResult, BttError> {
    let amount_rao = tao_to_rao(params.amount_tao)?;
    if amount_rao == 0 {
        return Err(BttError::invalid_amount(
            "liquidity amount must be greater than zero",
        ));
    }
    if params.tick_low >= params.tick_high {
        return Err(BttError::invalid_input(
            "tick-low must be strictly less than tick-high",
        ));
    }

    let hotkey_bytes = parse_ss58(params.hotkey)?;

    let pair = decrypt_coldkey_interactive(params.wallet)?;
    let coldkey_ss58 = AccountId32::from(PairTrait::public(&pair)).to_ss58check();
    let signer = Sr25519Signer::new(pair);

    let api = rpc::connect(endpoint).await?;

    let tx = subxt::dynamic::tx(
        "Swap",
        "add_liquidity",
        vec![
            SValue::from_bytes(hotkey_bytes),
            SValue::u128(params.netuid as u128),
            SValue::i128(params.tick_low as i128),
            SValue::i128(params.tick_high as i128),
            SValue::u128(amount_rao as u128),
        ],
    );

    let (tx_hash, block_hash) = submit_coldkey_tx(&api, &tx, &signer).await?;

    Ok(LiquidityTxResult {
        tx_hash,
        block: block_hash,
        action: "add_liquidity".to_string(),
        coldkey: coldkey_ss58,
        netuid: params.netuid,
    })
}

pub async fn remove_liquidity(
    endpoint: &str,
    wallet: &str,
    hotkey_ss58: &str,
    netuid: u16,
    position_id: u128,
) -> Result<LiquidityTxResult, BttError> {
    let hotkey_bytes = parse_ss58(hotkey_ss58)?;

    let pair = decrypt_coldkey_interactive(wallet)?;
    let coldkey_ss58 = AccountId32::from(PairTrait::public(&pair)).to_ss58check();
    let signer = Sr25519Signer::new(pair);

    let api = rpc::connect(endpoint).await?;

    let tx = subxt::dynamic::tx(
        "Swap",
        "remove_liquidity",
        vec![
            SValue::from_bytes(hotkey_bytes),
            SValue::u128(netuid as u128),
            SValue::u128(position_id),
        ],
    );

    let (tx_hash, block_hash) = submit_coldkey_tx(&api, &tx, &signer).await?;

    Ok(LiquidityTxResult {
        tx_hash,
        block: block_hash,
        action: "remove_liquidity".to_string(),
        coldkey: coldkey_ss58,
        netuid,
    })
}

pub async fn modify_position(
    endpoint: &str,
    wallet: &str,
    hotkey_ss58: &str,
    netuid: u16,
    position_id: u128,
    liquidity_delta: i64,
) -> Result<LiquidityTxResult, BttError> {
    if liquidity_delta == 0 {
        return Err(BttError::invalid_input(
            "liquidity delta must be non-zero",
        ));
    }

    let hotkey_bytes = parse_ss58(hotkey_ss58)?;

    let pair = decrypt_coldkey_interactive(wallet)?;
    let coldkey_ss58 = AccountId32::from(PairTrait::public(&pair)).to_ss58check();
    let signer = Sr25519Signer::new(pair);

    let api = rpc::connect(endpoint).await?;

    let tx = subxt::dynamic::tx(
        "Swap",
        "modify_position",
        vec![
            SValue::from_bytes(hotkey_bytes),
            SValue::u128(netuid as u128),
            SValue::u128(position_id),
            SValue::i128(liquidity_delta as i128),
        ],
    );

    let (tx_hash, block_hash) = submit_coldkey_tx(&api, &tx, &signer).await?;

    Ok(LiquidityTxResult {
        tx_hash,
        block: block_hash,
        action: "modify_position".to_string(),
        coldkey: coldkey_ss58,
        netuid,
    })
}

#[derive(Serialize)]
pub struct PositionInfo {
    pub position_id: u128,
    pub tick_low: i32,
    pub tick_high: i32,
    pub liquidity_rao: u64,
    pub liquidity: String,
}

#[derive(Serialize)]
pub struct ListPositionsResult {
    pub coldkey: String,
    pub netuid: u16,
    pub positions: Vec<PositionInfo>,
}

fn decode_position_value<C: Clone>(decoded: &subxt::dynamic::Value<C>) -> Option<PositionInfo> {
    let id = compact_value_to_u128(decoded.at("id")?)?;
    let tick_low = decoded.at("tick_low").and_then(|v| v.as_i128()).map(|n| n as i32)?;
    let tick_high = decoded.at("tick_high").and_then(|v| v.as_i128()).map(|n| n as i32)?;
    let liquidity = decoded.at("liquidity").and_then(value_to_u64)?;

    Some(PositionInfo {
        position_id: id,
        tick_low,
        tick_high,
        liquidity_rao: liquidity,
        liquidity: rao_to_tao_string(liquidity),
    })
}

pub async fn list_positions(
    endpoint: &str,
    coldkey_ss58: &str,
    netuid: u16,
) -> Result<ListPositionsResult, BttError> {
    let coldkey_bytes = parse_ss58(coldkey_ss58)?;

    let api = rpc::connect(endpoint).await?;

    let at_block = tokio::time::timeout(RPC_TIMEOUT, api.at_current_block())
        .await
        .map_err(|_| BttError::query("storage query timed out"))?
        .map_err(|e| BttError::query(format!("failed to get block: {e}")))?;

    let storage = at_block.storage();

    // Query LastPositionId to know the upper bound of position IDs.
    let last_id_query =
        subxt::dynamic::storage::<Vec<SValue>, SValue>("Swap", "LastPositionId");
    let last_id_result = tokio::time::timeout(
        RPC_TIMEOUT,
        storage.try_fetch(&last_id_query, Vec::<SValue>::new()),
    )
    .await
    .map_err(|_| BttError::query("LastPositionId fetch timed out"))?
    .map_err(|e| BttError::query(format!("failed to fetch LastPositionId: {e}")))?;

    let last_id = match last_id_result {
        Some(val) => {
            let decoded = val
                .decode()
                .map_err(|e| BttError::parse(format!("failed to decode LastPositionId: {e}")))?;
            compact_value_to_u128(&decoded).unwrap_or(0)
        }
        None => 0,
    };

    if last_id < 2 {
        return Ok(ListPositionsResult {
            coldkey: coldkey_ss58.to_string(),
            netuid,
            positions: Vec::new(),
        });
    }

    let positions_query =
        subxt::dynamic::storage::<Vec<SValue>, SValue>("Swap", "Positions");

    let mut positions = Vec::new();
    let upper = last_id.min(10_000);

    for pos_id in 2..=upper {
        let result = tokio::time::timeout(
            RPC_TIMEOUT,
            storage.try_fetch(
                &positions_query,
                vec![
                    SValue::u128(netuid as u128),
                    SValue::from_bytes(coldkey_bytes),
                    SValue::u128(pos_id),
                ],
            ),
        )
        .await
        .map_err(|_| BttError::query("position fetch timed out"))?
        .map_err(|e| BttError::query(format!("failed to fetch position: {e}")))?;

        if let Some(value) = result {
            let decoded = value
                .decode()
                .map_err(|e| BttError::parse(format!("failed to decode position: {e}")))?;
            if let Some(pos) = decode_position_value(&decoded) {
                if pos.liquidity_rao > 0 {
                    positions.push(pos);
                }
            }
        }
    }

    Ok(ListPositionsResult {
        coldkey: coldkey_ss58.to_string(),
        netuid,
        positions,
    })
}

#[derive(Serialize)]
pub struct PoolInfo {
    pub netuid: u16,
    pub current_tick: i32,
    pub current_liquidity_rao: u64,
    pub current_liquidity: String,
    pub user_liquidity_enabled: bool,
    pub v3_initialized: bool,
}

pub async fn pool_info(endpoint: &str, netuid: u16) -> Result<PoolInfo, BttError> {
    let api = rpc::connect(endpoint).await?;

    let at_block = tokio::time::timeout(RPC_TIMEOUT, api.at_current_block())
        .await
        .map_err(|_| BttError::query("storage query timed out"))?
        .map_err(|e| BttError::query(format!("failed to get block: {e}")))?;

    let storage = at_block.storage();

    let netuid_key = vec![SValue::u128(netuid as u128)];

    let fetch_u64 = |name: &'static str| {
        let query = subxt::dynamic::storage::<Vec<SValue>, SValue>("Swap", name);
        let keys = netuid_key.clone();
        let storage = &storage;
        async move {
            let result = tokio::time::timeout(
                RPC_TIMEOUT,
                storage.try_fetch(&query, keys),
            )
            .await
            .map_err(|_| BttError::query(format!("{name} fetch timed out")))?
            .map_err(|e| BttError::query(format!("failed to fetch {name}: {e}")))?;

            match result {
                Some(val) => {
                    let decoded = val
                        .decode()
                        .map_err(|e| BttError::parse(format!("failed to decode {name}: {e}")))?;
                    Ok(value_to_u64(&decoded).unwrap_or(0))
                }
                None => Ok(0),
            }
        }
    };

    let fetch_i32 = |name: &'static str| {
        let query = subxt::dynamic::storage::<Vec<SValue>, SValue>("Swap", name);
        let keys = netuid_key.clone();
        let storage = &storage;
        async move {
            let result = tokio::time::timeout(
                RPC_TIMEOUT,
                storage.try_fetch(&query, keys),
            )
            .await
            .map_err(|_| BttError::query(format!("{name} fetch timed out")))?
            .map_err(|e| BttError::query(format!("failed to fetch {name}: {e}")))?;

            match result {
                Some(val) => {
                    let decoded = val
                        .decode()
                        .map_err(|e| BttError::parse(format!("failed to decode {name}: {e}")))?;
                    Ok(decoded.as_i128().map(|n| n as i32).unwrap_or(0))
                }
                None => Ok(0),
            }
        }
    };

    let fetch_bool = |name: &'static str| {
        let query = subxt::dynamic::storage::<Vec<SValue>, SValue>("Swap", name);
        let keys = netuid_key.clone();
        let storage = &storage;
        async move {
            let result = tokio::time::timeout(
                RPC_TIMEOUT,
                storage.try_fetch(&query, keys),
            )
            .await
            .map_err(|_| BttError::query(format!("{name} fetch timed out")))?
            .map_err(|e| BttError::query(format!("failed to fetch {name}: {e}")))?;

            match result {
                Some(val) => {
                    let decoded = val
                        .decode()
                        .map_err(|e| BttError::parse(format!("failed to decode {name}: {e}")))?;
                    Ok(decoded.as_bool().unwrap_or(false))
                }
                None => Ok(false),
            }
        }
    };

    let current_tick = fetch_i32("CurrentTick").await?;
    let current_liquidity = fetch_u64("CurrentLiquidity").await?;
    let user_liquidity_enabled = fetch_bool("EnabledUserLiquidity").await?;
    let v3_initialized = fetch_bool("SwapV3Initialized").await?;

    Ok(PoolInfo {
        netuid,
        current_tick,
        current_liquidity_rao: current_liquidity,
        current_liquidity: rao_to_tao_string(current_liquidity),
        user_liquidity_enabled,
        v3_initialized,
    })
}
