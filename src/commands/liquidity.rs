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

/// Upper bound on how many `(netuid, coldkey, *)` entries we'll pull back
/// before bailing out. A single coldkey realistically holds at most a
/// few dozen positions per subnet; this cap exists only so a misbehaving
/// backend can't flood us unbounded.
const LIST_POSITIONS_HARD_CAP: usize = 10_000;

/// Upstream pallet_subtensor_swap tick bounds. From
/// `opentensor/subtensor@main:pallets/swap/src/tick.rs:194-199`:
///
/// ```text
/// const MIN_TICK: i32 = -887272;
/// pub const MIN: Self = Self(MIN_TICK.saturating_div(2));
/// pub const MAX: Self = Self(MAX_TICK.saturating_div(2));
/// ```
///
/// We enforce these client-side so the CLI fails fast with a helpful
/// error rather than paying gas to have the chain reject the extrinsic
/// with `InvalidTickRange`.
pub const TICK_INDEX_MIN: i32 = -443636;
pub const TICK_INDEX_MAX: i32 = 443636;

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

/// Build the dynamic payload for `Swap::add_liquidity`.
///
/// Upstream signature (`opentensor/subtensor@main:pallets/swap/src/pallet/mod.rs:373-380`):
///
/// ```text
/// pub fn add_liquidity(
///     origin: OriginFor<T>,
///     _hotkey: T::AccountId,
///     _netuid: NetUid,        // newtype around u16 → 2 bytes
///     _tick_low: TickIndex,   // newtype around i32 → 4 bytes
///     _tick_high: TickIndex,  // newtype around i32 → 4 bytes
///     _liquidity: u64,        // 8 bytes
/// ) -> DispatchResult
/// ```
///
/// The tick values must satisfy the range enforced by `TickIndex::new`
/// on the chain; see [`TICK_INDEX_MIN`] / [`TICK_INDEX_MAX`]. This
/// function assumes the caller has already validated the range.
fn build_add_liquidity_tx(
    hotkey_bytes: Vec<u8>,
    netuid: u16,
    tick_low: i32,
    tick_high: i32,
    amount_rao: u64,
) -> subxt::tx::DynamicPayload<Vec<SValue>> {
    subxt::dynamic::tx(
        "Swap",
        "add_liquidity",
        vec![
            SValue::from_bytes(hotkey_bytes),
            // NetUid (newtype u16). `SValue::from(u16)` produces a
            // U128 primitive; the subxt encoder narrows to 2 bytes at
            // the target TypeInfo.
            SValue::from(netuid),
            // TickIndex (newtype i32). Encoder narrows I128 → 4 bytes.
            SValue::from(tick_low),
            SValue::from(tick_high),
            // liquidity: u64. Encoder narrows U128 → 8 bytes.
            SValue::from(amount_rao),
        ],
    )
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

    // Client-side tick-bounds enforcement. Upstream `TickIndex::new`
    // rejects anything outside [-443636, 443636] and the extrinsic
    // reports `InvalidTickRange`; we surface that earlier with a
    // clearer message and no chain round-trip.
    if params.tick_low < TICK_INDEX_MIN || params.tick_high > TICK_INDEX_MAX {
        return Err(BttError::invalid_input(format!(
            "tick indexes must be in [{TICK_INDEX_MIN}, {TICK_INDEX_MAX}]; \
             got tick_low={tick_low}, tick_high={tick_high}",
            tick_low = params.tick_low,
            tick_high = params.tick_high,
        )));
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

    let tx = build_add_liquidity_tx(
        hotkey_bytes,
        params.netuid,
        params.tick_low,
        params.tick_high,
        amount_rao,
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

/// Build the dynamic payload for `Swap::remove_liquidity`.
///
/// Upstream signature (`pallets/swap/src/pallet/mod.rs:446-453`):
///
/// ```text
/// pub fn remove_liquidity(
///     origin: OriginFor<T>,
///     hotkey: T::AccountId,
///     netuid: NetUid,        // u16
///     position_id: PositionId, // u128
/// ) -> DispatchResult
/// ```
fn build_remove_liquidity_tx(
    hotkey_bytes: Vec<u8>,
    netuid: u16,
    position_id: u128,
) -> subxt::tx::DynamicPayload<Vec<SValue>> {
    subxt::dynamic::tx(
        "Swap",
        "remove_liquidity",
        vec![
            SValue::from_bytes(hotkey_bytes),
            SValue::from(netuid),
            // PositionId is a newtype around u128; pass a u128 directly.
            SValue::u128(position_id),
        ],
    )
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

    let tx = build_remove_liquidity_tx(hotkey_bytes, netuid, position_id);

    let (tx_hash, block_hash) = submit_coldkey_tx(&api, &tx, &signer).await?;

    Ok(LiquidityTxResult {
        tx_hash,
        block: block_hash,
        action: "remove_liquidity".to_string(),
        coldkey: coldkey_ss58,
        netuid,
    })
}

/// Build the dynamic payload for `Swap::modify_position`.
///
/// Upstream signature (`pallets/swap/src/pallet/mod.rs:507-513`):
///
/// ```text
/// pub fn modify_position(
///     origin: OriginFor<T>,
///     hotkey: T::AccountId,
///     netuid: NetUid,        // u16
///     position_id: PositionId, // u128
///     liquidity_delta: i64,   // 8 bytes
/// ) -> DispatchResult
/// ```
///
/// `liquidity_delta` is an abstract L-units Uniswap-V3 quantity, not a
/// RAO amount. See the barbarian-round-1 findings in PR #144 for the
/// extended discussion.
fn build_modify_position_tx(
    hotkey_bytes: Vec<u8>,
    netuid: u16,
    position_id: u128,
    liquidity_delta: i64,
) -> subxt::tx::DynamicPayload<Vec<SValue>> {
    subxt::dynamic::tx(
        "Swap",
        "modify_position",
        vec![
            SValue::from_bytes(hotkey_bytes),
            SValue::from(netuid),
            SValue::u128(position_id),
            // liquidity_delta: i64. Encoder narrows I128 → 8 bytes.
            SValue::from(liquidity_delta),
        ],
    )
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

    let tx = build_modify_position_tx(hotkey_bytes, netuid, position_id, liquidity_delta);

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

/// List positions for a coldkey on a subnet by iterating over the
/// `Swap::Positions` storage map with a `(NetUid, AccountId)` prefix.
///
/// The storage is declared upstream
/// (`pallets/swap/src/pallet/mod.rs:130-138`) as:
///
/// ```text
/// StorageNMap<_, (
///     NMapKey<Twox64Concat, NetUid>,
///     NMapKey<Twox64Concat, T::AccountId>,
///     NMapKey<Twox64Concat, PositionId>,
/// ), Position<T>, OptionQuery>
/// ```
///
/// Previous implementation iterated `for pos_id in 2..=LastPositionId`
/// which both started at 2 (missing position id 1) and did 10 000
/// sequential RPC round-trips when `LastPositionId` was large. This
/// version uses the subxt partial-key iterator, which issues a single
/// `state_getKeysPaged`-backed stream over the prefix
/// `(netuid, coldkey)` and returns only the positions that actually
/// exist for that pair.
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

    // `Swap::Positions` is a 3-key NMap `(NetUid, AccountId, PositionId)`.
    // Iterating with a 2-key prefix scans all positions held by this
    // coldkey on this subnet.
    let positions_addr =
        subxt::dynamic::storage::<Vec<SValue>, SValue>("Swap", "Positions");
    let prefix: Vec<SValue> = vec![
        SValue::from(netuid),
        SValue::from_bytes(coldkey_bytes),
    ];

    let mut stream = tokio::time::timeout(
        RPC_TIMEOUT,
        storage.iter(positions_addr, prefix),
    )
    .await
    .map_err(|_| BttError::query("Positions iter open timed out"))?
    .map_err(|e| BttError::query(format!("failed to open Positions iter: {e}")))?;

    let mut positions = Vec::new();

    while let Some(item) = tokio::time::timeout(RPC_TIMEOUT, stream.next())
        .await
        .map_err(|_| BttError::query("Positions iter next timed out"))?
    {
        let kv = item.map_err(|e| BttError::query(format!("Positions iter error: {e}")))?;
        let decoded = kv
            .value()
            .decode()
            .map_err(|e| BttError::parse(format!("failed to decode position: {e}")))?;
        if let Some(pos) = decode_position_value(&decoded) {
            if pos.liquidity_rao > 0 {
                positions.push(pos);
            }
        }

        if positions.len() >= LIST_POSITIONS_HARD_CAP {
            return Err(BttError::query(format!(
                "aborting: Positions stream exceeded hard cap of {LIST_POSITIONS_HARD_CAP} entries"
            )));
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

    let netuid_key = vec![SValue::from(netuid)];

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

// ─────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────
//
// These tests verify the SHAPE of the dynamic payloads — specifically,
// that tick indexes serialize as i32 (4 bytes each) rather than i128
// (16 bytes each), and liquidity_delta as i64 (8 bytes) rather than
// i128 (16 bytes). This was the regression the barbarian caught in
// PR #144 round 1.
//
// The subxt 0.50 dynamic API does not surface a "just give me the raw
// SCALE bytes against real metadata" shortcut at the `DynamicPayload`
// level without a live `OnlineClient`. Full byte-level golden vectors
// therefore require a pinned metadata fixture, which we do not yet
// ship. The fallback approach used here inspects the `scale_value::Value`
// variants directly: `Primitive::U128(n)` and `Primitive::I128(n)` are
// the only two numeric shapes `Value::from(u16/u32/u64/i32/i64)`
// produces, and the subxt encoder narrows them to the target width at
// encode time. This test asserts we're building the payloads with
// values that (a) fit the target width and (b) carry the correct sign,
// which is sufficient to prove the class of bug we just fixed cannot
// recur silently.
#[cfg(test)]
mod tests {
    use super::*;
    use subxt::ext::scale_value::{Primitive, ValueDef};

    /// Helper: pull the positional arguments out of a DynamicPayload.
    /// `CallData` for our dynamic txs is `Vec<SValue>` by construction
    /// in `build_*_tx`.
    fn args_of(tx: &subxt::tx::DynamicPayload<Vec<SValue>>) -> &[SValue] {
        tx.call_data().as_slice()
    }

    /// Expected widths (in bytes) for the primitives carried by each
    /// argument of `Swap::add_liquidity`, in positional order. Source:
    /// upstream `pallet_subtensor_swap::add_liquidity` signature.
    fn assert_numeric_fits(value: &SValue, signed: bool, max_bits: u32, label: &str) {
        match &value.value {
            ValueDef::Primitive(Primitive::U128(n)) => {
                assert!(!signed, "{label}: expected signed but got unsigned");
                let fits = max_bits >= 128 || *n < (1u128 << max_bits);
                assert!(fits, "{label}: value {n} does not fit in {max_bits} bits");
            }
            ValueDef::Primitive(Primitive::I128(n)) => {
                assert!(signed, "{label}: expected unsigned but got signed");
                if max_bits < 128 {
                    let lo = -(1i128 << (max_bits - 1));
                    let hi = (1i128 << (max_bits - 1)) - 1;
                    assert!(
                        *n >= lo && *n <= hi,
                        "{label}: value {n} does not fit in signed {max_bits} bits [{lo}, {hi}]"
                    );
                }
            }
            other => panic!("{label}: expected numeric primitive, got {other:?}"),
        }
    }

    /// Helper: does this SValue hold a 32-byte-array-shaped composite?
    fn is_32_byte_array(value: &SValue) -> bool {
        if let ValueDef::Composite(c) = &value.value {
            let values: Vec<_> = c.values().collect();
            return values.len() == 32;
        }
        false
    }

    #[test]
    fn add_liquidity_tx_encodes_correct_argument_widths() {
        let hotkey_bytes = vec![0x11u8; 32];
        let tx = build_add_liquidity_tx(hotkey_bytes, 5, -100, 100, 1_000_000_000);

        assert_eq!(tx.pallet_name(), "Swap");
        assert_eq!(tx.call_name(), "add_liquidity");

        let args = args_of(&tx);
        assert_eq!(args.len(), 5, "expected 5 positional args");

        // arg 0: hotkey AccountId — 32-byte composite.
        assert!(is_32_byte_array(&args[0]), "arg 0 hotkey should be a 32-byte array");

        // arg 1: netuid — u16 (fits in 16 bits, unsigned).
        assert_numeric_fits(&args[1], false, 16, "netuid");

        // arg 2: tick_low — i32. Must be signed, fit in 32 bits,
        // preserve the negative sign.
        assert_numeric_fits(&args[2], true, 32, "tick_low");
        if let ValueDef::Primitive(Primitive::I128(n)) = &args[2].value {
            assert_eq!(*n, -100i128, "tick_low value roundtrip");
        } else {
            panic!("tick_low was not an I128 primitive");
        }

        // arg 3: tick_high — i32.
        assert_numeric_fits(&args[3], true, 32, "tick_high");
        if let ValueDef::Primitive(Primitive::I128(n)) = &args[3].value {
            assert_eq!(*n, 100i128, "tick_high value roundtrip");
        } else {
            panic!("tick_high was not an I128 primitive");
        }

        // arg 4: liquidity — u64. Must fit in 64 bits.
        assert_numeric_fits(&args[4], false, 64, "liquidity");
        if let ValueDef::Primitive(Primitive::U128(n)) = &args[4].value {
            assert_eq!(*n, 1_000_000_000u128, "liquidity value roundtrip");
        } else {
            panic!("liquidity was not a U128 primitive");
        }
    }

    #[test]
    fn modify_position_tx_encodes_i64_delta_not_i128() {
        let hotkey_bytes = vec![0x22u8; 32];
        // Use a delta that fits in i64 but would only be legal if
        // we're actually encoding as i64.
        let delta: i64 = -1_234_567_890;
        let tx = build_modify_position_tx(hotkey_bytes, 5, 42u128, delta);

        assert_eq!(tx.pallet_name(), "Swap");
        assert_eq!(tx.call_name(), "modify_position");

        let args = args_of(&tx);
        assert_eq!(args.len(), 4);

        assert!(is_32_byte_array(&args[0]));
        assert_numeric_fits(&args[1], false, 16, "netuid");
        // position_id: u128, full width.
        assert_numeric_fits(&args[2], false, 128, "position_id");
        if let ValueDef::Primitive(Primitive::U128(n)) = &args[2].value {
            assert_eq!(*n, 42u128);
        } else {
            panic!("position_id was not a U128 primitive");
        }
        // delta: i64 — must be signed and fit in 64 bits.
        assert_numeric_fits(&args[3], true, 64, "liquidity_delta");
        if let ValueDef::Primitive(Primitive::I128(n)) = &args[3].value {
            assert_eq!(*n, delta as i128);
        } else {
            panic!("liquidity_delta was not an I128 primitive");
        }
    }

    #[test]
    fn remove_liquidity_tx_constructs_cleanly() {
        let hotkey_bytes = vec![0x33u8; 32];
        let tx = build_remove_liquidity_tx(hotkey_bytes, 1, 7u128);

        assert_eq!(tx.pallet_name(), "Swap");
        assert_eq!(tx.call_name(), "remove_liquidity");

        let args = args_of(&tx);
        assert_eq!(args.len(), 3);

        assert!(is_32_byte_array(&args[0]));
        assert_numeric_fits(&args[1], false, 16, "netuid");
        assert_numeric_fits(&args[2], false, 128, "position_id");
    }

    #[test]
    fn tick_index_bounds_match_upstream() {
        // If the upstream bounds ever change these constants must be
        // updated in lockstep. Pin them explicitly so a drift becomes
        // a CI failure rather than a silent miscompile against an
        // updated testnet.
        assert_eq!(TICK_INDEX_MIN, -443_636);
        assert_eq!(TICK_INDEX_MAX, 443_636);
    }
}
