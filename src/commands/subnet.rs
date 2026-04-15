// Subnet commands. Phase 1 (issue #77) is read-only. All four
// commands land now: `lock-cost` (PR #91), `list` (PR #92),
// `metagraph` (PR #94), `hyperparameters` (this PR). They call into
// `SubnetInfoRuntimeApi` / `SubnetRegistrationRuntimeApi` — pure
// runtime state queries, no extrinsics, no wallet material, no
// trust-sensitive surface. Phase 2 of issue #77 is reserved for
// write commands (`subnet register`, `subnet create`, etc.) and will
// be its own issue + PRs.

use std::time::Duration;

use serde::Serialize;
use sp_core::crypto::{AccountId32, Ss58Codec};
use subxt::dynamic::{At, Value};
use subxt::ext::scale_value::Value as SValue;

use crate::error::BttError;
use crate::rpc;

const RPC_TIMEOUT: Duration = rpc::RPC_TIMEOUT;

// ── lock-cost ────────────────────────────────────────────────────────────

/// Result shape for `btt subnet lock-cost`.
///
/// The TAO cost of creating a new subnet is computed inside the
/// subtensor runtime (see `SubtensorModule::get_network_lock_cost` in
/// `pallets/subtensor/src/coinbase/root.rs`) from five on-chain
/// quantities: `NetworkLastLockCost`, `NetworkMinLockCost`, the last
/// lock block, the current block, and `NetworkLockReductionInterval`.
/// The runtime exposes the final computed value through the
/// `SubnetRegistrationRuntimeApi::get_network_registration_cost`
/// runtime API, which is what we call here rather than replicating the
/// formula client-side — fewer round trips, no drift risk.
#[derive(Serialize)]
pub struct LockCostInfo {
    /// Current network lock cost, denominated in rao (1 TAO = 1e9 rao).
    /// Serialized as a decimal string for consistency with the rest of
    /// btt's JSON output, which stringifies on-chain u64/u128 values so
    /// downstream parsers do not have to worry about JSON number
    /// precision for large balances.
    pub lock_cost_rao: String,

    /// The same value converted to TAO, carried as a string with 9
    /// fractional digits. Convenience for humans; the authoritative
    /// field is `lock_cost_rao`.
    pub lock_cost_tao: String,

    /// The block number at which the runtime API was queried. Included
    /// so callers can correlate the returned cost with a specific chain
    /// state — the value can and does move over time as the lock
    /// reduction schedule ticks the cost down between registrations.
    pub at_block: u64,
}

/// Query the current network lock cost (TAO cost to register a new subnet).
///
/// This calls `SubnetRegistrationRuntimeApi::get_network_registration_cost`
/// on the head block. The runtime API performs the full `get_network_lock_cost`
/// calculation inside the runtime, so this function makes exactly two
/// round trips to the node: one `at_current_block` to pin the view, and
/// one runtime API call against that block.
pub async fn lock_cost(endpoint: &str) -> Result<LockCostInfo, BttError> {
    let api = rpc::connect(endpoint).await?;

    let at_block = tokio::time::timeout(RPC_TIMEOUT, api.at_current_block())
        .await
        .map_err(|_| BttError::query("at_current_block() timed out"))?
        .map_err(|e| BttError::query(format!("failed to resolve client at head: {e}")))?;

    let block_number: u64 = at_block.block_number();

    // Dynamic runtime API call: `SubnetRegistrationRuntimeApi::get_network_registration_cost()`.
    // Takes no arguments, returns a `TaoBalance` (u64 rao). We decode
    // through a dynamic `scale_value::Value` so this module stays free
    // of any compile-time dependency on subtensor's generated types.
    let call = subxt::dynamic::runtime_api_call::<Vec<SValue>, SValue>(
        "SubnetRegistrationRuntimeApi",
        "get_network_registration_cost",
        vec![],
    );

    let value = tokio::time::timeout(RPC_TIMEOUT, at_block.runtime_apis().call(call))
        .await
        .map_err(|_| BttError::query("get_network_registration_cost timed out"))?
        .map_err(|e| {
            BttError::query(format!(
                "get_network_registration_cost runtime call failed: {e}"
            ))
        })?;

    // The runtime returns a single integer value. `scale_value`'s
    // top-level decode may yield either a bare primitive or a
    // single-field composite depending on how the return type is
    // expressed at the metadata level. Walk both shapes defensively.
    let rao: u128 = extract_balance_u128(&value).ok_or_else(|| {
        BttError::parse(format!(
            "lock cost runtime value is not a decodable integer: {value:?}"
        ))
    })?;

    Ok(LockCostInfo {
        lock_cost_rao: rao.to_string(),
        lock_cost_tao: format_rao_as_tao(rao),
        at_block: block_number,
    })
}

// ── list ───────────────────────────────────────────────────────────────

/// One row in the output of `btt subnet list`.
///
/// The wire format of `SubtensorModule::SubnetInfo` has 18 fields; we
/// surface a curated nine here. The full dump is out of scope for a
/// list view — a future `subnet info --netuid <N>` command can emit
/// the full struct when that's actually useful. Field choice is:
///
/// - `netuid`            — the subnet id
/// - `owner_ss58`        — the ss58-encoded owner coldkey (created the subnet)
/// - `subnetwork_n`      — the current count of registered UIDs
/// - `max_allowed_uids`  — the slot cap (how many UIDs can exist)
/// - `tempo`             — blocks between emission distribution events
/// - `burn_rao`          — current registration burn, stringified rao
/// - `burn_tao`          — the same value expressed as TAO with 9 frac digits
/// - `emission_rao` — per-block TAO emitted into this subnet.
///   **Currently always "0"**: the upstream `get_subnet_info`
///   implementation in subtensor
///   (`pallets/subtensor/src/rpc_info/subnet_info.rs`) hardcodes
///   `emission_values: 0.into()` for both `SubnetInfo` v1 and v2 and
///   does not read from live chain state. btt decodes the field
///   faithfully and will produce real values the moment the runtime
///   starts populating it; the column is kept in place so downstream
///   parsers don't have to add and remove it across a runtime upgrade.
/// - `difficulty`        — PoW difficulty
/// - `immunity_period`   — blocks a new UID is immune from deregistration
///
/// Balances are stringified to protect downstream JSON parsers from
/// precision loss (Rao values routinely exceed JavaScript's
/// `Number.MAX_SAFE_INTEGER`).
#[derive(Serialize, Debug, PartialEq, Eq)]
pub struct SubnetListEntry {
    pub netuid: u16,
    pub owner_ss58: String,
    pub subnetwork_n: u16,
    pub max_allowed_uids: u16,
    pub tempo: u16,
    pub burn_rao: String,
    pub burn_tao: String,
    pub emission_rao: String,
    pub difficulty: u64,
    pub immunity_period: u16,
}

/// Result envelope for `btt subnet list`. `at_block` correlates the
/// snapshot to a specific chain state; `subnets` is sorted ascending by
/// `netuid`.
#[derive(Serialize)]
pub struct SubnetListResult {
    pub at_block: u64,
    pub subnets: Vec<SubnetListEntry>,
}

/// Enumerate every subnet currently known to the runtime.
///
/// Calls `SubnetInfoRuntimeApi::get_subnets_info` which returns a
/// `Vec<Option<SubnetInfo<AccountId32>>>` indexed by netuid. `None`
/// entries are filtered out (they represent gaps in the netuid range
/// from deregistered subnets). Each surviving `Some` is decoded into
/// a `SubnetListEntry`.
///
/// Two round trips: one `at_current_block`, one runtime API call.
pub async fn list(endpoint: &str) -> Result<SubnetListResult, BttError> {
    let api = rpc::connect(endpoint).await?;

    let at_block = tokio::time::timeout(RPC_TIMEOUT, api.at_current_block())
        .await
        .map_err(|_| BttError::query("at_current_block() timed out"))?
        .map_err(|e| BttError::query(format!("failed to resolve client at head: {e}")))?;

    let block_number: u64 = at_block.block_number();

    let call = subxt::dynamic::runtime_api_call::<Vec<SValue>, SValue>(
        "SubnetInfoRuntimeApi",
        "get_subnets_info",
        vec![],
    );

    let value = tokio::time::timeout(RPC_TIMEOUT, at_block.runtime_apis().call(call))
        .await
        .map_err(|_| BttError::query("get_subnets_info timed out"))?
        .map_err(|e| BttError::query(format!("get_subnets_info runtime call failed: {e}")))?;

    let mut subnets = parse_subnet_info_list(&value)?;
    subnets.sort_by_key(|e| e.netuid);

    Ok(SubnetListResult {
        at_block: block_number,
        subnets,
    })
}

/// Walk a decoded `Vec<Option<SubnetInfo>>` value and produce one
/// `SubnetListEntry` per `Some(info)`. Malformed entries produce errors:
/// we'd rather report a bad row than silently drop it, because a silent
/// drop hides runtime-version drift where a new field got added or
/// renamed.
fn parse_subnet_info_list<C: Clone>(value: &Value<C>) -> Result<Vec<SubnetListEntry>, BttError> {
    let mut out = Vec::new();
    let mut idx = 0usize;
    while let Some(entry) = value.at(idx) {
        idx += 1;

        // `Option<SubnetInfo>` decodes as an enum variant. `None` is a
        // variant named "None" with no fields; `Some` is a variant
        // named "Some" with a single child that IS the `SubnetInfo`
        // composite. scale-value exposes the variant payload through
        // `.at(0)`: for `Some(...)` we get the inner struct, for `None`
        // we get nothing.
        //
        // Note: under the *current* upstream implementation
        // (`pallets/subtensor/src/rpc_info/subnet_info.rs:172-192`)
        // `get_subnets_info` pushes only `Some` entries — deregistered-
        // netuid gaps are already filtered out at the producer. This
        // `None` skip branch is therefore dead code against the live
        // runtime today. It is kept as a defensive guard in case the
        // producer contract changes to include gap placeholders; if
        // the decoder ever begins reporting skipped rows, that is
        // signal that upstream shape moved.
        let info = match entry.at(0) {
            Some(inner) => inner,
            None => continue,
        };

        let netuid = compact_u16(info, "netuid").ok_or_else(|| {
            BttError::parse(format!(
                "SubnetInfo[{}]: missing or malformed netuid",
                idx - 1
            ))
        })?;

        let owner_bytes = extract_account_id_field(info, "owner").ok_or_else(|| {
            BttError::parse(format!(
                "SubnetInfo[netuid={netuid}]: missing or malformed owner account"
            ))
        })?;
        let owner_ss58 = AccountId32::from(owner_bytes).to_ss58check();

        let subnetwork_n = compact_u16(info, "subnetwork_n").ok_or_else(|| {
            BttError::parse(format!(
                "SubnetInfo[netuid={netuid}]: missing subnetwork_n"
            ))
        })?;
        let max_allowed_uids = compact_u16(info, "max_allowed_uids").ok_or_else(|| {
            BttError::parse(format!(
                "SubnetInfo[netuid={netuid}]: missing max_allowed_uids"
            ))
        })?;
        let tempo = compact_u16(info, "tempo").ok_or_else(|| {
            BttError::parse(format!("SubnetInfo[netuid={netuid}]: missing tempo"))
        })?;
        let immunity_period = compact_u16(info, "immunity_period").ok_or_else(|| {
            BttError::parse(format!(
                "SubnetInfo[netuid={netuid}]: missing immunity_period"
            ))
        })?;
        let difficulty = compact_u64(info, "difficulty").ok_or_else(|| {
            BttError::parse(format!("SubnetInfo[netuid={netuid}]: missing difficulty"))
        })?;

        let burn_rao = compact_u128(info, "burn").ok_or_else(|| {
            BttError::parse(format!("SubnetInfo[netuid={netuid}]: missing burn"))
        })?;
        // `SubnetInfo::emission_values` in the v1 struct (v2 has
        // `emission_value`); accept either so a runtime version swap
        // does not silently drop the column.
        let emission_rao = compact_u128(info, "emission_values")
            .or_else(|| compact_u128(info, "emission_value"))
            .ok_or_else(|| {
                BttError::parse(format!(
                    "SubnetInfo[netuid={netuid}]: missing emission_values/emission_value"
                ))
            })?;

        out.push(SubnetListEntry {
            netuid,
            owner_ss58,
            subnetwork_n,
            max_allowed_uids,
            tempo,
            burn_rao: burn_rao.to_string(),
            burn_tao: format_rao_as_tao(burn_rao),
            emission_rao: emission_rao.to_string(),
            difficulty,
            immunity_period,
        });
    }
    Ok(out)
}

// ── metagraph ─────────────────────────────────────────────────────────

/// Subnet-level header fields returned by `btt subnet metagraph`.
///
/// The upstream `Metagraph<AccountId>` struct has ~50 fields split
/// between subnet-scoped metadata and per-UID parallel arrays. This
/// header surfaces the subnet-scoped fields a user needs to understand
/// which subnet they are looking at. Per-UID data is in `uids`.
#[derive(Serialize, Debug)]
pub struct MetagraphHeader {
    pub netuid: u16,
    /// Subnet human name, decoded from the on-chain `Vec<u8>`. btcli
    /// displays this so users can disambiguate subnets by name; we
    /// pass it through as a UTF-8 string with lossy decoding, so any
    /// non-UTF-8 bytes are replaced with U+FFFD. The authoritative
    /// id is `netuid`, not `name`.
    pub name: String,
    /// Subnet token symbol (e.g. "α1"), same UTF-8 lossy decoding.
    pub symbol: String,
    pub owner_hotkey_ss58: String,
    pub owner_coldkey_ss58: String,
    pub tempo: u16,
    pub num_uids: u16,
    pub max_uids: u16,
    /// Block number at which the metagraph was queried.
    pub at_block: u64,
}

/// One row per UID in the metagraph. The curation is 14 fields: the
/// keys (hotkey + coldkey), the stake (three denominations: total in
/// rao + tao, alpha, tao), and the consensus-weighted metrics that
/// validators use to pick targets (rank, trust, consensus, incentive,
/// dividends, emission). Plus the two bools (active, validator_permit)
/// and last_update for liveness.
///
/// Not included in this first PR: axon info (ip, port), pruning_score,
/// block_at_registration, identity. Those can be folded into a
/// `--detail` flag or a followup PR without breaking the row shape.
///
/// `rank`/`trust`/`consensus`/`incentive`/`dividends` are stored on
/// chain as `u16` with the convention that `u16::MAX` corresponds to
/// `1.0`. We emit the raw u16 here so callers can apply whatever
/// normalization they want; a future `--pretty` renderer can convert
/// to a 0.0-1.0 float for humans.
#[derive(Serialize, Debug)]
pub struct MetagraphUid {
    pub uid: u16,
    pub hotkey_ss58: String,
    pub coldkey_ss58: String,
    pub total_stake_rao: String,
    pub total_stake_tao: String,
    pub alpha_stake_rao: String,
    pub tao_stake_rao: String,
    pub rank: u16,
    pub trust: u16,
    pub consensus: u16,
    pub incentive: u16,
    pub dividends: u16,
    /// Alpha-denominated per-block emission to this UID, stringified
    /// rao.
    pub emission_rao: String,
    pub active: bool,
    pub validator_permit: bool,
    pub last_update: u64,
}

#[derive(Serialize)]
pub struct SubnetMetagraphResult {
    pub header: MetagraphHeader,
    pub uids: Vec<MetagraphUid>,
}

/// Query the full metagraph of a subnet via
/// `SubnetInfoRuntimeApi::get_metagraph(netuid)`. Returns `None` from
/// the runtime if the netuid does not exist; btt translates that to a
/// structured error.
pub async fn metagraph(
    endpoint: &str,
    netuid: u16,
) -> Result<SubnetMetagraphResult, BttError> {
    let api = rpc::connect(endpoint).await?;

    let at_block = tokio::time::timeout(RPC_TIMEOUT, api.at_current_block())
        .await
        .map_err(|_| BttError::query("at_current_block() timed out"))?
        .map_err(|e| BttError::query(format!("failed to resolve client at head: {e}")))?;

    let block_number: u64 = at_block.block_number();

    let call = subxt::dynamic::runtime_api_call::<Vec<SValue>, SValue>(
        "SubnetInfoRuntimeApi",
        "get_metagraph",
        vec![SValue::u128(netuid as u128)],
    );

    let value = tokio::time::timeout(RPC_TIMEOUT, at_block.runtime_apis().call(call))
        .await
        .map_err(|_| BttError::query("get_metagraph timed out"))?
        .map_err(|e| BttError::query(format!("get_metagraph runtime call failed: {e}")))?;

    // `Option<Metagraph>` — None means the netuid does not exist on
    // chain. Peel the Option the same way parse_subnet_info_list does.
    let mg = value.at(0).ok_or_else(|| {
        BttError::query(format!("netuid {netuid} not found on chain"))
    })?;

    parse_metagraph(mg, netuid, block_number)
}

fn parse_metagraph<C: Clone>(
    mg: &Value<C>,
    expected_netuid: u16,
    at_block: u64,
) -> Result<SubnetMetagraphResult, BttError> {
    // ── header ─────────────────────────────────────────────────────
    let netuid = compact_u16(mg, "netuid").ok_or_else(|| {
        BttError::parse("metagraph: missing netuid field")
    })?;
    if netuid != expected_netuid {
        return Err(BttError::parse(format!(
            "metagraph: returned netuid {netuid} does not match requested {expected_netuid}"
        )));
    }

    let name = decode_compact_u8_vec(mg, "name").unwrap_or_default();
    let symbol = decode_compact_u8_vec(mg, "symbol").unwrap_or_default();

    let owner_hotkey = extract_account_id_field(mg, "owner_hotkey").ok_or_else(|| {
        BttError::parse("metagraph: missing owner_hotkey")
    })?;
    let owner_coldkey = extract_account_id_field(mg, "owner_coldkey").ok_or_else(|| {
        BttError::parse("metagraph: missing owner_coldkey")
    })?;
    let owner_hotkey_ss58 = AccountId32::from(owner_hotkey).to_ss58check();
    let owner_coldkey_ss58 = AccountId32::from(owner_coldkey).to_ss58check();

    let tempo = compact_u16(mg, "tempo").ok_or_else(|| {
        BttError::parse("metagraph: missing tempo")
    })?;
    let num_uids = compact_u16(mg, "num_uids").ok_or_else(|| {
        BttError::parse("metagraph: missing num_uids")
    })?;
    let max_uids = compact_u16(mg, "max_uids").ok_or_else(|| {
        BttError::parse("metagraph: missing max_uids")
    })?;

    let header = MetagraphHeader {
        netuid,
        name,
        symbol,
        owner_hotkey_ss58,
        owner_coldkey_ss58,
        tempo,
        num_uids,
        max_uids,
        at_block,
    };

    // ── per-UID parallel arrays ────────────────────────────────────
    //
    // Each field is a Vec of length num_uids. We walk each one into a
    // Vec<T>, then zip them by index into the final Vec<MetagraphUid>.
    //
    // Two of these fields (`rank` and `trust`) are returned as empty
    // Vecs by `get_metagraph` regardless of num_uids. Upstream
    // (`pallets/subtensor/src/rpc_info/metagraph.rs`) hardcodes them
    // to `Vec::new()` with a comment marking them "Deprecated: no
    // longer computed" — the fields are kept in the struct for wire
    // compatibility but the runtime no longer populates them. The
    // adjacent `pruning_score` field is in the same state (also empty
    // per the runtime API observation against testnet netuid 1 on
    // 2026-04-15); btt does not currently surface `pruning_score`
    // but uses the same decode path.
    //
    // `pad_or_check` handles this by backfilling with `T::default()`
    // to num_uids for empty arrays, so the parallel-array indexing
    // stays valid and the output contains zero placeholders which
    // correctly represent the "deprecated, not computed" state. Any
    // OTHER length mismatch (non-zero but != num_uids) IS treated as
    // a hard error — that indicates actual runtime-version drift
    // worth catching, not a deprecated-field no-op.
    let expected = num_uids as usize;

    let hotkeys = pad_or_check(walk_account_vec(mg, "hotkeys")?, expected, "hotkeys")?;
    let coldkeys = pad_or_check(walk_account_vec(mg, "coldkeys")?, expected, "coldkeys")?;
    let total_stakes = pad_or_check(
        walk_compact_u128_vec(mg, "total_stake")?,
        expected,
        "total_stake",
    )?;
    let alpha_stakes = pad_or_check(
        walk_compact_u128_vec(mg, "alpha_stake")?,
        expected,
        "alpha_stake",
    )?;
    let tao_stakes = pad_or_check(
        walk_compact_u128_vec(mg, "tao_stake")?,
        expected,
        "tao_stake",
    )?;
    let ranks = pad_or_check(walk_compact_u16_vec(mg, "rank")?, expected, "rank")?;
    let trusts = pad_or_check(walk_compact_u16_vec(mg, "trust")?, expected, "trust")?;
    let consensus =
        pad_or_check(walk_compact_u16_vec(mg, "consensus")?, expected, "consensus")?;
    let incentives = pad_or_check(
        walk_compact_u16_vec(mg, "incentives")?,
        expected,
        "incentives",
    )?;
    let dividends =
        pad_or_check(walk_compact_u16_vec(mg, "dividends")?, expected, "dividends")?;
    let emissions = pad_or_check(
        walk_compact_u128_vec(mg, "emission")?,
        expected,
        "emission",
    )?;
    let active = pad_or_check(walk_bool_vec(mg, "active")?, expected, "active")?;
    let val_permits = pad_or_check(
        walk_bool_vec(mg, "validator_permit")?,
        expected,
        "validator_permit",
    )?;
    let last_updates = pad_or_check(
        walk_compact_u64_vec(mg, "last_update")?,
        expected,
        "last_update",
    )?;

    let mut uids = Vec::with_capacity(expected);
    for i in 0..expected {
        let total_rao = total_stakes[i];
        uids.push(MetagraphUid {
            uid: i as u16,
            hotkey_ss58: AccountId32::from(hotkeys[i]).to_ss58check(),
            coldkey_ss58: AccountId32::from(coldkeys[i]).to_ss58check(),
            total_stake_rao: total_rao.to_string(),
            total_stake_tao: format_rao_as_tao(total_rao),
            alpha_stake_rao: alpha_stakes[i].to_string(),
            tao_stake_rao: tao_stakes[i].to_string(),
            rank: ranks[i],
            trust: trusts[i],
            consensus: consensus[i],
            incentive: incentives[i],
            dividends: dividends[i],
            emission_rao: emissions[i].to_string(),
            active: active[i],
            validator_permit: val_permits[i],
            last_update: last_updates[i],
        });
    }

    Ok(SubnetMetagraphResult { header, uids })
}

/// Decode a `Vec<Compact<u8>>` value as a lossy UTF-8 String. Used
/// for `name` and `symbol` fields. Returns `None` if the field is
/// missing or any element is not a decodable u8.
fn decode_compact_u8_vec<C: Clone>(composite: &Value<C>, field: &str) -> Option<String> {
    let v = composite.at(field)?;
    let mut bytes = Vec::new();
    let mut idx = 0usize;
    while let Some(entry) = v.at(idx) {
        idx += 1;
        let b = compact_value_to_u128(entry)?;
        if b > 255 {
            return None;
        }
        bytes.push(b as u8);
    }
    Some(String::from_utf8_lossy(&bytes).into_owned())
}

// ── hyperparameters ────────────────────────────────────────────────

/// Full subnet hyperparameter dump returned by `btt subnet hyperparameters --netuid <N>`.
///
/// This is the 27-field upstream `SubnetHyperparams` struct
/// (`pallets/subtensor/src/rpc_info/subnet_info.rs`), surfaced
/// one-for-one. Unlike `subnet list`, where we curate down from 18
/// upstream fields to 9 display fields, a hyperparameters dump is
/// inherently a full dump — users running this command want to see
/// the complete runtime configuration of a subnet, not a tasteful
/// subset. The one transformation we apply is stringifying balances
/// (`min_burn`, `max_burn`) for JSON parser safety.
#[derive(Serialize, Debug)]
pub struct SubnetHyperparamsInfo {
    pub netuid: u16,
    pub rho: u16,
    pub kappa: u16,
    pub immunity_period: u16,
    pub min_allowed_weights: u16,
    pub max_weights_limit: u16,
    pub tempo: u16,
    pub min_difficulty: u64,
    pub max_difficulty: u64,
    pub weights_version: u64,
    pub weights_rate_limit: u64,
    pub adjustment_interval: u16,
    pub activity_cutoff: u16,
    pub registration_allowed: bool,
    pub target_regs_per_interval: u16,
    pub min_burn_rao: String,
    pub max_burn_rao: String,
    pub bonds_moving_avg: u64,
    pub max_regs_per_block: u16,
    pub serving_rate_limit: u64,
    pub max_validators: u16,
    pub adjustment_alpha: u64,
    pub difficulty: u64,
    pub commit_reveal_period: u64,
    pub commit_reveal_weights_enabled: bool,
    pub alpha_high: u16,
    pub alpha_low: u16,
    pub liquid_alpha_enabled: bool,
    /// Block number at which the hyperparameters were queried.
    pub at_block: u64,
}

/// Query the hyperparameters of a subnet via
/// `SubnetInfoRuntimeApi::get_subnet_hyperparams(netuid)`. Returns
/// `None` from the runtime if the netuid does not exist; btt
/// translates that to a structured `QUERY_FAILED` error.
pub async fn hyperparameters(
    endpoint: &str,
    netuid: u16,
) -> Result<SubnetHyperparamsInfo, BttError> {
    let api = rpc::connect(endpoint).await?;

    let at_block = tokio::time::timeout(RPC_TIMEOUT, api.at_current_block())
        .await
        .map_err(|_| BttError::query("at_current_block() timed out"))?
        .map_err(|e| BttError::query(format!("failed to resolve client at head: {e}")))?;

    let block_number: u64 = at_block.block_number();

    let call = subxt::dynamic::runtime_api_call::<Vec<SValue>, SValue>(
        "SubnetInfoRuntimeApi",
        "get_subnet_hyperparams",
        vec![SValue::u128(netuid as u128)],
    );

    let value = tokio::time::timeout(RPC_TIMEOUT, at_block.runtime_apis().call(call))
        .await
        .map_err(|_| BttError::query("get_subnet_hyperparams timed out"))?
        .map_err(|e| {
            BttError::query(format!("get_subnet_hyperparams runtime call failed: {e}"))
        })?;

    // `Option<SubnetHyperparams>` — None means the netuid does not
    // exist on chain. Peel the Option via .at(0).
    let hp = value.at(0).ok_or_else(|| {
        BttError::query(format!("netuid {netuid} not found on chain"))
    })?;

    parse_hyperparams(hp, netuid, block_number)
}

fn parse_hyperparams<C: Clone>(
    hp: &Value<C>,
    netuid: u16,
    at_block: u64,
) -> Result<SubnetHyperparamsInfo, BttError> {
    // Upstream `SubnetHyperparams` does NOT carry a `netuid` field —
    // the netuid is an argument to `get_subnet_hyperparams`, not part
    // of the return shape. We echo it back in the output envelope
    // anyway so the JSON is self-describing.
    let u16_field = |name: &'static str| -> Result<u16, BttError> {
        compact_u16(hp, name).ok_or_else(|| {
            BttError::parse(format!("hyperparameters[netuid={netuid}]: missing {name}"))
        })
    };
    let u64_field = |name: &'static str| -> Result<u64, BttError> {
        compact_u64(hp, name).ok_or_else(|| {
            BttError::parse(format!("hyperparameters[netuid={netuid}]: missing {name}"))
        })
    };
    let u128_field = |name: &'static str| -> Result<u128, BttError> {
        compact_u128(hp, name).ok_or_else(|| {
            BttError::parse(format!("hyperparameters[netuid={netuid}]: missing {name}"))
        })
    };
    let bool_field = |name: &'static str| -> Result<bool, BttError> {
        hp.at(name)
            .and_then(|v| v.as_bool())
            .ok_or_else(|| {
                BttError::parse(format!(
                    "hyperparameters[netuid={netuid}]: missing or non-bool {name}"
                ))
            })
    };

    Ok(SubnetHyperparamsInfo {
        netuid,
        rho: u16_field("rho")?,
        kappa: u16_field("kappa")?,
        immunity_period: u16_field("immunity_period")?,
        min_allowed_weights: u16_field("min_allowed_weights")?,
        max_weights_limit: u16_field("max_weights_limit")?,
        tempo: u16_field("tempo")?,
        min_difficulty: u64_field("min_difficulty")?,
        max_difficulty: u64_field("max_difficulty")?,
        weights_version: u64_field("weights_version")?,
        weights_rate_limit: u64_field("weights_rate_limit")?,
        adjustment_interval: u16_field("adjustment_interval")?,
        activity_cutoff: u16_field("activity_cutoff")?,
        registration_allowed: bool_field("registration_allowed")?,
        target_regs_per_interval: u16_field("target_regs_per_interval")?,
        min_burn_rao: u128_field("min_burn")?.to_string(),
        max_burn_rao: u128_field("max_burn")?.to_string(),
        bonds_moving_avg: u64_field("bonds_moving_avg")?,
        max_regs_per_block: u16_field("max_regs_per_block")?,
        serving_rate_limit: u64_field("serving_rate_limit")?,
        max_validators: u16_field("max_validators")?,
        adjustment_alpha: u64_field("adjustment_alpha")?,
        difficulty: u64_field("difficulty")?,
        commit_reveal_period: u64_field("commit_reveal_period")?,
        commit_reveal_weights_enabled: bool_field("commit_reveal_weights_enabled")?,
        alpha_high: u16_field("alpha_high")?,
        alpha_low: u16_field("alpha_low")?,
        liquid_alpha_enabled: bool_field("liquid_alpha_enabled")?,
        at_block,
    })
}

// ── per-UID vec walkers ───────────────────────────────────────────

/// Normalize a per-UID Vec against the expected length. Three cases:
/// - `got == expected`: pass through unchanged.
/// - `got == 0` and `expected > 0`: backfill with `T::default()` to
///   `expected` elements. This accommodates the runtime returning
///   empty Vecs for fields whose storage has not yet been populated
///   (e.g. `rank`, `trust`, `pruning_score` on a subnet whose epoch
///   has not yet computed these values). The parallel-array indexing
///   stays valid and the output contains zero placeholders which
///   correctly represent the "not yet computed" state.
/// - any other mismatch: hard error. A non-zero length that still
///   doesn't match `num_uids` is runtime-version drift worth catching.
fn pad_or_check<T: Default + Clone>(
    got: Vec<T>,
    expected: usize,
    field: &str,
) -> Result<Vec<T>, BttError> {
    if got.len() == expected {
        Ok(got)
    } else if got.is_empty() {
        Ok(vec![T::default(); expected])
    } else {
        Err(BttError::parse(format!(
            "metagraph: per-UID array `{field}` has {got_len} elements, expected {expected} (num_uids) or 0",
            got_len = got.len()
        )))
    }
}

fn walk_account_vec<C: Clone>(mg: &Value<C>, field: &str) -> Result<Vec<[u8; 32]>, BttError> {
    let v = mg.at(field).ok_or_else(|| {
        BttError::parse(format!("metagraph: missing vec field `{field}`"))
    })?;
    let mut out = Vec::new();
    let mut idx = 0usize;
    while let Some(entry) = v.at(idx) {
        idx += 1;
        let bytes = {
            // Try the wrapped-tuple-struct shape first (AccountId32
            // as a single-field composite wrapping [u8; 32]) and
            // fall back to the raw byte array.
            if let Some(inner) = entry.at(0) {
                value_to_32_bytes(inner)
            } else {
                value_to_32_bytes(entry)
            }
        }
        .ok_or_else(|| {
            BttError::parse(format!(
                "metagraph: `{field}`[{}] is not a decodable 32-byte account id",
                idx - 1
            ))
        })?;
        out.push(bytes);
    }
    Ok(out)
}

fn walk_compact_u16_vec<C: Clone>(mg: &Value<C>, field: &str) -> Result<Vec<u16>, BttError> {
    walk_compact_numeric_vec(mg, field, |n| u16::try_from(n).ok())
}

fn walk_compact_u64_vec<C: Clone>(mg: &Value<C>, field: &str) -> Result<Vec<u64>, BttError> {
    walk_compact_numeric_vec(mg, field, |n| u64::try_from(n).ok())
}

fn walk_compact_u128_vec<C: Clone>(mg: &Value<C>, field: &str) -> Result<Vec<u128>, BttError> {
    walk_compact_numeric_vec(mg, field, Some)
}

fn walk_compact_numeric_vec<C: Clone, T>(
    mg: &Value<C>,
    field: &str,
    coerce: impl Fn(u128) -> Option<T>,
) -> Result<Vec<T>, BttError> {
    let v = mg.at(field).ok_or_else(|| {
        BttError::parse(format!("metagraph: missing vec field `{field}`"))
    })?;
    let mut out = Vec::new();
    let mut idx = 0usize;
    while let Some(entry) = v.at(idx) {
        idx += 1;
        let n = compact_value_to_u128(entry).ok_or_else(|| {
            BttError::parse(format!(
                "metagraph: `{field}`[{}] is not a decodable integer",
                idx - 1
            ))
        })?;
        let typed = coerce(n).ok_or_else(|| {
            BttError::parse(format!(
                "metagraph: `{field}`[{}] value {n} out of range for target type",
                idx - 1
            ))
        })?;
        out.push(typed);
    }
    Ok(out)
}

fn walk_bool_vec<C: Clone>(mg: &Value<C>, field: &str) -> Result<Vec<bool>, BttError> {
    let v = mg.at(field).ok_or_else(|| {
        BttError::parse(format!("metagraph: missing vec field `{field}`"))
    })?;
    let mut out = Vec::new();
    let mut idx = 0usize;
    while let Some(entry) = v.at(idx) {
        idx += 1;
        // scale-value represents booleans as Primitive::Bool under
        // ValueDef::Primitive. Access via the primitive converter.
        let b = entry.as_bool().ok_or_else(|| {
            BttError::parse(format!(
                "metagraph: `{field}`[{}] is not a bool",
                idx - 1
            ))
        })?;
        out.push(b);
    }
    Ok(out)
}

// ── decoder helpers ────────────────────────────────────────────────────
//
// These helpers intentionally duplicate the shape of the helpers in
// `stake.rs`. Consolidating them into a shared module under
// `src/commands/` is tracked by issue #93 as a pure refactor PR;
// doing it inline here would creep scope across two commands.

/// Extract a `Compact<u*>` field from a composite, coerced to u16.
/// Fails if the field is missing, not a primitive, or exceeds u16 range.
fn compact_u16<C: Clone>(composite: &Value<C>, field: &str) -> Option<u16> {
    let v = composite.at(field)?;
    compact_value_to_u128(v).and_then(|n| u16::try_from(n).ok())
}

/// Same, coerced to u64.
fn compact_u64<C: Clone>(composite: &Value<C>, field: &str) -> Option<u64> {
    let v = composite.at(field)?;
    compact_value_to_u128(v).and_then(|n| u64::try_from(n).ok())
}

/// Same, left as u128 (for balances).
fn compact_u128<C: Clone>(composite: &Value<C>, field: &str) -> Option<u128> {
    let v = composite.at(field)?;
    compact_value_to_u128(v)
}

/// The SCALE-value representation of a `Compact<T>` is a single-field
/// composite wrapping the inner primitive. Walk the wrapper if
/// present, otherwise read the primitive directly — both shapes show
/// up in the wild depending on how the codec flattens on that runtime
/// version.
fn compact_value_to_u128<C: Clone>(v: &Value<C>) -> Option<u128> {
    if let Some(n) = v.as_u128() {
        return Some(n);
    }
    if let subxt::ext::scale_value::ValueDef::Composite(c) = &v.value {
        let values: Vec<&Value<C>> = c.values().collect();
        if values.len() == 1 {
            return compact_value_to_u128(values[0]);
        }
    }
    None
}

/// Pull a 32-byte AccountId out of a named field. Mirrors the helper
/// in `stake.rs`; see the note above about consolidation.
fn extract_account_id_field<C: Clone>(entry: &Value<C>, field: &str) -> Option<[u8; 32]> {
    let field_val = entry.at(field)?;
    if let Some(inner) = field_val.at(0) {
        if let Some(bytes) = value_to_32_bytes(inner) {
            return Some(bytes);
        }
    }
    value_to_32_bytes(field_val)
}

fn value_to_32_bytes<C: Clone>(value: &Value<C>) -> Option<[u8; 32]> {
    let mut bytes = Vec::with_capacity(32);
    let mut idx = 0usize;
    while let Some(v) = value.at(idx) {
        let b = v.as_u128()?;
        if b > 255 {
            return None;
        }
        bytes.push(b as u8);
        idx += 1;
        if bytes.len() > 32 {
            return None;
        }
    }
    if bytes.len() == 32 {
        let mut arr = [0u8; 32];
        arr.copy_from_slice(&bytes);
        Some(arr)
    } else {
        None
    }
}

/// Walk a decoded `scale_value::Value` looking for a u128-compatible
/// integer. Accepts either the bare-integer shape or a single-field
/// composite wrapping one (the SCALE-Value codec occasionally produces
/// the latter for tuple-struct newtypes).
fn extract_balance_u128<C>(v: &subxt::dynamic::Value<C>) -> Option<u128> {
    if let Some(n) = v.as_u128() {
        return Some(n);
    }
    // Composite case: exactly one field, recurse.
    if let subxt::ext::scale_value::ValueDef::Composite(c) = &v.value {
        let values: Vec<&subxt::dynamic::Value<C>> = c.values().collect();
        if values.len() == 1 {
            return extract_balance_u128(values[0]);
        }
    }
    None
}

/// Format a rao integer (u128) as a decimal TAO string with 9 fractional
/// digits. The string representation is stable across hosts — no
/// floating-point conversion is performed, so the returned value is
/// exact to the last rao.
fn format_rao_as_tao(rao: u128) -> String {
    const RAO_PER_TAO: u128 = 1_000_000_000;
    let whole = rao / RAO_PER_TAO;
    let frac = rao % RAO_PER_TAO;
    format!("{whole}.{frac:09}")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn format_rao_zero() {
        assert_eq!(format_rao_as_tao(0), "0.000000000");
    }

    #[test]
    fn format_rao_one_tao() {
        assert_eq!(format_rao_as_tao(1_000_000_000), "1.000000000");
    }

    #[test]
    fn format_rao_one_rao() {
        assert_eq!(format_rao_as_tao(1), "0.000000001");
    }

    #[test]
    fn format_rao_mixed() {
        // 2500 TAO exactly: the current default lock cost after the
        // migrate_network_lock_cost_2500 upstream migration.
        assert_eq!(format_rao_as_tao(2_500_000_000_000), "2500.000000000");
    }

    #[test]
    fn format_rao_large_with_fraction() {
        // 1.234567890 TAO.
        assert_eq!(format_rao_as_tao(1_234_567_890), "1.234567890");
    }

    #[test]
    fn format_rao_u128_max_does_not_panic() {
        // Sanity: the format routine handles the full u128 range without
        // overflow. u128::MAX in rao is ~3.4e29 TAO, which is absurd but
        // defensible — the function is a formatter, not a policy.
        let _ = format_rao_as_tao(u128::MAX);
    }
}
