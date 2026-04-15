// Subnet commands. Phase 1 (issue #77) is read-only.
//
// Ships so far: `lock-cost` (PR #91), `list` (this PR). Remaining
// phase-1 commands: `metagraph --netuid <N>`, `hyperparameters --netuid
// <N>`. All four call into `SubnetInfoRuntimeApi` / `SubnetRegistration
// RuntimeApi` — pure runtime state queries, no extrinsics, no wallet
// material, no trust-sensitive surface. Phase 2 of issue #77 is
// reserved for write commands (`subnet register`, `subnet create`,
// etc.) and will be its own issue + PRs.

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
