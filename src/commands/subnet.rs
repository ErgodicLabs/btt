// Subnet commands. Phase 1 (issue #77) is read-only: `lock-cost`
// ships in this PR as the first command; `list`, `metagraph`, and
// `hyperparameters` land in follow-ups.
//
// All commands in this module are pure runtime state queries. They do
// not submit extrinsics, require wallet material, or touch any
// trust-sensitive surface. Phase 2 of issue #77 is reserved for write
// commands (`subnet register`, `subnet create`, etc.) and will be its
// own issue + PRs.

use std::time::Duration;

use serde::Serialize;
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
