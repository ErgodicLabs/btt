//! Shared helpers for walking `scale_value::Value` trees that come back
//! from `subxt::dynamic::runtime_api_call(...)` and
//! `subxt::dynamic::storage(...)` calls.
//!
//! Every command module that hits the chain with a dynamic API
//! eventually needs the same small set of primitives: pull a
//! `Compact<T>`-wrapped integer out of a named field, peel a 32-byte
//! `AccountId32` out of whatever shape scale-value happens to surface
//! it as, walk a `Vec<Compact<T>>` into a `Vec<T>`, and normalize
//! parallel per-row arrays whose upstream producer may have left one
//! of them empty as a deprecated-field placeholder.
//!
//! Before this module, `stake.rs` had its own copies of
//! `extract_account_id_field`, `value_to_32_bytes`, and `value_to_u64`;
//! `subnet.rs` had those same three plus eleven more (`compact_u16`,
//! `compact_u64`, `compact_u128`, `compact_value_to_u128`,
//! `decode_compact_u8_vec`, `pad_or_check`, `walk_account_vec`,
//! `walk_compact_u16_vec`, `walk_compact_u64_vec`, `walk_compact_u128_vec`,
//! `walk_compact_numeric_vec`, `walk_bool_vec`, `extract_balance_u128`).
//! 14 helpers total, duplicated across two files. Issue #93 consolidates
//! them here so a future chain-touching command can `use
//! crate::commands::dynamic_decode::*` and skip the copy-paste.
//!
//! This is a pure refactor. Zero behavior change — every helper's body
//! is moved unchanged from its original site, and the original sites
//! are converted into `use` imports.

use sp_core::crypto::{AccountId32, Ss58Codec};
use subxt::dynamic::{At, Value};

use crate::error::BttError;

// ── scalar integer extractors ─────────────────────────────────────────

/// Extract a `Compact<u*>` field from a composite, coerced to u16.
/// Fails if the field is missing, not a primitive, or exceeds u16 range.
pub(crate) fn compact_u16<C: Clone>(composite: &Value<C>, field: &str) -> Option<u16> {
    let v = composite.at(field)?;
    compact_value_to_u128(v).and_then(|n| u16::try_from(n).ok())
}

/// Same, coerced to u64.
pub(crate) fn compact_u64<C: Clone>(composite: &Value<C>, field: &str) -> Option<u64> {
    let v = composite.at(field)?;
    compact_value_to_u128(v).and_then(|n| u64::try_from(n).ok())
}

/// Same, left as u128 (for balances).
pub(crate) fn compact_u128<C: Clone>(composite: &Value<C>, field: &str) -> Option<u128> {
    let v = composite.at(field)?;
    compact_value_to_u128(v)
}

/// The SCALE-value representation of a `Compact<T>` is a single-field
/// composite wrapping the inner primitive. Walk the wrapper if
/// present, otherwise read the primitive directly — both shapes show
/// up in the wild depending on how the codec flattens on that runtime
/// version.
pub(crate) fn compact_value_to_u128<C: Clone>(v: &Value<C>) -> Option<u128> {
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

/// Coerce a scale-value primitive into a u64. Convenience wrapper on
/// `compact_value_to_u128` with a `u64::try_from`; accepts both
/// `Primitive(U128(n))` and `Composite(Unnamed([U128(n)]))` (the
/// Compact-wrapping shape).
pub(crate) fn value_to_u64<C: Clone>(value: &Value<C>) -> Option<u64> {
    compact_value_to_u128(value).and_then(|n| u64::try_from(n).ok())
}

/// Walk a decoded `scale_value::Value` looking for a u128-compatible
/// integer. Accepts either the bare-integer shape or a single-field
/// composite wrapping one (the SCALE-Value codec occasionally produces
/// the latter for tuple-struct newtypes).
///
/// Effectively identical in behavior to `compact_value_to_u128`; kept
/// as a separate name because the two have slightly different call
/// sites (balances via runtime-api return vs compact-wrapped field
/// reads). Consider deprecating one in a future cleanup if they prove
/// equivalent in practice.
pub(crate) fn extract_balance_u128<C: Clone>(v: &Value<C>) -> Option<u128> {
    compact_value_to_u128(v)
}

// ── AccountId32 / byte-array extractors ───────────────────────────────

/// Pull a 32-byte AccountId out of a named field. scale-value can
/// surface an `AccountId32` as either a single-field tuple struct
/// wrapping `[u8; 32]` or as the raw byte array directly; the helper
/// tries both shapes.
pub(crate) fn extract_account_id_field<C: Clone>(
    entry: &Value<C>,
    field: &str,
) -> Option<[u8; 32]> {
    let field_val = entry.at(field)?;
    // Try: AccountId -> inner tuple (.0) -> [u8; 32]
    if let Some(inner) = field_val.at(0) {
        if let Some(bytes) = value_to_32_bytes(inner) {
            return Some(bytes);
        }
    }
    // Fallback: field is directly the byte array
    value_to_32_bytes(field_val)
}

/// Try to coerce a Value into 32 bytes. Accepts a sequence-of-u8
/// composite (the subxt dynamic representation of `[u8; 32]`). Returns
/// `None` for shorter or longer sequences.
pub(crate) fn value_to_32_bytes<C: Clone>(value: &Value<C>) -> Option<[u8; 32]> {
    let mut bytes = Vec::with_capacity(32);
    let mut idx = 0usize;
    while let Some(v) = value.at(idx) {
        let b = value_to_u64(v)?;
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

/// Convenience: extract a 32-byte account and ss58-encode it in one
/// step. Returns `None` if the field is missing or malformed. Used by
/// per-UID walkers that need ss58 strings for output rather than raw
/// bytes for further manipulation.
///
/// Not currently used outside this module; exposed because it is a
/// natural pair for `extract_account_id_field` and the ss58 encode is
/// the same `AccountId32::from(bytes).to_ss58check()` pattern every
/// caller writes inline.
#[allow(dead_code)]
pub(crate) fn extract_account_id_ss58<C: Clone>(
    entry: &Value<C>,
    field: &str,
) -> Option<String> {
    extract_account_id_field(entry, field).map(|b| AccountId32::from(b).to_ss58check())
}

// ── per-UID / per-row Vec walkers ────────────────────────────────────

/// Decode a `Vec<Compact<u8>>` value as a lossy UTF-8 String. Used
/// for `name` and `symbol` fields on Metagraph. Returns `None` if the
/// field is missing or any element is not a decodable u8.
pub(crate) fn decode_compact_u8_vec<C: Clone>(
    composite: &Value<C>,
    field: &str,
) -> Option<String> {
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

/// Normalize a per-UID `Vec<T>` against the expected length. Three cases:
///
/// - `got == expected`: pass through unchanged.
/// - `got == 0` and `expected > 0`: backfill with `T::default()` to
///   `expected` elements. This accommodates the runtime returning
///   empty Vecs for fields whose storage has been deprecated
///   upstream (e.g. `rank`, `trust`, `pruning_score` on Metagraph
///   since the 2026 epoch-consensus rewrite).
/// - any other mismatch: hard error. A non-zero length that still
///   does not match `num_uids` is runtime-version drift worth
///   catching, not silently truncating or padding.
pub(crate) fn pad_or_check<T: Default + Clone>(
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
            "per-row array `{field}` has {got_len} elements, expected {expected} or 0",
            got_len = got.len()
        )))
    }
}

/// Walk a `Vec<AccountId32>` field into `Vec<[u8; 32]>`. Errors if the
/// field is missing or any element fails to decode as 32 bytes.
pub(crate) fn walk_account_vec<C: Clone>(
    mg: &Value<C>,
    field: &str,
) -> Result<Vec<[u8; 32]>, BttError> {
    let v = mg
        .at(field)
        .ok_or_else(|| BttError::parse(format!("missing vec field `{field}`")))?;
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
                "`{field}`[{}] is not a decodable 32-byte account id",
                idx - 1
            ))
        })?;
        out.push(bytes);
    }
    Ok(out)
}

/// u16-typed wrapper around `walk_compact_numeric_vec`.
pub(crate) fn walk_compact_u16_vec<C: Clone>(
    mg: &Value<C>,
    field: &str,
) -> Result<Vec<u16>, BttError> {
    walk_compact_numeric_vec(mg, field, |n| u16::try_from(n).ok())
}

/// u64-typed wrapper.
pub(crate) fn walk_compact_u64_vec<C: Clone>(
    mg: &Value<C>,
    field: &str,
) -> Result<Vec<u64>, BttError> {
    walk_compact_numeric_vec(mg, field, |n| u64::try_from(n).ok())
}

/// u128-typed wrapper — identity coerce, for balances.
pub(crate) fn walk_compact_u128_vec<C: Clone>(
    mg: &Value<C>,
    field: &str,
) -> Result<Vec<u128>, BttError> {
    walk_compact_numeric_vec(mg, field, Some)
}

/// Generic walker: pull every element of a `Vec<Compact<T>>` field
/// out as a u128 and coerce it to `T` via the caller-supplied closure.
/// Used by the three `walk_compact_uN_vec` thin wrappers.
pub(crate) fn walk_compact_numeric_vec<C: Clone, T>(
    mg: &Value<C>,
    field: &str,
    coerce: impl Fn(u128) -> Option<T>,
) -> Result<Vec<T>, BttError> {
    let v = mg
        .at(field)
        .ok_or_else(|| BttError::parse(format!("missing vec field `{field}`")))?;
    let mut out = Vec::new();
    let mut idx = 0usize;
    while let Some(entry) = v.at(idx) {
        idx += 1;
        let n = compact_value_to_u128(entry).ok_or_else(|| {
            BttError::parse(format!(
                "`{field}`[{}] is not a decodable integer",
                idx - 1
            ))
        })?;
        let typed = coerce(n).ok_or_else(|| {
            BttError::parse(format!(
                "`{field}`[{}] value {n} out of range for target type",
                idx - 1
            ))
        })?;
        out.push(typed);
    }
    Ok(out)
}

/// Walk a `Vec<bool>` field.
pub(crate) fn walk_bool_vec<C: Clone>(
    mg: &Value<C>,
    field: &str,
) -> Result<Vec<bool>, BttError> {
    let v = mg
        .at(field)
        .ok_or_else(|| BttError::parse(format!("missing vec field `{field}`")))?;
    let mut out = Vec::new();
    let mut idx = 0usize;
    while let Some(entry) = v.at(idx) {
        idx += 1;
        let b = entry
            .as_bool()
            .ok_or_else(|| BttError::parse(format!("`{field}`[{}] is not a bool", idx - 1)))?;
        out.push(b);
    }
    Ok(out)
}
