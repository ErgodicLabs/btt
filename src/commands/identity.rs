use std::time::Duration;

use serde::Serialize;
use sp_core::Pair as PairTrait;
use subxt::dynamic::{At, Value};
use subxt::ext::scale_value::Value as SValue;

use crate::commands::chain::parse_ss58;
use crate::commands::dynamic_decode::value_to_u64;
use crate::commands::stake::Sr25519Signer;
use crate::commands::wallet_keys::decrypt_coldkey_interactive;
use crate::error::BttError;
use crate::rpc;

const RPC_TIMEOUT: Duration = Duration::from_secs(30);

#[derive(Serialize)]
pub struct IdentityInfo {
    pub address: String,
    pub name: String,
    pub url: String,
    pub description: String,
    pub image: String,
    pub discord: String,
    pub github_repo: String,
    pub github_username: String,
}

fn value_to_string<C: Clone>(val: &Value<C>) -> String {
    let mut bytes = Vec::new();
    let mut idx = 0usize;
    while let Some(v) = val.at(idx) {
        if let Some(b) = value_to_u64(v) {
            if b <= 255 {
                bytes.push(b as u8);
            }
        }
        idx += 1;
    }
    String::from_utf8(bytes).unwrap_or_default()
}

fn extract_identity_field<C: Clone>(val: &Value<C>, field: &str) -> String {
    match val.at(field) {
        Some(v) => value_to_string(v),
        None => String::new(),
    }
}

pub async fn get_identity(endpoint: &str, address: &str) -> Result<IdentityInfo, BttError> {
    let account_id_bytes = parse_ss58(address)?;

    let api = rpc::connect(endpoint).await?;

    let storage_query =
        subxt::dynamic::storage::<Vec<SValue>, SValue>("SubtensorModule", "Identities");

    let at_block = tokio::time::timeout(RPC_TIMEOUT, api.at_current_block())
        .await
        .map_err(|_| BttError::query("storage query timed out"))?
        .map_err(|e| BttError::query(format!("failed to get block: {e}")))?;

    let storage = at_block.storage();

    let result = tokio::time::timeout(
        RPC_TIMEOUT,
        storage.try_fetch(&storage_query, vec![SValue::from_bytes(account_id_bytes)]),
    )
    .await
    .map_err(|_| BttError::query("identity fetch timed out"))?
    .map_err(|e| BttError::query(format!("failed to fetch identity: {e}")))?;

    match result {
        Some(value) => {
            let decoded = value
                .decode()
                .map_err(|e| BttError::parse(format!("failed to decode identity: {e}")))?;

            Ok(IdentityInfo {
                address: address.to_string(),
                name: extract_identity_field(&decoded, "name"),
                url: extract_identity_field(&decoded, "url"),
                description: extract_identity_field(&decoded, "description"),
                image: extract_identity_field(&decoded, "image"),
                discord: extract_identity_field(&decoded, "discord"),
                github_repo: extract_identity_field(&decoded, "github_repo"),
                github_username: extract_identity_field(&decoded, "github_username"),
            })
        }
        None => Ok(IdentityInfo {
            address: address.to_string(),
            name: String::new(),
            url: String::new(),
            description: String::new(),
            image: String::new(),
            discord: String::new(),
            github_repo: String::new(),
            github_username: String::new(),
        }),
    }
}

#[derive(Serialize)]
pub struct SetIdentityResult {
    pub tx_hash: String,
    pub block: String,
    pub address: String,
    pub name: String,
}

pub struct SetIdentityFields<'a> {
    pub display_name: &'a str,
    pub url: &'a str,
    pub description: &'a str,
    pub image: &'a str,
    pub discord: &'a str,
    pub github_repo: &'a str,
    pub github_username: &'a str,
}

pub async fn set_identity(
    endpoint: &str,
    wallet: &str,
    fields: SetIdentityFields<'_>,
) -> Result<SetIdentityResult, BttError> {
    let pair = decrypt_coldkey_interactive(wallet)?;
    let from_ss58 = sp_core::crypto::AccountId32::from(PairTrait::public(&pair)).to_string();
    let signer = Sr25519Signer::new(pair);

    let api = rpc::connect(endpoint).await?;

    let tx = subxt::dynamic::tx(
        "SubtensorModule",
        "set_identity",
        vec![
            SValue::string(fields.display_name),
            SValue::string(fields.url),
            SValue::string(fields.image),
            SValue::string(fields.discord),
            SValue::string(fields.description),
            SValue::string(""),
            SValue::string(fields.github_repo),
            SValue::string(fields.github_username),
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

    Ok(SetIdentityResult {
        tx_hash,
        block: block_hash,
        address: from_ss58,
        name: fields.display_name.to_string(),
    })
}
