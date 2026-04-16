use std::time::Instant;

use serde::Serialize;

use crate::error::BttError;
use crate::rpc;

const RAO_PER_TAO: u64 = 1_000_000_000;

#[derive(Serialize)]
pub struct ConvertResult {
    pub tao: String,
    pub rao: u64,
}

pub fn convert_rao_to_tao(rao: u64) -> ConvertResult {
    let whole = rao / RAO_PER_TAO;
    let frac = rao % RAO_PER_TAO;
    ConvertResult {
        tao: format!("{whole}.{frac:09}"),
        rao,
    }
}

pub fn convert_tao_to_rao(tao: f64) -> Result<ConvertResult, BttError> {
    if tao < 0.0 {
        return Err(BttError::invalid_amount("TAO amount cannot be negative"));
    }
    if !tao.is_finite() {
        return Err(BttError::invalid_amount(
            "TAO amount must be a finite number",
        ));
    }
    let rao = (tao * RAO_PER_TAO as f64).round() as u64;
    Ok(ConvertResult {
        tao: format!("{}.{:09}", rao / RAO_PER_TAO, rao % RAO_PER_TAO),
        rao,
    })
}

#[derive(Serialize)]
pub struct LatencyResult {
    pub endpoint: String,
    pub latency_ms: f64,
    pub block_number: Option<u64>,
}

pub async fn latency(endpoint: &str) -> Result<LatencyResult, BttError> {
    let start = Instant::now();
    let api = rpc::connect(endpoint).await?;

    let at_block = api
        .at_current_block()
        .await
        .map_err(|e| BttError::connection(format!("failed to fetch latest block: {e}")))?;

    let elapsed = start.elapsed();
    let block_number: u64 = at_block.block_number();

    Ok(LatencyResult {
        endpoint: endpoint.to_string(),
        latency_ms: elapsed.as_secs_f64() * 1000.0,
        block_number: Some(block_number),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn convert_zero_rao() {
        let r = convert_rao_to_tao(0);
        assert_eq!(r.rao, 0);
        assert_eq!(r.tao, "0.000000000");
    }

    #[test]
    fn convert_one_tao_in_rao() {
        let r = convert_rao_to_tao(1_000_000_000);
        assert_eq!(r.tao, "1.000000000");
    }

    #[test]
    fn convert_fractional_rao() {
        let r = convert_rao_to_tao(1_500_000_000);
        assert_eq!(r.tao, "1.500000000");
    }

    #[test]
    fn convert_tao_to_rao_basic() {
        let r = convert_tao_to_rao(1.0).expect("1.0 TAO is valid");
        assert_eq!(r.rao, 1_000_000_000);
    }

    #[test]
    fn convert_tao_to_rao_fractional() {
        let r = convert_tao_to_rao(0.5).expect("0.5 TAO is valid");
        assert_eq!(r.rao, 500_000_000);
    }

    #[test]
    fn convert_tao_to_rao_negative() {
        assert!(convert_tao_to_rao(-1.0).is_err());
    }

    #[test]
    fn convert_tao_to_rao_infinity() {
        assert!(convert_tao_to_rao(f64::INFINITY).is_err());
    }

    #[test]
    fn convert_tao_to_rao_nan() {
        assert!(convert_tao_to_rao(f64::NAN).is_err());
    }
}
