use serde::Serialize;
use std::fmt;

/// Structured error codes for machine-readable output.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
#[allow(dead_code)]
pub enum ErrorCode {
    ConnectionFailed,
    InvalidAddress,
    QueryFailed,
    WalletNotFound,
    IoError,
    ParseError,
    CryptoError,
    InvalidInput,
    SigningFailed,
    SubmissionFailed,
    DecryptionFailed,
    InvalidAmount,
    Unknown,
}

impl fmt::Display for ErrorCode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = serde_json::to_value(self)
            .ok()
            .and_then(|v| v.as_str().map(String::from))
            .unwrap_or_else(|| format!("{:?}", self));
        write!(f, "{}", s)
    }
}

/// A structured error that serializes to JSON.
#[derive(Debug, Serialize)]
pub struct BttError {
    pub code: ErrorCode,
    pub message: String,
}

impl BttError {
    pub fn new(code: ErrorCode, message: impl Into<String>) -> Self {
        Self {
            code,
            message: message.into(),
        }
    }

    pub fn connection(msg: impl Into<String>) -> Self {
        Self::new(ErrorCode::ConnectionFailed, msg)
    }

    pub fn query(msg: impl Into<String>) -> Self {
        Self::new(ErrorCode::QueryFailed, msg)
    }

    pub fn invalid_address(msg: impl Into<String>) -> Self {
        Self::new(ErrorCode::InvalidAddress, msg)
    }

    pub fn wallet_not_found(msg: impl Into<String>) -> Self {
        Self::new(ErrorCode::WalletNotFound, msg)
    }

    pub fn io(msg: impl Into<String>) -> Self {
        Self::new(ErrorCode::IoError, msg)
    }

    pub fn parse(msg: impl Into<String>) -> Self {
        Self::new(ErrorCode::ParseError, msg)
    }

    pub fn crypto(msg: impl Into<String>) -> Self {
        Self::new(ErrorCode::CryptoError, msg)
    }

    pub fn invalid_input(msg: impl Into<String>) -> Self {
        Self::new(ErrorCode::InvalidInput, msg)
    }

    #[allow(dead_code)]
    pub fn signing_failed(msg: impl Into<String>) -> Self {
        Self::new(ErrorCode::SigningFailed, msg)
    }

    pub fn submission_failed(msg: impl Into<String>) -> Self {
        Self::new(ErrorCode::SubmissionFailed, msg)
    }

    #[allow(dead_code)]
    pub fn decryption_failed(msg: impl Into<String>) -> Self {
        Self::new(ErrorCode::DecryptionFailed, msg)
    }

    pub fn invalid_amount(msg: impl Into<String>) -> Self {
        Self::new(ErrorCode::InvalidAmount, msg)
    }
}

impl fmt::Display for BttError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "[{}] {}", self.code, self.message)
    }
}

impl std::error::Error for BttError {}
