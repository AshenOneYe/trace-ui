use thiserror::Error;

#[derive(Debug, Error)]
pub enum TraceError {
    #[error("session not found: {0}")]
    SessionNotFound(String),

    #[error("index not built, call build_index first")]
    IndexNotReady,

    #[error("operation already in progress: {0}")]
    OperationInProgress(String),

    #[error("invalid argument: {0}")]
    InvalidArgument(String),

    #[error("parse error at line {line:?}: {detail}")]
    ParseError { line: Option<u32>, detail: String },

    #[error("cache error: {0}")]
    CacheError(String),

    #[error("io error: {0}")]
    Io(#[from] std::io::Error),

    #[error("operation cancelled")]
    Cancelled,

    #[error("resource budget exceeded: {0}")]
    ResourceBudgetExceeded(String),

    #[error("internal error: {0}")]
    Internal(String),
}

pub type Result<T> = std::result::Result<T, TraceError>;
