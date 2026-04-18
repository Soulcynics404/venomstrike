use thiserror::Error;

#[derive(Error, Debug)]
pub enum VenomError {
    #[error("HTTP request failed: {0}")]
    HttpError(#[from] reqwest::Error),

    #[error("URL parse error: {0}")]
    UrlError(#[from] url::ParseError),

    #[error("IO error: {0}")]
    IoError(#[from] std::io::Error),

    #[error("JSON error: {0}")]
    JsonError(#[from] serde_json::Error),

    #[error("CSV error: {0}")]
    CsvError(#[from] csv::Error),

    #[error("DNS resolution failed: {0}")]
    DnsError(String),

    #[error("Target out of scope: {0}")]
    ScopeError(String),

    #[error("Rate limit exceeded")]
    RateLimitError,

    #[error("Scanner error: {0}")]
    ScannerError(String),

    #[error("Configuration error: {0}")]
    ConfigError(String),

    #[error("Report generation error: {0}")]
    ReportError(String),

    #[error("CVE lookup error: {0}")]
    CveError(String),

    #[error("Timeout: {0}")]
    TimeoutError(String),
}

pub type VenomResult<T> = Result<T, VenomError>;