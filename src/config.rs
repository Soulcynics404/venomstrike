use serde::{Deserialize, Serialize};
use std::path::PathBuf;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AppConfig {
    pub target: TargetConfig,
    pub scanning: ScanningConfig,
    pub rate_limit: RateLimitConfig,
    pub output: OutputConfig,
    pub api_keys: ApiKeysConfig,
    pub payloads: PayloadsConfig,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TargetConfig {
    pub url: String,
    pub scope: Vec<String>,
    pub exclude: Vec<String>,
    pub max_depth: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanningConfig {
    pub threads: usize,
    pub timeout_secs: u64,
    pub follow_redirects: bool,
    pub max_redirects: usize,
    pub user_agent: String,
    pub proxy: Option<String>,
    pub phases: Vec<String>,
    pub enable_nmap: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RateLimitConfig {
    pub requests_per_second: u32,
    pub burst_size: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OutputConfig {
    pub directory: PathBuf,
    pub formats: Vec<String>,
    pub verbose: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApiKeysConfig {
    pub nvd_api_key: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PayloadsConfig {
    pub xss: PathBuf,
    pub sqli: PathBuf,
    pub lfi: PathBuf,
    pub ssti: PathBuf,
    pub ssrf: PathBuf,
    pub cmdi: PathBuf,
    pub subdomains: PathBuf,
    pub open_redirect: PathBuf,
}

impl Default for AppConfig {
    fn default() -> Self {
        Self {
            target: TargetConfig {
                url: String::new(),
                scope: vec![],
                exclude: vec![],
                max_depth: 3,
            },
            scanning: ScanningConfig {
                threads: 10,
                timeout_secs: 30,
                follow_redirects: true,
                max_redirects: 5,
                user_agent: "VenomStrike/1.0 Security Scanner".to_string(),
                proxy: None,
                phases: vec![
                    "recon".into(),
                    "fingerprint".into(),
                    "cve".into(),
                    "active".into(),
                    "report".into(),
                ],
                enable_nmap: false,
            },
            rate_limit: RateLimitConfig {
                requests_per_second: 10,
                burst_size: 20,
            },
            output: OutputConfig {
                directory: PathBuf::from("./reports"),
                formats: vec!["html".into(), "json".into()],
                verbose: false,
            },
            api_keys: ApiKeysConfig {
                nvd_api_key: None,
            },
            payloads: PayloadsConfig {
                xss: PathBuf::from("./payloads/xss.txt"),
                sqli: PathBuf::from("./payloads/sqli.txt"),
                lfi: PathBuf::from("./payloads/lfi.txt"),
                ssti: PathBuf::from("./payloads/ssti.txt"),
                ssrf: PathBuf::from("./payloads/ssrf.txt"),
                cmdi: PathBuf::from("./payloads/cmdi.txt"),
                subdomains: PathBuf::from("./payloads/subdomains.txt"),
                open_redirect: PathBuf::from("./payloads/open_redirect.txt"),
            },
        }
    }
}

impl AppConfig {
    pub fn load(path: Option<&str>) -> anyhow::Result<Self> {
        if let Some(config_path) = path {
            let content = std::fs::read_to_string(config_path)?;
            let config: AppConfig = toml::from_str(&content)?;
            Ok(config)
        } else {
            Ok(Self::default())
        }
    }
}