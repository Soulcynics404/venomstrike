pub mod traits;
pub mod sqli;
pub mod xss;
pub mod ssrf;
pub mod lfi;
pub mod ssti;
pub mod cmdi;
pub mod cors;
pub mod open_redirect;
pub mod csrf;
pub mod headers;
pub mod ssl;

use reqwest::Client;
use crate::config::AppConfig;
use crate::core::crawler::CrawledPage;
use crate::core::rate_limiter::VenomRateLimiter;
use crate::reporting::models::Vulnerability;
use crate::error::VenomResult;
use traits::VulnerabilityScanner;

pub async fn run_active_scans(
    pages: &[CrawledPage],
    client: &Client,
    rate_limiter: &VenomRateLimiter,
    config: &AppConfig,
) -> VenomResult<Vec<Vulnerability>> {
    let mut all_vulns = Vec::new();

    // Build scanner registry
    let scanners: Vec<Box<dyn VulnerabilityScanner>> = vec![
        Box::new(sqli::SqliScanner::new(&config.payloads.sqli)),
        Box::new(xss::XssScanner::new(&config.payloads.xss)),
        Box::new(ssrf::SsrfScanner::new(&config.payloads.ssrf)),
        Box::new(lfi::LfiScanner::new(&config.payloads.lfi)),
        Box::new(ssti::SstiScanner::new(&config.payloads.ssti)),
        Box::new(cmdi::CmdiScanner::new(&config.payloads.cmdi)),
        Box::new(cors::CorsScanner::new()),
        Box::new(open_redirect::OpenRedirectScanner::new(&config.payloads.open_redirect)),
        Box::new(csrf::CsrfScanner::new()),
        Box::new(headers::HeaderScanner::new()),
        Box::new(ssl::SslScanner::new()),
    ];

    for scanner in &scanners {
        if !scanner.is_enabled() {
            continue;
        }

        println!("  {} Running: {}", "🔍", scanner.name());
        rate_limiter.until_ready().await;

        match scanner.scan(pages, client).await {
            Ok(vulns) => {
                if !vulns.is_empty() {
                    println!("    {} Found {} issue(s)", "⚠", vulns.len());
                }
                all_vulns.extend(vulns);
            }
            Err(e) => {
                log::warn!("Scanner {} failed: {}", scanner.name(), e);
            }
        }
    }

    // Sort by severity
    all_vulns.sort_by(|a, b| severity_order(&a.severity).cmp(&severity_order(&b.severity)));
    Ok(all_vulns)
}

fn severity_order(severity: &str) -> u8 {
    match severity.to_uppercase().as_str() {
        "CRITICAL" => 0,
        "HIGH" => 1,
        "MEDIUM" => 2,
        "LOW" => 3,
        "INFO" => 4,
        _ => 5,
    }
}

use colored::Colorize;