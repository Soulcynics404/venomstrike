pub mod dns;
pub mod subdomain;
pub mod port_scan;

use reqwest::Client;
use crate::config::AppConfig;
use crate::core::rate_limiter::VenomRateLimiter;
use crate::reporting::models::ReconResults;
use crate::error::VenomResult;

pub async fn run_recon(
    target: &str,
    client: &Client,
    rate_limiter: &VenomRateLimiter,
    config: &AppConfig,
) -> VenomResult<ReconResults> {
    let url = url::Url::parse(target)?;
    let domain = url.host_str().unwrap_or("").to_string();

    println!("  {} DNS Enumeration for {}", "→".green(), domain);
    let dns_records = dns::enumerate_dns(&domain).await?;
    for record in &dns_records {
        println!("    {} {} → {}", "•".cyan(), record.record_type, record.value);
    }

    println!("  {} Subdomain Discovery", "→".green());
    let subdomains = subdomain::discover_subdomains(
        &domain,
        client,
        rate_limiter,
        &config.payloads.subdomains,
    ).await?;
    println!("    Found {} subdomains", subdomains.len());

    let ports;
    if config.scanning.enable_nmap {
        println!("  {} Port Scanning (Nmap)", "→".green());
        ports = port_scan::nmap_scan(&domain).await?;
    } else {
        println!("  {} Basic Port Scanning", "→".green());
        ports = port_scan::basic_port_scan(&domain).await?;
    }
    println!("    Found {} open ports", ports.len());

    Ok(ReconResults {
        domain,
        dns_records,
        subdomains,
        open_ports: ports,
    })
}

use colored::Colorize;