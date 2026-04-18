use clap::Parser;
use colored::*;
use std::path::PathBuf;

mod cli;
mod config;
mod error;
mod core;
mod recon;
mod fingerprint;
mod cve;
mod scanners;
mod reporting;
mod utils;

use cli::{Cli, Commands};
use config::AppConfig;
use core::engine::ScanEngine;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info"))
        .format_timestamp(None)
        .init();

    let cli = Cli::parse();

    match cli.command {
        Commands::Scan {
            target,
            config: config_path,
            output,
            formats,
            threads,
            rate_limit,
            phases,
            nmap,
            proxy,
            nvd_key,
            user_agent,
            scope,
            verbose,
            timeout,
            cookie,
            auth,
        } => {
            let mut app_config = if let Some(ref path) = config_path {
                AppConfig::load(Some(path))?
            } else {
                AppConfig::default()
            };

            // Override config with CLI args
            app_config.target.url = target;
            app_config.output.directory = PathBuf::from(output);
            app_config.output.formats = formats;
            app_config.scanning.threads = threads;
            app_config.rate_limit.requests_per_second = rate_limit;
            app_config.scanning.phases = phases;
            app_config.scanning.enable_nmap = nmap;
            app_config.scanning.proxy = proxy;
            app_config.api_keys.nvd_api_key = nvd_key;
            app_config.output.verbose = verbose;
            app_config.scanning.timeout_secs = timeout;

            if let Some(ua) = user_agent {
                app_config.scanning.user_agent = ua;
            }

            if let Some(scope_domains) = scope {
                app_config.target.scope = scope_domains;
            }

            // Create output directory
            std::fs::create_dir_all(&app_config.output.directory)?;

            let engine = ScanEngine::new(app_config)?
                .with_auth(cookie, auth)?;

            let mut report = engine.run_full_scan().await?;
            report.finalize();

            println!("\n{}", "Reports saved to ./reports/".green().bold());
        }

        Commands::Recon { target, nmap, verbose } => {
            let mut config = AppConfig::default();
            config.target.url = target;
            config.scanning.enable_nmap = nmap;
            config.output.verbose = verbose;
            config.scanning.phases = vec!["recon".to_string()];

            let engine = ScanEngine::new(config)?;
            engine.run_full_scan().await?;
        }

        Commands::CveLookup { technology, version, nvd_key } => {
            let config = AppConfig {
                api_keys: config::ApiKeysConfig { nvd_api_key: nvd_key },
                ..AppConfig::default()
            };

            let tech = reporting::models::Technology {
                name: technology.clone(),
                version: Some(version.clone()),
                category: "Manual Lookup".to_string(),
                cpe: None,
                confidence: 100,
            };

            println!("{} Looking up CVEs for {} v{}", "🔍".bold(), technology.cyan(), version.cyan());

            let findings = cve::run_cve_intelligence(&[tech], &config).await?;

            if findings.is_empty() {
                println!("{}", "No CVEs found.".yellow());
            } else {
                for f in &findings {
                    let sev = match f.severity.as_str() {
                        "CRITICAL" => f.severity.red().bold(),
                        "HIGH" => f.severity.red(),
                        "MEDIUM" => f.severity.yellow(),
                        "LOW" => f.severity.green(),
                        _ => f.severity.white(),
                    };
                    println!("\n  {} {} [{}] CVSS: {}", "⚠".red(), f.cve_id.white().bold(), sev, f.cvss_score);
                    println!("    {}", f.description.chars().take(120).collect::<String>());
                    if !f.exploits.is_empty() {
                        println!("    {} {} exploits available", "💀".red(), f.exploits.len());
                    }
                    if f.is_kev {
                        println!("    {} Known Exploited Vulnerability (CISA KEV)", "🚨".red().bold());
                    }
                    if let Some(epss) = f.epss_score {
                        println!("    EPSS: {:.2}%", epss * 100.0);
                    }
                }
            }
        }

        Commands::Report { input, formats, output } => {
            let json_content = std::fs::read_to_string(&input)?;
            let report: reporting::models::ScanReport = serde_json::from_str(&json_content)?;
            let output_dir = PathBuf::from(output);
            std::fs::create_dir_all(&output_dir)?;

            for format in &formats {
                reporting::generate_report(&report, format, &output_dir).await?;
                println!("{} {} report generated", "✓".green(), format);
            }
        }
    }

    Ok(())
}