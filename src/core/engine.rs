use colored::*;
use indicatif::{ProgressBar, ProgressStyle};

use crate::config::AppConfig;
use crate::core::rate_limiter::{create_rate_limiter, VenomRateLimiter};
use crate::core::scope::ScopeEnforcer;
use crate::core::session::SessionManager;
use crate::core::crawler::Crawler;
use crate::recon;
use crate::fingerprint;
use crate::cve;
use crate::scanners;
use crate::reporting;
use crate::reporting::models::*;
use crate::error::VenomResult;

pub struct ScanEngine {
    config: AppConfig,
    session: SessionManager,
    scope: ScopeEnforcer,
    rate_limiter: VenomRateLimiter,
    cookie: Option<String>,
    auth: Option<String>,
}

impl ScanEngine {
    pub fn new(config: AppConfig) -> VenomResult<Self> {
        let scope = ScopeEnforcer::new(
            &config.target.url,
            config.target.scope.clone(),
            config.target.exclude.clone(),
        )?;

        let session = SessionManager::new(
            config.scanning.timeout_secs,
            &config.scanning.user_agent,
            config.scanning.proxy.as_deref(),
            None,
            None,
            config.scanning.follow_redirects,
        )?;

        let rate_limiter = create_rate_limiter(
            config.rate_limit.requests_per_second,
            config.rate_limit.burst_size,
        );

        Ok(Self {
            config,
            session,
            scope,
            rate_limiter,
            cookie: None,
            auth: None,
        })
    }

    pub fn with_auth(mut self, cookie: Option<String>, auth: Option<String>) -> VenomResult<Self> {
        self.cookie = cookie.clone();
        self.auth = auth.clone();
        self.session = SessionManager::new(
            self.config.scanning.timeout_secs,
            &self.config.scanning.user_agent,
            self.config.scanning.proxy.as_deref(),
            cookie,
            auth,
            self.config.scanning.follow_redirects,
        )?;
        Ok(self)
    }

    pub async fn run_full_scan(&self) -> VenomResult<ScanReport> {
        let target = &self.config.target.url;
        print_banner();
        println!("{} Target: {}", "🎯".bold(), target.cyan().bold());
        println!("{}", "─".repeat(60));

        let mut report = ScanReport::new(target.clone());

        // Phase 1: Reconnaissance
        if self.config.scanning.phases.contains(&"recon".to_string()) {
            println!("\n{}", "═══ Phase 1: Reconnaissance ═══".yellow().bold());
            let pb = create_progress_bar("Reconnaissance");

            let recon_results = recon::run_recon(
                target,
                self.session.client(),
                &self.rate_limiter,
                &self.config,
            ).await?;

            report.recon = Some(recon_results);
            pb.finish_with_message("Reconnaissance complete ✓");
        }

        // Phase 2: Technology Fingerprinting
        if self.config.scanning.phases.contains(&"fingerprint".to_string()) {
            println!("\n{}", "═══ Phase 2: Technology Fingerprinting ═══".yellow().bold());
            let pb = create_progress_bar("Fingerprinting");

            let tech_results = fingerprint::run_fingerprint(
                target,
                self.session.client(),
                &self.rate_limiter,
            ).await?;

            for tech in &tech_results {
                println!("  {} {} v{} [{}%]", "→".green(),
                    tech.name.white().bold(),
                    tech.version.as_deref().unwrap_or("unknown").cyan(),
                    tech.confidence);
            }

            report.technologies = tech_results;
            pb.finish_with_message("Fingerprinting complete ✓");
        }

        // Phase 3: CVE Intelligence
        if self.config.scanning.phases.contains(&"cve".to_string()) {
            println!("\n{}", "═══ Phase 3: CVE Intelligence Engine ═══".yellow().bold());
            let pb = create_progress_bar("CVE Lookup");

            let cve_results = cve::run_cve_intelligence(
                &report.technologies,
                &self.config,
            ).await?;

            for finding in &cve_results {
                let severity_colored = match finding.severity.as_str() {
                    "CRITICAL" => finding.severity.red().bold(),
                    "HIGH" => finding.severity.red(),
                    "MEDIUM" => finding.severity.yellow(),
                    "LOW" => finding.severity.green(),
                    _ => finding.severity.white(),
                };
                println!("  {} {} [{}] CVSS: {}", "⚠".red(),
                    finding.cve_id.white().bold(), severity_colored, finding.cvss_score);

                if !finding.exploits.is_empty() {
                    for exploit in &finding.exploits {
                        println!("    {} {} → {}", "💀".red(), exploit.id, exploit.url.cyan());
                    }
                }

                if finding.is_kev {
                    println!("    {} CISA Known Exploited Vulnerability!", "🚨".red().bold());
                }
            }

            report.cve_findings = cve_results;
            pb.finish_with_message("CVE Intelligence complete ✓");
        }

        // Phase 4: Active Vulnerability Scanning
        if self.config.scanning.phases.contains(&"active".to_string()) {
            println!("\n{}", "═══ Phase 4: Active Vulnerability Scanning ═══".yellow().bold());

            println!("  {} Crawling target...", "🕷".bold());
            let mut crawler = Crawler::new(
                self.session.client().clone(),
                self.scope.clone(),
                self.rate_limiter.clone(),
                self.config.target.max_depth,
            ).with_auth_cookie(self.cookie.clone());

            let pages = crawler.crawl(target).await?;
            println!("  {} Discovered {} pages", "✓".green(), pages.len());

            let vuln_results = scanners::run_active_scans(
                &pages,
                self.session.client(),
                &self.rate_limiter,
                &self.config,
            ).await?;

            for vuln in &vuln_results {
                let severity_colored = match vuln.severity.as_str() {
                    "CRITICAL" => vuln.severity.red().bold(),
                    "HIGH" => vuln.severity.red(),
                    "MEDIUM" => vuln.severity.yellow(),
                    "LOW" => vuln.severity.green(),
                    "INFO" => vuln.severity.blue(),
                    _ => vuln.severity.white(),
                };
                println!("  {} [{}] {} at {}", "🔥".bold(), severity_colored,
                    vuln.title, vuln.url.cyan());
                if let Some(ref payload) = vuln.payload {
                    println!("    {} Payload: {}", "→".green(), payload.yellow());
                }
            }

            report.vulnerabilities = vuln_results;
        }

        // Finalize report with end time
        report.finalize();

        // Phase 5: Report Generation
        if self.config.scanning.phases.contains(&"report".to_string()) {
            println!("\n{}", "═══ Phase 5: VAPT Report Generation ═══".yellow().bold());

            for format in &self.config.output.formats {
                let pb = create_progress_bar(&format!("Generating {} report", format));
                reporting::generate_report(&report, format, &self.config.output.directory).await?;
                pb.finish_with_message(format!("{} report generated ✓", format));
            }
        }

        println!("\n{}", "═══ Scan Complete ═══".green().bold());
        let summary = report.executive_summary();
        println!("  Duration: {}", summary.duration.cyan());
        println!("  Total findings: {}", report.total_findings());
        println!("  Critical: {} | High: {} | Medium: {} | Low: {} | Info: {}",
            summary.critical.to_string().red().bold(),
            summary.high.to_string().red(),
            summary.medium.to_string().yellow(),
            summary.low.to_string().green(),
            summary.info.to_string().blue(),
        );

        Ok(report)
    }
}

fn print_banner() {
    let banner = r#"
 ██╗   ██╗███████╗███╗   ██╗ ██████╗ ███╗   ███╗███████╗████████╗██████╗ ██╗██╗  ██╗███████╗
 ██║   ██║██╔════╝████╗  ██║██╔═══██╗████╗ ████║██╔════╝╚══██╔══╝██╔══██╗██║██║ ██╔╝██╔════╝
 ██║   ██║█████╗  ██╔██╗ ██║██║   ██║██╔████╔██║███████╗   ██║   ██████╔╝██║█████╔╝ █████╗
 ╚██╗ ██╔╝██╔══╝  ██║╚██╗██║██║   ██║██║╚██╔╝██║╚════██║   ██║   ██╔══██╗██║██╔═██╗ ██╔══╝
  ╚████╔╝ ███████╗██║ ╚████║╚██████╔╝██║ ╚═╝ ██║███████║   ██║   ██║  ██║██║██║  ██╗███████╗
   ╚═══╝  ╚══════╝╚═╝  ╚═══╝ ╚═════╝ ╚═╝     ╚═╝╚══════╝   ╚═╝   ╚═╝  ╚═╝╚═╝╚═╝  ╚═╝╚══════╝
                    Advanced Web Vulnerability Scanner & VAPT Reporter v1.0.1
    "#;
    println!("{}", banner.red().bold());
}

fn create_progress_bar(msg: &str) -> ProgressBar {
    let pb = ProgressBar::new_spinner();
    pb.set_style(
        ProgressStyle::default_spinner()
            .template("{spinner:.green} [{elapsed_precise}] {msg}")
            .unwrap()
    );
    pb.set_message(msg.to_string());
    pb.enable_steady_tick(std::time::Duration::from_millis(100));
    pb
}