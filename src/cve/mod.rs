pub mod nvd;
pub mod exploitdb;
pub mod epss;
pub mod kev;

use crate::config::AppConfig;
use crate::reporting::models::{Technology, CveFinding};
use crate::error::VenomResult;

pub async fn run_cve_intelligence(
    technologies: &[Technology],
    config: &AppConfig,
) -> VenomResult<Vec<CveFinding>> {
    let mut all_findings = Vec::new();

    // Load local databases
    let exploitdb_data = exploitdb::load_exploitdb().await.unwrap_or_default();
    let kev_data = kev::load_kev_catalog().await.unwrap_or_default();

    for tech in technologies {
        if tech.version.is_none() {
            continue; // Skip techs without version info
        }

        let version = tech.version.as_deref().unwrap_or("");
        println!("  {} Querying CVEs for {} v{}", "→".to_string(), tech.name, version);

        // Query NVD
        let mut cves = nvd::query_nvd(
            &tech.name,
            version,
            tech.cpe.as_deref(),
            config.api_keys.nvd_api_key.as_deref(),
        ).await.unwrap_or_default();

        // Enrich with ExploitDB
        for cve in &mut cves {
            let exploits = exploitdb::find_exploits(&cve.cve_id, &exploitdb_data);
            cve.exploits = exploits;

            // Check CISA KEV
            if let Some(kev_entry) = kev::check_kev(&cve.cve_id, &kev_data) {
                cve.is_kev = true;
                cve.kev_date_added = Some(kev_entry.date_added.clone());
            }

            // Get EPSS score
            if let Ok(Some(epss_data)) = epss::get_epss_score(&cve.cve_id).await {
                cve.epss_score = Some(epss_data.probability);
                cve.epss_percentile = Some(epss_data.percentile);
            }

            // Generate remediation
            cve.remediation = generate_remediation(&tech.name, version, &cve.cve_id);
        }

        all_findings.extend(cves);
    }

    // Sort by CVSS score descending
    all_findings.sort_by(|a, b| b.cvss_score.partial_cmp(&a.cvss_score).unwrap_or(std::cmp::Ordering::Equal));
    Ok(all_findings)
}

fn generate_remediation(tech: &str, version: &str, cve_id: &str) -> String {
    format!(
        "1. Update {} from version {} to the latest stable release.\n\
         2. Review the advisory for {} at https://nvd.nist.gov/vuln/detail/{}\n\
         3. Apply vendor-provided patches immediately.\n\
         4. If upgrade is not possible, implement compensating controls (WAF rules, network segmentation).\n\
         5. Monitor for exploitation attempts in logs.",
        tech, version, cve_id, cve_id
    )
}

use colored::Colorize;