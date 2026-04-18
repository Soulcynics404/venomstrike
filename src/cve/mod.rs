pub mod nvd;
pub mod exploitdb;
pub mod epss;
pub mod kev;

use crate::config::AppConfig;
use crate::reporting::models::{Technology, CveFinding, ExploitInfo};
use crate::error::VenomResult;
use colored::Colorize;

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
            continue;
        }

        let version = tech.version.as_deref().unwrap_or("");
        if version.is_empty() || version == "unknown" {
            continue;
        }

        println!("  {} Querying CVEs for {} v{}",
            "→".green(), tech.name.white().bold(), version.cyan());

        // Query NVD
        let mut cves = nvd::query_nvd(
            &tech.name,
            version,
            tech.cpe.as_deref(),
            config.api_keys.nvd_api_key.as_deref(),
        ).await.unwrap_or_default();

        println!("    {} {} CVEs returned from NVD", "•".cyan(), cves.len());

        // Enrich each CVE
        for cve in &mut cves {
            // ExploitDB matching
            let exploits = exploitdb::find_exploits(&cve.cve_id, &exploitdb_data);
            cve.exploits = exploits;

            // Always add useful reference links
            add_reference_links(cve);

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
            cve.remediation = generate_remediation(&tech.name, version, &cve.cve_id, &cve.severity);
        }

        all_findings.extend(cves);
    }

    // Sort by CVSS score descending
    all_findings.sort_by(|a, b| b.cvss_score.partial_cmp(&a.cvss_score).unwrap_or(std::cmp::Ordering::Equal));

    // Deduplicate by CVE ID
    all_findings.dedup_by(|a, b| a.cve_id == b.cve_id);

    Ok(all_findings)
}

/// Add reference links for each CVE (ExploitDB search, MITRE, etc.)
fn add_reference_links(cve: &mut CveFinding) {
    let cve_id = &cve.cve_id;

    // NVD link (should already be there but ensure it)
    let nvd_link = format!("https://nvd.nist.gov/vuln/detail/{}", cve_id);
    if !cve.references.iter().any(|r| r.contains("nvd.nist.gov")) {
        cve.references.insert(0, nvd_link);
    }

    // MITRE link
    let mitre_link = format!("https://cve.mitre.org/cgi-bin/cvename.cgi?name={}", cve_id);
    if !cve.references.iter().any(|r| r.contains("mitre.org")) {
        cve.references.push(mitre_link);
    }

    // ExploitDB search link (always useful even if no direct match)
    let edb_search = format!("https://www.exploit-db.com/search?cve={}", cve_id.replace("CVE-", ""));
    if !cve.references.iter().any(|r| r.contains("exploit-db.com")) {
        cve.references.push(edb_search);
    }

    // GitHub Advisory search
    let gh_advisory = format!("https://github.com/advisories?query={}", cve_id);
    cve.references.push(gh_advisory);

    // Packet Storm search
    let packetstorm = format!("https://packetstormsecurity.com/search/?q={}", cve_id);
    cve.references.push(packetstorm);
}

fn generate_remediation(tech: &str, version: &str, cve_id: &str, severity: &str) -> String {
    let urgency = match severity {
        "CRITICAL" => "IMMEDIATELY",
        "HIGH" => "within 1 week",
        "MEDIUM" => "within 1 month",
        _ => "when convenient",
    };

    format!(
        "1. Update {} from version {} to the latest stable release ({})\n\
         2. Review the advisory: https://nvd.nist.gov/vuln/detail/{}\n\
         3. Search for exploits: https://www.exploit-db.com/search?cve={}\n\
         4. Apply vendor-provided patches {}\n\
         5. If upgrade is not possible, implement compensating controls (WAF rules, network segmentation)\n\
         6. Monitor for exploitation attempts in logs",
        tech, version, urgency, cve_id,
        cve_id.replace("CVE-", ""),
        urgency
    )
}