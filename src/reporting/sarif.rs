use std::path::Path;
use serde_json::json;
use crate::reporting::models::ScanReport;
use crate::error::VenomResult;

pub async fn generate_sarif_report(report: &ScanReport, output_dir: &Path) -> VenomResult<()> {
    let filename = format!("venomstrike_report_{}.sarif", report.id);
    let filepath = output_dir.join(&filename);

    let mut results = Vec::new();
    let mut rules = Vec::new();
    let mut rule_ids = std::collections::HashSet::new();

    // Convert vulnerabilities to SARIF results
    for vuln in &report.vulnerabilities {
        let rule_id = vuln.cwe_id.clone().unwrap_or_else(|| vuln.vulnerability_type.clone());

        if !rule_ids.contains(&rule_id) {
            rule_ids.insert(rule_id.clone());
            rules.push(json!({
                "id": rule_id,
                "name": vuln.vulnerability_type,
                "shortDescription": { "text": vuln.title },
                "fullDescription": { "text": vuln.description },
                "helpUri": vuln.references.first().unwrap_or(&String::new()),
                "defaultConfiguration": {
                    "level": sarif_level(&vuln.severity)
                },
                "properties": {
                    "tags": ["security", "vulnerability"]
                }
            }));
        }

        results.push(json!({
            "ruleId": rule_id,
            "level": sarif_level(&vuln.severity),
            "message": {
                "text": format!("{}: {}", vuln.title, vuln.description)
            },
            "locations": [{
                "physicalLocation": {
                    "artifactLocation": {
                        "uri": vuln.url
                    }
                }
            }],
            "fingerprints": {
                "venomstrike/id": vuln.id
            },
            "properties": {
                "severity": vuln.severity,
                "parameter": vuln.parameter,
                "payload": vuln.payload,
                "evidence": vuln.evidence,
                "remediation": vuln.remediation,
            }
        }));
    }

    // Convert CVE findings to SARIF results
    for cve in &report.cve_findings {
        let rule_id = cve.cve_id.clone();

        if !rule_ids.contains(&rule_id) {
            rule_ids.insert(rule_id.clone());
            rules.push(json!({
                "id": rule_id,
                "name": format!("{} in {} {}", cve.cve_id, cve.affected_technology, cve.affected_version),
                "shortDescription": { "text": format!("{} (CVSS: {})", cve.cve_id, cve.cvss_score) },
                "fullDescription": { "text": cve.description },
                "helpUri": format!("https://nvd.nist.gov/vuln/detail/{}", cve.cve_id),
                "defaultConfiguration": {
                    "level": sarif_level(&cve.severity)
                }
            }));
        }

        results.push(json!({
            "ruleId": rule_id,
            "level": sarif_level(&cve.severity),
            "message": {
                "text": format!("{}: {} (CVSS: {}) — {}", cve.cve_id, cve.severity, cve.cvss_score, cve.description)
            },
            "locations": [{
                "physicalLocation": {
                    "artifactLocation": {
                        "uri": report.target
                    }
                }
            }],
            "properties": {
                "cvss_score": cve.cvss_score,
                "severity": cve.severity,
                "is_kev": cve.is_kev,
                "epss_score": cve.epss_score,
                "exploit_count": cve.exploits.len(),
            }
        }));
    }

    let sarif = json!({
        "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/main/sarif-2.1/schema/sarif-schema-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {
                "driver": {
                    "name": "VenomStrike",
                    "version": "1.0.0",
                    "informationUri": "https://github.com/Soulcynics404/venomstrike",
                    "rules": rules
                }
            },
            "results": results,
            "invocations": [{
                "executionSuccessful": true,
                "startTimeUtc": report.start_time.to_rfc3339(),
                "endTimeUtc": report.end_time.map(|e| e.to_rfc3339()).unwrap_or_default(),
            }]
        }]
    });

    let json_str = serde_json::to_string_pretty(&sarif).map_err(|e| {
        crate::error::VenomError::ReportError(format!("SARIF serialization failed: {}", e))
    })?;

    std::fs::write(&filepath, json_str).map_err(|e| {
        crate::error::VenomError::ReportError(format!("Failed to write SARIF report: {}", e))
    })?;

    println!("  📄 SARIF report saved: {}", filepath.display());
    Ok(())
}

fn sarif_level(severity: &str) -> &str {
    match severity.to_uppercase().as_str() {
        "CRITICAL" | "HIGH" => "error",
        "MEDIUM" => "warning",
        "LOW" | "INFO" => "note",
        _ => "none",
    }
}