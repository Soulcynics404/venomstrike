use serde::{Deserialize, Serialize};
use chrono::{DateTime, Utc};
use uuid::Uuid;

// ============ MAIN SCAN REPORT ============

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanReport {
    pub id: String,
    pub target: String,
    pub start_time: DateTime<Utc>,
    pub end_time: Option<DateTime<Utc>>,
    pub scanner_version: String,
    pub recon: Option<ReconResults>,
    pub technologies: Vec<Technology>,
    pub cve_findings: Vec<CveFinding>,
    pub vulnerabilities: Vec<Vulnerability>,
    pub header_findings: Vec<HeaderFinding>,
    pub ssl_findings: Vec<SslFinding>,
    pub methodology: String,
    pub scope_description: String,
}

impl ScanReport {
    pub fn new(target: String) -> Self {
        Self {
            id: Uuid::new_v4().to_string(),
            target,
            start_time: Utc::now(),
            end_time: None,
            scanner_version: "1.0.0".to_string(),
            recon: None,
            technologies: Vec::new(),
            cve_findings: Vec::new(),
            vulnerabilities: Vec::new(),
            header_findings: Vec::new(),
            ssl_findings: Vec::new(),
            methodology: DEFAULT_METHODOLOGY.to_string(),
            scope_description: String::new(),
        }
    }

    pub fn finalize(&mut self) {
        self.end_time = Some(Utc::now());
    }

    pub fn total_findings(&self) -> usize {
        self.cve_findings.len() + self.vulnerabilities.len()
            + self.header_findings.len() + self.ssl_findings.len()
    }

    pub fn count_by_severity(&self, severity: &str) -> usize {
        let sev = severity.to_uppercase();
        self.vulnerabilities.iter().filter(|v| v.severity.to_uppercase() == sev).count()
            + self.cve_findings.iter().filter(|c| c.severity.to_uppercase() == sev).count()
            + self.header_findings.iter().filter(|h| h.severity.to_uppercase() == sev).count()
            + self.ssl_findings.iter().filter(|s| s.severity.to_uppercase() == sev).count()
    }

    pub fn executive_summary(&self) -> ExecutiveSummary {
        ExecutiveSummary {
            target: self.target.clone(),
            scan_date: self.start_time.format("%Y-%m-%d %H:%M UTC").to_string(),
            duration: self.end_time.map(|e| {
                let dur = e - self.start_time;
                format!("{}m {}s", dur.num_minutes(), dur.num_seconds() % 60)
            }).unwrap_or("N/A".to_string()),
            total_findings: self.total_findings(),
            critical: self.count_by_severity("CRITICAL"),
            high: self.count_by_severity("HIGH"),
            medium: self.count_by_severity("MEDIUM"),
            low: self.count_by_severity("LOW"),
            info: self.count_by_severity("INFO"),
            technologies_found: self.technologies.len(),
            cves_found: self.cve_findings.len(),
            overall_risk: self.calculate_risk(),
        }
    }

    fn calculate_risk(&self) -> String {
        let critical = self.count_by_severity("CRITICAL");
        let high = self.count_by_severity("HIGH");
        if critical > 0 { "CRITICAL".to_string() }
        else if high > 0 { "HIGH".to_string() }
        else if self.count_by_severity("MEDIUM") > 0 { "MEDIUM".to_string() }
        else if self.count_by_severity("LOW") > 0 { "LOW".to_string() }
        else { "INFORMATIONAL".to_string() }
    }

    pub fn remediation_roadmap(&self) -> Vec<RemediationItem> {
        let mut items = Vec::new();
        let mut priority = 1;

        // Critical CVEs first
        for cve in self.cve_findings.iter().filter(|c| c.severity == "CRITICAL") {
            items.push(RemediationItem {
                priority,
                title: format!("Patch {}", cve.cve_id),
                description: cve.remediation.clone(),
                severity: "CRITICAL".to_string(),
                effort: "Immediate".to_string(),
            });
            priority += 1;
        }

        // Critical vulns
        for vuln in self.vulnerabilities.iter().filter(|v| v.severity == "CRITICAL") {
            items.push(RemediationItem {
                priority,
                title: format!("Fix: {}", vuln.title),
                description: vuln.remediation.clone(),
                severity: "CRITICAL".to_string(),
                effort: "High".to_string(),
            });
            priority += 1;
        }

        // High severity
        for cve in self.cve_findings.iter().filter(|c| c.severity == "HIGH") {
            items.push(RemediationItem {
                priority,
                title: format!("Patch {}", cve.cve_id),
                description: cve.remediation.clone(),
                severity: "HIGH".to_string(),
                effort: "Within 1 week".to_string(),
            });
            priority += 1;
        }

        for vuln in self.vulnerabilities.iter().filter(|v| v.severity == "HIGH") {
            items.push(RemediationItem {
                priority,
                title: format!("Fix: {}", vuln.title),
                description: vuln.remediation.clone(),
                severity: "HIGH".to_string(),
                effort: "Within 1 week".to_string(),
            });
            priority += 1;
        }

        // Medium
        for vuln in self.vulnerabilities.iter().filter(|v| v.severity == "MEDIUM") {
            items.push(RemediationItem {
                priority,
                title: format!("Fix: {}", vuln.title),
                description: vuln.remediation.clone(),
                severity: "MEDIUM".to_string(),
                effort: "Within 1 month".to_string(),
            });
            priority += 1;
        }

        // Low
        for vuln in self.vulnerabilities.iter().filter(|v| v.severity == "LOW") {
            items.push(RemediationItem {
                priority,
                title: format!("Fix: {}", vuln.title),
                description: vuln.remediation.clone(),
                severity: "LOW".to_string(),
                effort: "When convenient".to_string(),
            });
            priority += 1;
        }

        items
    }
}

// ============ RECON MODELS ============

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReconResults {
    pub domain: String,
    pub dns_records: Vec<DnsRecord>,
    pub subdomains: Vec<SubdomainInfo>,
    pub open_ports: Vec<PortInfo>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DnsRecord {
    pub record_type: String,
    pub value: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SubdomainInfo {
    pub subdomain: String,
    pub ip: String,
    pub status_code: Option<u16>,
    pub title: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PortInfo {
    pub port: u16,
    pub state: String,
    pub service: String,
    pub version: Option<String>,
}

// ============ TECHNOLOGY MODELS ============

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Technology {
    pub name: String,
    pub version: Option<String>,
    pub category: String,
    pub cpe: Option<String>,
    pub confidence: u8,
}

// ============ CVE MODELS ============

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CveFinding {
    pub cve_id: String,
    pub cvss_score: f64,
    pub severity: String,
    pub description: String,
    pub affected_technology: String,
    pub affected_version: String,
    pub exploits: Vec<ExploitInfo>,
    pub epss_score: Option<f64>,
    pub epss_percentile: Option<f64>,
    pub is_kev: bool,
    pub kev_date_added: Option<String>,
    pub references: Vec<String>,
    pub remediation: String,
    pub cwe_id: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExploitInfo {
    pub id: String,
    pub title: String,
    pub source: String,
    pub url: String,
    pub exploit_type: String,
}

// ============ VULNERABILITY MODELS ============

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Vulnerability {
    pub id: String,
    pub title: String,
    pub vulnerability_type: String,
    pub severity: String,
    pub cvss_score: Option<f64>,
    pub url: String,
    pub parameter: Option<String>,
    pub payload: Option<String>,
    pub evidence: String,
    pub description: String,
    pub impact: String,
    pub remediation: String,
    pub references: Vec<String>,
    pub cwe_id: Option<String>,
    pub request: Option<String>,
    pub response_snippet: Option<String>,
}

impl Vulnerability {
    pub fn new(
        title: &str,
        vuln_type: &str,
        severity: &str,
        url: &str,
    ) -> Self {
        Self {
            id: Uuid::new_v4().to_string(),
            title: title.to_string(),
            vulnerability_type: vuln_type.to_string(),
            severity: severity.to_string(),
            cvss_score: None,
            url: url.to_string(),
            parameter: None,
            payload: None,
            evidence: String::new(),
            description: String::new(),
            impact: String::new(),
            remediation: String::new(),
            references: Vec::new(),
            cwe_id: None,
            request: None,
            response_snippet: None,
        }
    }
}

// ============ HEADER / SSL MODELS ============

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HeaderFinding {
    pub header_name: String,
    pub status: String,      // "missing", "misconfigured", "present"
    pub current_value: Option<String>,
    pub recommended_value: String,
    pub severity: String,
    pub description: String,
    pub remediation: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SslFinding {
    pub title: String,
    pub severity: String,
    pub description: String,
    pub details: String,
    pub remediation: String,
}

// ============ REPORT HELPER MODELS ============

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExecutiveSummary {
    pub target: String,
    pub scan_date: String,
    pub duration: String,
    pub total_findings: usize,
    pub critical: usize,
    pub high: usize,
    pub medium: usize,
    pub low: usize,
    pub info: usize,
    pub technologies_found: usize,
    pub cves_found: usize,
    pub overall_risk: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RemediationItem {
    pub priority: usize,
    pub title: String,
    pub description: String,
    pub severity: String,
    pub effort: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RiskMatrix {
    pub likelihood: String,
    pub impact: String,
    pub risk_level: String,
}

// ============ CONSTANTS ============

pub const DEFAULT_METHODOLOGY: &str = r#"The assessment was conducted using VenomStrike, an automated vulnerability scanner that performs:
1. Passive reconnaissance including DNS enumeration and subdomain discovery
2. Technology fingerprinting to identify the target's technology stack
3. CVE intelligence gathering using NIST NVD, ExploitDB, EPSS, and CISA KEV
4. Active vulnerability scanning using custom-built detection modules
5. Manual verification of critical findings

All testing was performed in accordance with OWASP Testing Guide v4 and PTES methodologies."#;