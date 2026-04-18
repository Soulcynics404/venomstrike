#[cfg(test)]
mod tests {
    use venomstrike::reporting::models::*;
    use venomstrike::core::scope::ScopeEnforcer;

    #[test]
    fn test_scan_report_creation() {
        let report = ScanReport::new("https://example.com".to_string());
        assert_eq!(report.target, "https://example.com");
        assert_eq!(report.total_findings(), 0);
        assert_eq!(report.count_by_severity("CRITICAL"), 0);
    }

    #[test]
    fn test_vulnerability_creation() {
        let vuln = Vulnerability::new("Test XSS", "XSS", "HIGH", "https://example.com/page?q=test");
        assert_eq!(vuln.title, "Test XSS");
        assert_eq!(vuln.severity, "HIGH");
        assert_eq!(vuln.vulnerability_type, "XSS");
    }

    #[test]
    fn test_severity_counting() {
        let mut report = ScanReport::new("https://example.com".to_string());

        let mut v1 = Vulnerability::new("Critical Bug", "SQLi", "CRITICAL", "https://example.com");
        let mut v2 = Vulnerability::new("High Bug", "XSS", "HIGH", "https://example.com");
        let mut v3 = Vulnerability::new("Medium Bug", "CORS", "MEDIUM", "https://example.com");

        report.vulnerabilities.push(v1);
        report.vulnerabilities.push(v2);
        report.vulnerabilities.push(v3);

        assert_eq!(report.count_by_severity("CRITICAL"), 1);
        assert_eq!(report.count_by_severity("HIGH"), 1);
        assert_eq!(report.count_by_severity("MEDIUM"), 1);
        assert_eq!(report.count_by_severity("LOW"), 0);
        assert_eq!(report.total_findings(), 3);
    }

    #[test]
    fn test_executive_summary() {
        let mut report = ScanReport::new("https://example.com".to_string());
        report.vulnerabilities.push(
            Vulnerability::new("Critical", "SQLi", "CRITICAL", "https://example.com")
        );

        let summary = report.executive_summary();
        assert_eq!(summary.overall_risk, "CRITICAL");
        assert_eq!(summary.critical, 1);
        assert_eq!(summary.total_findings, 1);
    }

    #[test]
    fn test_remediation_roadmap() {
        let mut report = ScanReport::new("https://example.com".to_string());

        let mut v1 = Vulnerability::new("SQLi", "SQLi", "CRITICAL", "https://example.com");
        v1.remediation = "Fix SQL injection".to_string();

        let mut v2 = Vulnerability::new("XSS", "XSS", "HIGH", "https://example.com");
        v2.remediation = "Fix XSS".to_string();

        report.vulnerabilities.push(v1);
        report.vulnerabilities.push(v2);

        let roadmap = report.remediation_roadmap();
        assert!(!roadmap.is_empty());
        assert_eq!(roadmap[0].severity, "CRITICAL");
    }

    #[test]
    fn test_scope_enforcer_in_scope() {
        let scope = ScopeEnforcer::new(
            "https://example.com",
            vec![],
            vec![],
        ).unwrap();

        assert!(scope.is_in_scope("https://example.com/page"));
        assert!(scope.is_in_scope("https://example.com/admin/settings"));
        assert!(scope.is_in_scope("https://sub.example.com/page"));
        assert!(!scope.is_in_scope("https://evil.com/page"));
        assert!(!scope.is_in_scope("https://notexample.com"));
    }

    #[test]
    fn test_scope_enforcer_excludes() {
        let scope = ScopeEnforcer::new(
            "https://example.com",
            vec![],
            vec!["/logout".to_string(), "/signout".to_string()],
        ).unwrap();

        assert!(scope.is_in_scope("https://example.com/page"));
        assert!(!scope.is_in_scope("https://example.com/logout"));
        assert!(!scope.is_in_scope("https://example.com/signout"));
    }

    #[test]
    fn test_technology_model() {
        let tech = Technology {
            name: "Apache".to_string(),
            version: Some("2.4.51".to_string()),
            category: "Web Server".to_string(),
            cpe: Some("cpe:2.3:a:apache:http_server".to_string()),
            confidence: 95,
        };

        assert_eq!(tech.name, "Apache");
        assert_eq!(tech.version, Some("2.4.51".to_string()));
    }

    #[test]
    fn test_cve_finding_model() {
        let cve = CveFinding {
            cve_id: "CVE-2021-44228".to_string(),
            cvss_score: 10.0,
            severity: "CRITICAL".to_string(),
            description: "Log4Shell".to_string(),
            affected_technology: "Log4j".to_string(),
            affected_version: "2.14.1".to_string(),
            exploits: vec![
                ExploitInfo {
                    id: "EDB-50592".to_string(),
                    title: "Log4Shell RCE".to_string(),
                    source: "ExploitDB".to_string(),
                    url: "https://www.exploit-db.com/exploits/50592".to_string(),
                    exploit_type: "remote".to_string(),
                }
            ],
            epss_score: Some(0.976),
            epss_percentile: Some(0.999),
            is_kev: true,
            kev_date_added: Some("2021-12-10".to_string()),
            references: vec!["https://nvd.nist.gov/vuln/detail/CVE-2021-44228".to_string()],
            remediation: "Upgrade Log4j to 2.17.1+".to_string(),
            cwe_id: Some("CWE-917".to_string()),
        };

        assert_eq!(cve.cvss_score, 10.0);
        assert!(cve.is_kev);
        assert_eq!(cve.exploits.len(), 1);
    }

    #[test]
    fn test_risk_calculation() {
        let mut report = ScanReport::new("https://example.com".to_string());
        assert_eq!(report.executive_summary().overall_risk, "INFORMATIONAL");

        report.vulnerabilities.push(
            Vulnerability::new("Low", "Info", "LOW", "https://example.com")
        );
        assert_eq!(report.executive_summary().overall_risk, "LOW");

        report.vulnerabilities.push(
            Vulnerability::new("Medium", "XSS", "MEDIUM", "https://example.com")
        );
        assert_eq!(report.executive_summary().overall_risk, "MEDIUM");

        report.vulnerabilities.push(
            Vulnerability::new("Critical", "SQLi", "CRITICAL", "https://example.com")
        );
        assert_eq!(report.executive_summary().overall_risk, "CRITICAL");
    }
}