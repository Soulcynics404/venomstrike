use async_trait::async_trait;
use std::path::{Path, PathBuf};
use crate::scanners::traits::VulnerabilityScanner;
use crate::core::crawler::CrawledPage;
use crate::reporting::models::Vulnerability;
use crate::error::VenomResult;

pub struct OpenRedirectScanner {
    payloads_path: PathBuf,
}

impl OpenRedirectScanner {
    pub fn new(payloads_path: &Path) -> Self {
        Self { payloads_path: payloads_path.to_path_buf() }
    }

    fn load_payloads(&self) -> Vec<String> {
        if let Ok(content) = std::fs::read_to_string(&self.payloads_path) {
            content.lines().map(|l| l.trim().to_string()).filter(|l| !l.is_empty() && !l.starts_with('#')).collect()
        } else {
            default_redirect_payloads()
        }
    }
}

#[async_trait]
impl VulnerabilityScanner for OpenRedirectScanner {
    fn name(&self) -> &str { "Open Redirect Scanner" }
    fn description(&self) -> &str { "Tests for Open Redirect vulnerabilities" }

    async fn scan(
        &self,
        pages: &[CrawledPage],
        client: &reqwest::Client,
    ) -> VenomResult<Vec<Vulnerability>> {
        let mut vulns = Vec::new();
        let payloads = self.load_payloads();

        let redirect_params = vec!["url", "redirect", "redir", "rurl", "dest",
            "destination", "next", "target", "return", "returnTo", "return_to",
            "checkout_url", "continue", "return_path", "go", "goto", "out",
            "view", "to", "image_url", "open", "callback", "link"];

        // Build a non-redirect client
        let no_redirect_client = reqwest::Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .danger_accept_invalid_certs(true)
            .timeout(std::time::Duration::from_secs(10))
            .build()
            .unwrap_or_else(|_| client.clone());

        for page in pages {
            for (param_name, _) in &page.params {
                let param_lower = param_name.to_lowercase();
                let is_redirect_param = redirect_params.iter().any(|p| param_lower.contains(p));

                if !is_redirect_param {
                    continue;
                }

                for payload in &payloads {
                    let test_url = inject_param(&page.url, param_name, payload);

                    if let Ok(resp) = no_redirect_client.get(&test_url).send().await {
                        let status = resp.status().as_u16();

                        // Check for redirect status codes
                        if status == 301 || status == 302 || status == 303 || status == 307 || status == 308 {
                            if let Some(location) = resp.headers().get("location") {
                                let loc = location.to_str().unwrap_or("");
                                if loc.contains("evil.com") || loc.contains("attacker.com")
                                    || loc.starts_with("//evil") || loc.starts_with("https://evil")
                                {
                                    vulns.push(create_redirect_vuln(
                                        &page.url, param_name, payload,
                                        &format!("Redirects to: {} (HTTP {})", loc, status),
                                    ));
                                    break;
                                }
                            }
                        }

                        // Check for meta refresh or JS redirect in body
                        if let Ok(body) = resp.text().await {
                            if body.contains("evil.com") || body.contains("attacker.com") {
                                if body.contains("window.location") || body.contains("meta http-equiv=\"refresh\"") {
                                    vulns.push(create_redirect_vuln(
                                        &page.url, param_name, payload,
                                        "Client-side redirect to attacker domain detected in response body",
                                    ));
                                    break;
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

fn create_redirect_vuln(url: &str, param: &str, payload: &str, evidence: &str) -> Vulnerability {
    let mut vuln = Vulnerability::new("Open Redirect", "Open Redirect", "MEDIUM", url);
    vuln.parameter = Some(param.to_string());
    vuln.payload = Some(payload.to_string());
    vuln.evidence = evidence.to_string();
    vuln.description = format!(
        "An Open Redirect vulnerability was found in the '{}' parameter. \
         The application redirects users to external URLs without validation.", param
    );
    vuln.impact = "An attacker can craft links that appear legitimate but redirect victims to \
         phishing sites, malware distribution, or OAuth token theft.".to_string();
    vuln.remediation = "1. Validate redirect URLs against a whitelist of allowed domains\n\
         2. Use relative paths instead of full URLs\n\
         3. Display a warning page before external redirects\n\
         4. Avoid using user input in redirect destinations".to_string();
    vuln.cwe_id = Some("CWE-601".to_string());
    vuln.references = vec![
        "https://cheatsheetseries.owasp.org/cheatsheets/Unvalidated_Redirects_and_Forwards_Cheat_Sheet.html".to_string(),
    ];
    vuln
}

fn default_redirect_payloads() -> Vec<String> {
    vec![
        "https://evil.com", "//evil.com", "/\\evil.com",
        "https://evil.com%2f%2f", "////evil.com",
        "https:evil.com", "http://evil.com",
        "/redirect?url=https://evil.com",
        "https://evil.com/.target.com",
        "https://target.com@evil.com",
        "https://evil.com#target.com",
        "https://evil.com?target.com",
        "//evil%00.com", "//evil.com/%09/",
        "/%0d/evil.com", "/.evil.com",
        "https://evil.com/target.com",
    ].iter().map(|s| s.to_string()).collect()
}