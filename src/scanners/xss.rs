use async_trait::async_trait;
use std::path::{Path, PathBuf};
use crate::scanners::traits::VulnerabilityScanner;
use crate::core::crawler::CrawledPage;
use crate::reporting::models::Vulnerability;
use crate::error::VenomResult;

pub struct XssScanner {
    payloads_path: PathBuf,
}

impl XssScanner {
    pub fn new(payloads_path: &Path) -> Self {
        Self { payloads_path: payloads_path.to_path_buf() }
    }

    fn load_payloads(&self) -> Vec<String> {
        if let Ok(content) = std::fs::read_to_string(&self.payloads_path) {
            content.lines().map(|l| l.trim().to_string())
                .filter(|l| !l.is_empty() && !l.starts_with('#')).collect()
        } else {
            default_xss_payloads()
        }
    }
}

#[async_trait]
impl VulnerabilityScanner for XssScanner {
    fn name(&self) -> &str { "XSS Scanner" }
    fn description(&self) -> &str { "Tests for Reflected Cross-Site Scripting with encoding bypass" }

    async fn scan(
        &self,
        pages: &[CrawledPage],
        client: &reqwest::Client,
    ) -> VenomResult<Vec<Vulnerability>> {
        let mut vulns = Vec::new();
        let payloads = self.load_payloads();
        let mut tested = std::collections::HashSet::new();

        for page in pages {
            let cookie = page.auth_cookie.clone();

            // Test URL parameters
            for (param_name, _) in &page.params {
                let test_key = format!("xss:{}:{}", page.url, param_name);
                if tested.contains(&test_key) { continue; }

                for payload in &payloads {
                    let test_url = inject_param(&page.url, param_name, payload);

                    let mut req = client.get(&test_url);
                    if let Some(ref c) = cookie { req = req.header("Cookie", c); }

                    if let Ok(resp) = req.send().await {
                        if let Ok(body) = resp.text().await {
                            if body.contains(payload) {
                                tested.insert(test_key.clone());
                                vulns.push(create_xss_vuln(
                                    &page.url, param_name, payload,
                                    "Reflected XSS", "HIGH",
                                    &format!("Payload reflected without encoding in response body: {}", payload),
                                ));
                                break;
                            }

                            let decoded = html_decode(payload);
                            if decoded != *payload && body.contains(&decoded) {
                                tested.insert(test_key.clone());
                                vulns.push(create_xss_vuln(
                                    &page.url, param_name, payload,
                                    "Reflected XSS (HTML Decoded)", "HIGH",
                                    &format!("Payload reflected after HTML decoding: {}", decoded),
                                ));
                                break;
                            }
                        }
                    }
                }

                if tested.contains(&test_key) { continue; }

                // Try encoding bypass
                for payload in payloads.iter().take(5) {
                    let encoded_variants = vec![
                        urlencoding::encode(payload).to_string(),
                        payload.replace("<", "%3C").replace(">", "%3E"),
                        double_url_encode(payload),
                    ];

                    for enc_payload in &encoded_variants {
                        let test_url = inject_param(&page.url, param_name, enc_payload);

                        let mut req = client.get(&test_url);
                        if let Some(ref c) = cookie { req = req.header("Cookie", c); }

                        if let Ok(resp) = req.send().await {
                            if let Ok(body) = resp.text().await {
                                if body.contains(payload) || body.contains(&html_decode(payload)) {
                                    tested.insert(test_key.clone());
                                    vulns.push(create_xss_vuln(
                                        &page.url, param_name, enc_payload,
                                        "Reflected XSS (Encoding Bypass)", "HIGH",
                                        &format!("Payload reflected after encoding bypass. Original: {} | Encoded: {}", payload, enc_payload),
                                    ));
                                    break;
                                }
                            }
                        }
                    }
                    if tested.contains(&test_key) { break; }
                }
            }

            // Test forms
            for form in &page.forms {
                for input in &form.inputs {
                    if input.input_type == "hidden" || input.input_type == "submit" { continue; }

                    let form_key = format!("xss:form:{}:{}", form.action, input.name);
                    if tested.contains(&form_key) { continue; }

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
                            let mut req = client.post(&form.action).form(&form_data);
                            if let Some(ref c) = cookie { req = req.header("Cookie", c); }
                            req.send().await
                        } else {
                            let mut url = url::Url::parse(&form.action).unwrap_or_else(|_| url::Url::parse(&page.url).unwrap());
                            for (k, v) in &form_data { url.query_pairs_mut().append_pair(k, v); }
                            let mut req = client.get(url.as_str());
                            if let Some(ref c) = cookie { req = req.header("Cookie", c); }
                            req.send().await
                        };

                        if let Ok(resp) = result {
                            if let Ok(body) = resp.text().await {
                                if body.contains(payload) {
                                    tested.insert(form_key.clone());
                                    vulns.push(create_xss_vuln(
                                        &form.action, &input.name, payload,
                                        &format!("Reflected XSS ({} Form)", form.method), "HIGH",
                                        &format!("Payload '{}' reflected in {} form response at input '{}'", payload, form.method, input.name),
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

fn html_decode(input: &str) -> String {
    input.replace("&lt;", "<").replace("&gt;", ">")
        .replace("&amp;", "&").replace("&quot;", "\"")
        .replace("&#39;", "'").replace("&#x27;", "'")
}

fn double_url_encode(input: &str) -> String {
    let first = urlencoding::encode(input);
    urlencoding::encode(&first).to_string()
}

fn create_xss_vuln(url: &str, param: &str, payload: &str, title: &str, severity: &str, evidence: &str) -> Vulnerability {
    let mut vuln = Vulnerability::new(title, "Cross-Site Scripting (XSS)", severity, url);
    vuln.parameter = Some(param.to_string());
    vuln.payload = Some(payload.to_string());
    vuln.evidence = evidence.to_string();
    vuln.description = format!(
        "Reflected XSS found in parameter '{}'. The payload '{}' was reflected in the server response \
         without proper output encoding, allowing script execution in victims' browsers.",
        param, payload
    );
    vuln.impact = "An attacker can inject malicious scripts that execute in victims' browsers, \
         enabling session hijacking, credential theft, defacement, or malware distribution.".to_string();
    vuln.remediation = "1. Implement context-aware output encoding (HTML, JS, URL, CSS)\n\
         2. Use Content-Security-Policy (CSP) headers\n\
         3. Validate and sanitize all user input\n\
         4. Use HTTPOnly and Secure flags on cookies\n\
         5. Consider frameworks with auto-escaping (React, Angular)".to_string();
    vuln.cwe_id = Some("CWE-79".to_string());
    vuln.references = vec![
        "https://owasp.org/www-community/attacks/xss/".to_string(),
        "https://portswigger.net/web-security/cross-site-scripting".to_string(),
        "https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html".to_string(),
    ];
    vuln
}

fn default_xss_payloads() -> Vec<String> {
    vec![
        "<script>alert('XSS')</script>",
        "<img src=x onerror=alert('XSS')>",
        "<svg onload=alert('XSS')>",
        "'\"><script>alert('XSS')</script>",
        "<body onload=alert('XSS')>",
        "<iframe src=\"javascript:alert('XSS')\">",
        "\"><img src=x onerror=alert(1)>",
        "<details open ontoggle=alert(1)>",
        "<input onfocus=alert(1) autofocus>",
        "<marquee onstart=alert(1)>",
    ].iter().map(|s| s.to_string()).collect()
}