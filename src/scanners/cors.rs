use async_trait::async_trait;
use crate::scanners::traits::VulnerabilityScanner;
use crate::core::crawler::CrawledPage;
use crate::reporting::models::Vulnerability;
use crate::error::VenomResult;

pub struct CorsScanner;

impl CorsScanner {
    pub fn new() -> Self { Self }
}

#[async_trait]
impl VulnerabilityScanner for CorsScanner {
    fn name(&self) -> &str { "CORS Misconfiguration Scanner" }
    fn description(&self) -> &str { "Tests for Cross-Origin Resource Sharing misconfigurations" }

    async fn scan(
        &self,
        pages: &[CrawledPage],
        client: &reqwest::Client,
    ) -> VenomResult<Vec<Vulnerability>> {
        let mut vulns = Vec::new();

        // Test unique origins only
        let mut tested_origins = std::collections::HashSet::new();

        for page in pages {
            let base_url = if let Ok(parsed) = url::Url::parse(&page.url) {
                format!("{}://{}", parsed.scheme(), parsed.host_str().unwrap_or(""))
            } else {
                continue;
            };

            if tested_origins.contains(&base_url) {
                continue;
            }
            tested_origins.insert(base_url.clone());

            // Test 1: Arbitrary origin reflection
            let evil_origin = "https://evil-attacker.com";
            if let Ok(resp) = client.get(&page.url)
                .header("Origin", evil_origin)
                .send().await
            {
                let headers = resp.headers();
                if let Some(acao) = headers.get("access-control-allow-origin") {
                    let acao_str = acao.to_str().unwrap_or("");

                    if acao_str == evil_origin {
                        let has_credentials = headers.get("access-control-allow-credentials")
                            .map(|v| v.to_str().unwrap_or("") == "true")
                            .unwrap_or(false);

                        let severity = if has_credentials { "HIGH" } else { "MEDIUM" };

                        vulns.push(create_cors_vuln(
                            &page.url,
                            &format!("Origin '{}' reflected in ACAO header. Credentials: {}", evil_origin, has_credentials),
                            severity,
                            "Arbitrary Origin Reflection",
                        ));
                    }

                    // Test 2: Wildcard with credentials
                    if acao_str == "*" {
                        if headers.get("access-control-allow-credentials")
                            .map(|v| v.to_str().unwrap_or("") == "true")
                            .unwrap_or(false)
                        {
                            vulns.push(create_cors_vuln(
                                &page.url,
                                "Wildcard ACAO (*) with credentials allowed",
                                "HIGH",
                                "Wildcard Origin with Credentials",
                            ));
                        }
                    }
                }
            }

            // Test 3: Null origin
            if let Ok(resp) = client.get(&page.url)
                .header("Origin", "null")
                .send().await
            {
                if let Some(acao) = resp.headers().get("access-control-allow-origin") {
                    if acao.to_str().unwrap_or("") == "null" {
                        vulns.push(create_cors_vuln(
                            &page.url,
                            "Null origin accepted in ACAO header",
                            "MEDIUM",
                            "Null Origin Accepted",
                        ));
                    }
                }
            }

            // Test 4: Subdomain prefix bypass
            if let Ok(parsed) = url::Url::parse(&page.url) {
                let host = parsed.host_str().unwrap_or("");
                let bypass_origin = format!("https://{}.evil.com", host);

                if let Ok(resp) = client.get(&page.url)
                    .header("Origin", &bypass_origin)
                    .send().await
                {
                    if let Some(acao) = resp.headers().get("access-control-allow-origin") {
                        if acao.to_str().unwrap_or("") == bypass_origin {
                            vulns.push(create_cors_vuln(
                                &page.url,
                                &format!("Prefix bypass accepted: {}", bypass_origin),
                                "MEDIUM",
                                "CORS Origin Prefix Bypass",
                            ));
                        }
                    }
                }
            }
        }

        Ok(vulns)
    }
}

fn create_cors_vuln(url: &str, evidence: &str, severity: &str, title: &str) -> Vulnerability {
    let mut vuln = Vulnerability::new(
        &format!("CORS Misconfiguration: {}", title),
        "CORS Misconfiguration", severity, url
    );
    vuln.evidence = evidence.to_string();
    vuln.description = "The application has a misconfigured Cross-Origin Resource Sharing (CORS) policy \
         that may allow unauthorized cross-origin access to sensitive data.".to_string();
    vuln.impact = "An attacker can read sensitive data from the application using a malicious \
         website, potentially stealing user data, tokens, or performing actions on behalf of users.".to_string();
    vuln.remediation = "1. Never reflect arbitrary origins in Access-Control-Allow-Origin\n\
         2. Use a strict whitelist of allowed origins\n\
         3. Avoid using wildcard (*) with credentials\n\
         4. Don't accept the null origin\n\
         5. Validate the Origin header server-side".to_string();
    vuln.cwe_id = Some("CWE-942".to_string());
    vuln.references = vec![
        "https://portswigger.net/web-security/cors".to_string(),
        "https://owasp.org/www-community/attacks/CORS_OriginHeaderScrutiny".to_string(),
    ];
    vuln
}