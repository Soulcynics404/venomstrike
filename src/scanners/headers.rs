use async_trait::async_trait;
use crate::scanners::traits::VulnerabilityScanner;
use crate::core::crawler::CrawledPage;
use crate::reporting::models::Vulnerability;
use crate::error::VenomResult;

pub struct HeaderScanner;

impl HeaderScanner {
    pub fn new() -> Self { Self }
}

#[async_trait]
impl VulnerabilityScanner for HeaderScanner {
    fn name(&self) -> &str { "Security Headers Scanner" }
    fn description(&self) -> &str { "Analyzes HTTP security headers for misconfigurations" }

    async fn scan(
        &self,
        pages: &[CrawledPage],
        _client: &reqwest::Client,
    ) -> VenomResult<Vec<Vulnerability>> {
        let mut vulns = Vec::new();
        let mut checked_hosts = std::collections::HashSet::new();

        for page in pages {
            let host = url::Url::parse(&page.url)
                .ok()
                .and_then(|u| u.host_str().map(|h| h.to_string()))
                .unwrap_or_default();

            if checked_hosts.contains(&host) {
                continue;
            }
            checked_hosts.insert(host);

            let headers: std::collections::HashMap<String, String> = page.headers.iter()
                .map(|(k, v)| (k.to_lowercase(), v.clone()))
                .collect();

            // Strict-Transport-Security
            if !headers.contains_key("strict-transport-security") {
                vulns.push(create_header_vuln(
                    &page.url,
                    "Strict-Transport-Security",
                    "Missing",
                    "max-age=31536000; includeSubDomains; preload",
                    "MEDIUM",
                    "Without HSTS, users are vulnerable to SSL stripping attacks and protocol downgrade.",
                ));
            } else {
                let val = headers.get("strict-transport-security").unwrap();
                if !val.contains("includeSubDomains") {
                    vulns.push(create_header_vuln(
                        &page.url,
                        "Strict-Transport-Security",
                        &format!("Incomplete: {}", val),
                        "max-age=31536000; includeSubDomains; preload",
                        "LOW",
                        "HSTS header is present but doesn't include subdomains.",
                    ));
                }
            }

            // Content-Security-Policy
            if !headers.contains_key("content-security-policy") {
                vulns.push(create_header_vuln(
                    &page.url,
                    "Content-Security-Policy",
                    "Missing",
                    "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'",
                    "MEDIUM",
                    "Without CSP, the application is more susceptible to XSS and data injection attacks.",
                ));
            } else {
                let csp = headers.get("content-security-policy").unwrap();
                if csp.contains("unsafe-inline") && csp.contains("unsafe-eval") {
                    vulns.push(create_header_vuln(
                        &page.url,
                        "Content-Security-Policy",
                        &format!("Weak: {}", csp),
                        "Remove 'unsafe-inline' and 'unsafe-eval'",
                        "LOW",
                        "CSP allows unsafe-inline and unsafe-eval, weakening XSS protection.",
                    ));
                }
            }

            // X-Content-Type-Options
            if !headers.contains_key("x-content-type-options") {
                vulns.push(create_header_vuln(
                    &page.url,
                    "X-Content-Type-Options",
                    "Missing",
                    "nosniff",
                    "LOW",
                    "Without this header, browsers may MIME-sniff responses, leading to XSS.",
                ));
            }

            // X-Frame-Options
            if !headers.contains_key("x-frame-options") && !has_frame_ancestors_csp(&headers) {
                vulns.push(create_header_vuln(
                    &page.url,
                    "X-Frame-Options",
                    "Missing",
                    "DENY or SAMEORIGIN",
                    "MEDIUM",
                    "Without framing protection, the application is vulnerable to clickjacking.",
                ));
            }

            // X-XSS-Protection (legacy but still checked)
            if !headers.contains_key("x-xss-protection") {
                vulns.push(create_header_vuln(
                    &page.url,
                    "X-XSS-Protection",
                    "Missing",
                    "1; mode=block",
                    "INFO",
                    "Legacy XSS filter header is absent. Modern browsers rely on CSP instead.",
                ));
            }

            // Referrer-Policy
            if !headers.contains_key("referrer-policy") {
                vulns.push(create_header_vuln(
                    &page.url,
                    "Referrer-Policy",
                    "Missing",
                    "strict-origin-when-cross-origin",
                    "LOW",
                    "Without Referrer-Policy, sensitive URL data may leak to external sites.",
                ));
            }

            // Permissions-Policy
            if !headers.contains_key("permissions-policy") && !headers.contains_key("feature-policy") {
                vulns.push(create_header_vuln(
                    &page.url,
                    "Permissions-Policy",
                    "Missing",
                    "camera=(), microphone=(), geolocation=()",
                    "LOW",
                    "Without Permissions-Policy, the browser may grant access to powerful features.",
                ));
            }

            // Cache-Control for sensitive pages
            if page.url.contains("login") || page.url.contains("account") || page.url.contains("admin") {
                let has_no_store = headers.get("cache-control")
                    .map(|v| v.contains("no-store"))
                    .unwrap_or(false);

                if !has_no_store {
                    vulns.push(create_header_vuln(
                        &page.url,
                        "Cache-Control",
                        headers.get("cache-control").map(|s| s.as_str()).unwrap_or("Missing"),
                        "no-store, no-cache, must-revalidate",
                        "LOW",
                        "Sensitive page may be cached by browsers or proxies.",
                    ));
                }
            }

            // Server header information disclosure
            if let Some(server) = headers.get("server") {
                if server.contains('/') {
                    vulns.push(create_header_vuln(
                        &page.url,
                        "Server",
                        &format!("Exposes version: {}", server),
                        "Remove version information",
                        "INFO",
                        "Server header reveals software version, aiding attackers in targeting known vulnerabilities.",
                    ));
                }
            }

            // X-Powered-By information disclosure
            if headers.contains_key("x-powered-by") {
                let val = headers.get("x-powered-by").unwrap();
                vulns.push(create_header_vuln(
                    &page.url,
                    "X-Powered-By",
                    &format!("Present: {}", val),
                    "Remove this header entirely",
                    "INFO",
                    "X-Powered-By header reveals technology stack information.",
                ));
            }

            // Check cookies for security flags
            for (name, value) in &page.headers {
                if name.to_lowercase() == "set-cookie" {
                    let cookie_lower = value.to_lowercase();
                    let cookie_name = value.split('=').next().unwrap_or("unknown");

                    if !cookie_lower.contains("httponly") {
                        vulns.push(create_cookie_vuln(
                            &page.url,
                            cookie_name,
                            "HttpOnly flag missing",
                            "Cookie accessible via JavaScript, increasing XSS impact.",
                            "LOW",
                        ));
                    }

                    if page.url.starts_with("https") && !cookie_lower.contains("secure") {
                        vulns.push(create_cookie_vuln(
                            &page.url,
                            cookie_name,
                            "Secure flag missing",
                            "Cookie may be transmitted over unencrypted HTTP connections.",
                            "LOW",
                        ));
                    }
                }
            }
        }

        Ok(vulns)
    }
}

fn has_frame_ancestors_csp(headers: &std::collections::HashMap<String, String>) -> bool {
    headers.get("content-security-policy")
        .map(|csp| csp.contains("frame-ancestors"))
        .unwrap_or(false)
}

fn create_header_vuln(url: &str, header: &str, status: &str, recommended: &str, severity: &str, desc: &str) -> Vulnerability {
    let mut vuln = Vulnerability::new(
        &format!("Security Header: {}", header),
        "Security Misconfiguration",
        severity,
        url,
    );
    vuln.evidence = format!("Header: {} | Status: {} | Recommended: {}", header, status, recommended);
    vuln.description = desc.to_string();
    vuln.remediation = format!(
        "Add or fix the {} header.\nRecommended value: {}\n\
         Configure this in your web server (Apache: Header set, Nginx: add_header) \
         or application framework.", header, recommended
    );
    vuln.cwe_id = Some("CWE-693".to_string());
    vuln.references = vec![
        "https://owasp.org/www-project-secure-headers/".to_string(),
        format!("https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/{}", header),
    ];
    vuln
}

fn create_cookie_vuln(url: &str, cookie_name: &str, issue: &str, desc: &str, severity: &str) -> Vulnerability {
    let mut vuln = Vulnerability::new(
        &format!("Insecure Cookie: {} - {}", cookie_name, issue),
        "Security Misconfiguration",
        severity,
        url,
    );
    vuln.evidence = format!("Cookie '{}': {}", cookie_name, issue);
    vuln.description = desc.to_string();
    vuln.remediation = format!(
        "Set proper security flags on cookie '{}':\n\
         Set-Cookie: {}=value; HttpOnly; Secure; SameSite=Lax; Path=/", cookie_name, cookie_name
    );
    vuln.cwe_id = Some("CWE-614".to_string());
    vuln
}