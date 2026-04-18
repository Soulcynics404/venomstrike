use async_trait::async_trait;
use crate::scanners::traits::VulnerabilityScanner;
use crate::core::crawler::CrawledPage;
use crate::reporting::models::Vulnerability;
use crate::error::VenomResult;
use std::time::Duration;

pub struct SslScanner;

impl SslScanner {
    pub fn new() -> Self { Self }
}

#[async_trait]
impl VulnerabilityScanner for SslScanner {
    fn name(&self) -> &str { "SSL/TLS Scanner" }
    fn description(&self) -> &str { "Checks SSL/TLS configuration and certificate issues" }

    async fn scan(
        &self,
        pages: &[CrawledPage],
        _client: &reqwest::Client,
    ) -> VenomResult<Vec<Vulnerability>> {
        let mut vulns = Vec::new();
        let mut checked_hosts = std::collections::HashSet::new();

        for page in pages {
            let parsed = match url::Url::parse(&page.url) {
                Ok(u) => u,
                Err(_) => continue,
            };

            if parsed.scheme() != "https" {
                // Check if HTTPS is available
                let https_url = page.url.replace("http://", "https://");
                let test_client = reqwest::Client::builder()
                    .timeout(Duration::from_secs(5))
                    .danger_accept_invalid_certs(true)
                    .build()
                    .unwrap();

                if test_client.get(&https_url).send().await.is_ok() {
                    vulns.push(create_ssl_vuln(
                        &page.url,
                        "HTTP Used Instead of HTTPS",
                        "HIGH",
                        "The application is accessed over HTTP but HTTPS is available.",
                        "All traffic is transmitted in cleartext, exposing sensitive data to interception.",
                        "Redirect all HTTP traffic to HTTPS. Configure HSTS header.",
                    ));
                } else {
                    vulns.push(create_ssl_vuln(
                        &page.url,
                        "HTTPS Not Available",
                        "HIGH",
                        "The application does not support HTTPS encryption.",
                        "All traffic including credentials and session tokens is unencrypted.",
                        "Obtain and install an SSL/TLS certificate. Consider Let's Encrypt for free certificates.",
                    ));
                }
                continue;
            }

            let host = match parsed.host_str() {
                Some(h) => h.to_string(),
                None => continue,
            };

            if checked_hosts.contains(&host) {
                continue;
            }
            checked_hosts.insert(host.clone());

            let port = parsed.port().unwrap_or(443);

            // Connect and check certificate
            match check_certificate(&host, port).await {
                Ok(cert_info) => {
                    // Check expiration
                    if cert_info.days_until_expiry < 0 {
                        vulns.push(create_ssl_vuln(
                            &page.url,
                            "SSL Certificate Expired",
                            "CRITICAL",
                            &format!("Certificate expired {} days ago. Issuer: {}", -cert_info.days_until_expiry, cert_info.issuer),
                            "Users will see security warnings. MITM attacks become trivial.",
                            "Renew the SSL certificate immediately.",
                        ));
                    } else if cert_info.days_until_expiry < 30 {
                        vulns.push(create_ssl_vuln(
                            &page.url,
                            "SSL Certificate Expiring Soon",
                            "MEDIUM",
                            &format!("Certificate expires in {} days. Issuer: {}", cert_info.days_until_expiry, cert_info.issuer),
                            "Certificate will expire soon, potentially causing service disruption.",
                            "Renew the SSL certificate before expiration. Consider setting up auto-renewal.",
                        ));
                    }

                    // Check self-signed
                    if cert_info.is_self_signed {
                        vulns.push(create_ssl_vuln(
                            &page.url,
                            "Self-Signed SSL Certificate",
                            "MEDIUM",
                            "The SSL certificate is self-signed and not trusted by browsers.",
                            "Users will see security warnings. Cannot verify server identity.",
                            "Replace with a certificate from a trusted Certificate Authority.",
                        ));
                    }

                    // Check hostname mismatch
                    if !cert_info.hostname_match {
                        vulns.push(create_ssl_vuln(
                            &page.url,
                            "SSL Certificate Hostname Mismatch",
                            "HIGH",
                            &format!("Certificate CN/SAN does not match hostname '{}'", host),
                            "Browsers will reject the connection. Indicates possible misconfiguration.",
                            "Obtain a certificate that includes the correct hostname in CN or SAN.",
                        ));
                    }
                }
                Err(e) => {
                    log::warn!("SSL check failed for {}: {}", host, e);
                }
            }

            // Test for HTTP access (mixed content / no redirect)
            let http_url = format!("http://{}:{}", host, if port == 443 { 80 } else { port });
            let no_redirect = reqwest::Client::builder()
                .redirect(reqwest::redirect::Policy::none())
                .timeout(Duration::from_secs(5))
                .build()
                .unwrap();

            if let Ok(resp) = no_redirect.get(&http_url).send().await {
                let status = resp.status().as_u16();
                if status == 200 {
                    vulns.push(create_ssl_vuln(
                        &page.url,
                        "HTTP Not Redirected to HTTPS",
                        "MEDIUM",
                        "HTTP requests return 200 OK instead of redirecting to HTTPS.",
                        "Users accessing HTTP version are not protected by encryption.",
                        "Configure HTTP to HTTPS redirect (301) for all paths.",
                    ));
                }
            }
        }

        Ok(vulns)
    }
}

struct CertInfo {
    days_until_expiry: i64,
    issuer: String,
    is_self_signed: bool,
    hostname_match: bool,
}

async fn check_certificate(host: &str, port: u16) -> Result<CertInfo, Box<dyn std::error::Error + Send + Sync>> {
    let connector = native_tls::TlsConnector::builder()
        .danger_accept_invalid_certs(true)
        .danger_accept_invalid_hostnames(true)
        .build()?;

    let stream = tokio::net::TcpStream::connect(format!("{}:{}", host, port)).await?;
    let connector = tokio_native_tls::TlsConnector::from(connector);
    let tls_stream = connector.connect(host, stream).await?;

    let cert = tls_stream.get_ref()
        .peer_certificate()?
        .ok_or("No certificate found")?;

    let der = cert.to_der()?;

    // Parse with x509-parser
    let (_, x509_cert) = x509_parser::parse_x509_certificate(&der)
        .map_err(|e| format!("X509 parse error: {:?}", e))?;

    let not_after = x509_cert.validity().not_after.timestamp();
    let now = chrono::Utc::now().timestamp();
    let days_until_expiry = (not_after - now) / 86400;

    let issuer = x509_cert.issuer().to_string();
    let subject = x509_cert.subject().to_string();

    let is_self_signed = issuer == subject;
    let hostname_match = subject.contains(host) || check_san(host, &x509_cert);

    Ok(CertInfo {
        days_until_expiry,
        issuer,
        is_self_signed,
        hostname_match,
    })
}

fn check_san(host: &str, cert: &x509_parser::certificate::X509Certificate) -> bool {
    if let Ok(Some(san)) = cert.subject_alternative_name() {
        for name in &san.value.general_names {
            match name {
                x509_parser::extensions::GeneralName::DNSName(dns) => {
                    if *dns == host || (dns.starts_with("*.") && host.ends_with(&dns[1..])) {
                        return true;
                    }
                }
                _ => {}
            }
        }
    }
    false
}

fn create_ssl_vuln(url: &str, title: &str, severity: &str, desc: &str, impact: &str, remediation: &str) -> Vulnerability {
    let mut vuln = Vulnerability::new(title, "SSL/TLS", severity, url);
    vuln.description = desc.to_string();
    vuln.impact = impact.to_string();
    vuln.remediation = remediation.to_string();
    vuln.evidence = desc.to_string();
    vuln.cwe_id = Some("CWE-295".to_string());
    vuln.references = vec![
        "https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/09-Testing_for_Weak_Cryptography/01-Testing_for_Weak_Transport_Layer_Security".to_string(),
    ];
    vuln
}