use async_trait::async_trait;
use crate::scanners::traits::VulnerabilityScanner;
use crate::core::crawler::CrawledPage;
use crate::reporting::models::Vulnerability;
use crate::error::VenomResult;

pub struct CsrfScanner;

impl CsrfScanner {
    pub fn new() -> Self { Self }
}

#[async_trait]
impl VulnerabilityScanner for CsrfScanner {
    fn name(&self) -> &str { "CSRF Scanner" }
    fn description(&self) -> &str { "Detects missing CSRF protection on state-changing forms" }

    async fn scan(
        &self,
        pages: &[CrawledPage],
        _client: &reqwest::Client,
    ) -> VenomResult<Vec<Vulnerability>> {
        let mut vulns = Vec::new();

        let csrf_token_names = vec![
            "csrf", "xsrf", "_token", "authenticity_token", "csrf_token",
            "csrfmiddlewaretoken", "__requestverificationtoken", "_csrf",
            "antiforgery", "anti-csrf", "token", "nonce", "__csrf_magic",
        ];

        for page in pages {
            for form in &page.forms {
                if form.method != "POST" {
                    continue;
                }

                let has_csrf_token = form.inputs.iter().any(|input| {
                    let name_lower = input.name.to_lowercase();
                    csrf_token_names.iter().any(|token_name| name_lower.contains(token_name))
                });

                if !has_csrf_token {
                    let is_sensitive = is_sensitive_form(&form.action, &form.inputs);

                    if is_sensitive {
                        let input_names: Vec<String> = form.inputs.iter()
                            .map(|i| i.name.clone())
                            .collect();

                        vulns.push(create_csrf_vuln(
                            &form.action,
                            &format!("POST form at {} has no CSRF token. Inputs: {:?}", form.action, input_names),
                            &page.url,
                        ));
                    }
                }
            }

            // Check for SameSite cookie attribute
            for (header_name, header_value) in &page.headers {
                if header_name.to_lowercase() == "set-cookie" {
                    let cookie_lower = header_value.to_lowercase();
                    if !cookie_lower.contains("samesite") {
                        let cookie_name = header_value.split('=').next().unwrap_or("unknown");
                        vulns.push(create_cookie_csrf_vuln(
                            &page.url,
                            &format!("Cookie '{}' missing SameSite attribute", cookie_name),
                        ));
                    }
                }
            }
        }

        vulns.dedup_by(|a, b| a.url == b.url && a.title == b.title);
        Ok(vulns)
    }
}

fn is_sensitive_form(action: &str, inputs: &[crate::core::crawler::FormInput]) -> bool {
    let sensitive_actions = vec![
        "login", "signup", "register", "password", "profile", "settings",
        "account", "admin", "delete", "update", "edit", "create", "upload",
        "transfer", "payment", "checkout", "order", "subscribe",
    ];

    let action_lower = action.to_lowercase();
    if sensitive_actions.iter().any(|s| action_lower.contains(s)) {
        return true;
    }

    let sensitive_inputs = vec![
        "password", "email", "amount", "transfer", "delete", "admin", "role", "permission",
    ];

    inputs.iter().any(|input| {
        let name_lower = input.name.to_lowercase();
        sensitive_inputs.iter().any(|s| name_lower.contains(s))
    })
}

fn create_csrf_vuln(url: &str, evidence: &str, source_page: &str) -> Vulnerability {
    let mut vuln = Vulnerability::new("Missing CSRF Protection", "CSRF", "MEDIUM", url);
    vuln.evidence = evidence.to_string();
    vuln.description = format!(
        "A state-changing POST form found on {} lacks CSRF token protection. \
         An attacker could craft a malicious page that submits this form on behalf of authenticated users.",
        source_page
    );
    vuln.impact = "An attacker can perform unauthorized actions on behalf of authenticated users, \
         such as changing passwords, transferring funds, or modifying account settings.".to_string();
    vuln.remediation = "1. Implement anti-CSRF tokens (synchronizer token pattern)\n\
         2. Use SameSite cookie attribute (Strict or Lax)\n\
         3. Verify the Origin and Referer headers\n\
         4. Use framework-provided CSRF protection (Django CSRF, Rails protect_from_forgery)\n\
         5. Consider double-submit cookie pattern as additional defense".to_string();
    vuln.cwe_id = Some("CWE-352".to_string());
    vuln.references = vec![
        "https://owasp.org/www-community/attacks/csrf".to_string(),
        "https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html".to_string(),
    ];
    vuln
}

fn create_cookie_csrf_vuln(url: &str, evidence: &str) -> Vulnerability {
    let mut vuln = Vulnerability::new("Cookie Missing SameSite Attribute", "CSRF", "LOW", url);
    vuln.evidence = evidence.to_string();
    vuln.description = "A session cookie is set without the SameSite attribute, which provides \
         browser-level CSRF protection.".to_string();
    vuln.impact = "Without SameSite, cookies are sent with all cross-origin requests, \
         making CSRF attacks easier.".to_string();
    vuln.remediation = "Set the SameSite attribute to 'Strict' or 'Lax' on all session cookies.\n\
         Example: Set-Cookie: session=abc123; SameSite=Lax; Secure; HttpOnly".to_string();
    vuln.cwe_id = Some("CWE-1275".to_string());
    vuln
}