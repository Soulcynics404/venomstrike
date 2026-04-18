use async_trait::async_trait;
use std::path::{Path, PathBuf};
use crate::scanners::traits::VulnerabilityScanner;
use crate::core::crawler::CrawledPage;
use crate::reporting::models::Vulnerability;
use crate::error::VenomResult;

pub struct SstiScanner {
    payloads_path: PathBuf,
}

impl SstiScanner {
    pub fn new(payloads_path: &Path) -> Self {
        Self { payloads_path: payloads_path.to_path_buf() }
    }

    fn load_payloads(&self) -> Vec<SstiPayload> {
        if let Ok(content) = std::fs::read_to_string(&self.payloads_path) {
            content.lines()
                .filter(|l| !l.trim().is_empty() && !l.starts_with('#'))
                .map(|l| SstiPayload { payload: l.trim().to_string(), expected: None })
                .collect()
        } else {
            default_ssti_payloads()
        }
    }
}

struct SstiPayload {
    payload: String,
    expected: Option<String>,
}

#[async_trait]
impl VulnerabilityScanner for SstiScanner {
    fn name(&self) -> &str { "SSTI Scanner" }
    fn description(&self) -> &str { "Tests for Server-Side Template Injection vulnerabilities" }

    async fn scan(
        &self,
        pages: &[CrawledPage],
        client: &reqwest::Client,
    ) -> VenomResult<Vec<Vulnerability>> {
        let mut vulns = Vec::new();

        // Math-based detection payloads with expected results
        let detection_payloads = vec![
            ("{{7*7}}", "49"),
            ("${7*7}", "49"),
            ("#{7*7}", "49"),
            ("<%= 7*7 %>", "49"),
            ("{{7*'7'}}", "7777777"),   // Jinja2 specific
            ("${7*7}", "49"),
            ("{7*7}", "49"),
            ("{{config}}", "SECRET_KEY"), // Flask/Jinja2
        ];

        for page in pages {
            for (param_name, _) in &page.params {
                for (payload, expected) in &detection_payloads {
                    let test_url = inject_param(&page.url, param_name, payload);

                    if let Ok(resp) = client.get(&test_url).send().await {
                        if let Ok(body) = resp.text().await {
                            if body.contains(expected) && !page.body.contains(expected) {
                                let template_engine = identify_template_engine(payload, &body);

                                vulns.push(create_ssti_vuln(
                                    &page.url, param_name, payload,
                                    &format!("Template expression evaluated. Expected '{}' found in response. Engine: {}", expected, template_engine),
                                ));
                                break;
                            }
                        }
                    }
                }
            }

            // Test forms
            for form in &page.forms {
                for input in &form.inputs {
                    if input.input_type == "hidden" || input.input_type == "submit" {
                        continue;
                    }

                    for (payload, expected) in &detection_payloads {
                        let mut form_data = std::collections::HashMap::new();
                        for inp in &form.inputs {
                            if inp.name == input.name {
                                form_data.insert(inp.name.clone(), payload.to_string());
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
                                if body.contains(expected) {
                                    vulns.push(create_ssti_vuln(
                                        &form.action, &input.name, payload,
                                        &format!("SSTI in form: expression evaluated to '{}'", expected),
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

fn identify_template_engine(payload: &str, body: &str) -> String {
    if payload.starts_with("{{") && body.contains("49") {
        if body.contains("7777777") { return "Jinja2/Twig".to_string(); }
        return "Jinja2/Twig/Handlebars".to_string();
    }
    if payload.starts_with("${") { return "FreeMarker/Velocity/Mako".to_string(); }
    if payload.starts_with("<%=") { return "ERB/JSP".to_string(); }
    if payload.starts_with("#{") { return "Pebble/Thymeleaf".to_string(); }
    "Unknown".to_string()
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

fn create_ssti_vuln(url: &str, param: &str, payload: &str, evidence: &str) -> Vulnerability {
    let mut vuln = Vulnerability::new("Server-Side Template Injection (SSTI)", "SSTI", "CRITICAL", url);
    vuln.parameter = Some(param.to_string());
    vuln.payload = Some(payload.to_string());
    vuln.evidence = evidence.to_string();
    vuln.description = format!(
        "Server-Side Template Injection was detected in the '{}' parameter. \
         User input is being embedded into server-side template expressions and evaluated.", param
    );
    vuln.impact = "An attacker can execute arbitrary code on the server, read sensitive files, \
         and potentially achieve full Remote Code Execution.".to_string();
    vuln.remediation = "1. Never pass user input directly into template expressions\n\
         2. Use a logic-less template engine when possible\n\
         3. Sandbox the template environment\n\
         4. Implement strict input validation".to_string();
    vuln.cwe_id = Some("CWE-1336".to_string());
    vuln.references = vec![
        "https://portswigger.net/research/server-side-template-injection".to_string(),
        "https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/07-Input_Validation_Testing/18-Testing_for_Server-side_Template_Injection".to_string(),
    ];
    vuln
}

fn default_ssti_payloads() -> Vec<SstiPayload> {
    vec![
        SstiPayload { payload: "{{7*7}}".to_string(), expected: Some("49".to_string()) },
        SstiPayload { payload: "${7*7}".to_string(), expected: Some("49".to_string()) },
        SstiPayload { payload: "#{7*7}".to_string(), expected: Some("49".to_string()) },
        SstiPayload { payload: "<%= 7*7 %>".to_string(), expected: Some("49".to_string()) },
        SstiPayload { payload: "{{7*'7'}}".to_string(), expected: Some("7777777".to_string()) },
        SstiPayload { payload: "${{7*7}}".to_string(), expected: Some("49".to_string()) },
    ]
}