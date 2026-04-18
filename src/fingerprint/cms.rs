use reqwest::Client;
use reqwest::header::HeaderMap;
use crate::core::rate_limiter::VenomRateLimiter;
use crate::reporting::models::Technology;
use crate::error::VenomResult;
use regex::Regex;

pub async fn detect_cms(
    target: &str,
    client: &Client,
    rate_limiter: &VenomRateLimiter,
    _headers: &HeaderMap,
    body: &str,
) -> VenomResult<Vec<Technology>> {
    let mut techs = Vec::new();

    // WordPress detection — require STRONG signals in the homepage body
    let wp_signals: Vec<&str> = vec!["wp-content", "wp-includes", "/wp-json/", "wp-emoji"];
    let wp_count = wp_signals.iter().filter(|s| body.contains(**s)).count();

    if wp_count >= 2 {
        // Need at least 2 signals to confirm WordPress
        let version = extract_wp_version(body);
        techs.push(Technology {
            name: "WordPress".to_string(),
            version,
            category: "CMS".to_string(),
            cpe: Some("cpe:2.3:a:wordpress:wordpress".to_string()),
            confidence: 95,
        });
    }

    // Joomla detection — require body signals, not just path existence
    let joomla_signals: Vec<&str> = vec!["/media/jui/", "Joomla!", "/components/com_", "joomla-"];
    let joomla_count = joomla_signals.iter().filter(|s| body.contains(**s)).count();

    if joomla_count >= 2 {
        techs.push(Technology {
            name: "Joomla".to_string(),
            version: None,
            category: "CMS".to_string(),
            cpe: Some("cpe:2.3:a:joomla:joomla".to_string()),
            confidence: 85,
        });
    }

    // Drupal detection — require body signals
    let drupal_signals: Vec<&str> = vec!["/sites/default/", "drupal.js", "Drupal.settings", "/core/misc/drupal.js"];
    let drupal_count = drupal_signals.iter().filter(|s| body.contains(**s)).count();

    if drupal_count >= 2 {
        techs.push(Technology {
            name: "Drupal".to_string(),
            version: None,
            category: "CMS".to_string(),
            cpe: Some("cpe:2.3:a:drupal:drupal".to_string()),
            confidence: 85,
        });
    }

    // Path-based checks — ONLY confirm if the response body contains CMS-specific content
    // NOT just checking for 200/302 status codes (which could be login redirects)
    let cms_path_checks: Vec<(&str, &str, &str)> = vec![
        ("/wp-login.php", "WordPress", "wp-login"),
        ("/wp-admin/", "WordPress", "wp-login"),
        ("/administrator/", "Joomla", "mod-login"),
        ("/user/login", "Drupal", "drupal"),
    ];

    for (path, cms_name, body_marker) in &cms_path_checks {
        // Skip if already detected
        if techs.iter().any(|t| t.name == *cms_name) {
            continue;
        }

        let url = format!("{}{}", target.trim_end_matches('/'), path);
        rate_limiter.until_ready().await;

        if let Ok(resp) = client.get(&url).send().await {
            if resp.status().is_success() || resp.status().as_u16() == 302 {
                if let Ok(resp_body) = resp.text().await {
                    // CRITICAL FIX: Verify the response actually contains CMS markers
                    if resp_body.to_lowercase().contains(body_marker) {
                        techs.push(Technology {
                            name: cms_name.to_string(),
                            version: None,
                            category: "CMS".to_string(),
                            cpe: None,
                            confidence: 80,
                        });
                    }
                }
            }
        }
    }

    // Check package.json ONLY if it returns valid JSON (not a 404 page or redirect)
    let pkg_url = format!("{}/package.json", target.trim_end_matches('/'));
    rate_limiter.until_ready().await;
    if let Ok(resp) = client.get(&pkg_url).send().await {
        if resp.status().is_success() {
            if let Ok(text) = resp.text().await {
                // Verify it's actual JSON and not an HTML error page
                if text.trim().starts_with('{') {
                    if let Ok(json) = serde_json::from_str::<serde_json::Value>(&text) {
                        if let Some(deps) = json.get("dependencies").and_then(|d| d.as_object()) {
                            for (name, version) in deps {
                                let v = version.as_str().map(|s| {
                                    s.trim_start_matches('^')
                                     .trim_start_matches('~')
                                     .trim_start_matches('>')
                                     .trim_start_matches('=')
                                     .to_string()
                                });
                                techs.push(Technology {
                                    name: name.clone(),
                                    version: v,
                                    category: "JavaScript Library".to_string(),
                                    cpe: None,
                                    confidence: 100,
                                });
                            }
                        }
                    }
                }
            }
        }
    }

    Ok(techs)
}

fn extract_wp_version(body: &str) -> Option<String> {
    let re = Regex::new(r#"content="WordPress\s+([\d\.]+)"#).ok()?;
    re.captures(body).and_then(|c| c.get(1).map(|m| m.as_str().to_string()))
}