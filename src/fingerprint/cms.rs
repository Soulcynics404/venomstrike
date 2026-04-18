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

    // WordPress detection
    if body.contains("wp-content") || body.contains("wp-includes") || body.contains("/wp-json/") {
        let version = extract_wp_version(body);
        techs.push(Technology {
            name: "WordPress".to_string(),
            version,
            category: "CMS".to_string(),
            cpe: Some("cpe:2.3:a:wordpress:wordpress".to_string()),
            confidence: 95,
        });
    }

    // Joomla detection
    if body.contains("/media/jui/") || body.contains("Joomla!") || body.contains("/administrator/") {
        techs.push(Technology {
            name: "Joomla".to_string(),
            version: None,
            category: "CMS".to_string(),
            cpe: Some("cpe:2.3:a:joomla:joomla".to_string()),
            confidence: 85,
        });
    }

    // Drupal detection
    if body.contains("Drupal") || body.contains("/sites/default/") || body.contains("drupal.js") {
        techs.push(Technology {
            name: "Drupal".to_string(),
            version: None,
            category: "CMS".to_string(),
            cpe: Some("cpe:2.3:a:drupal:drupal".to_string()),
            confidence: 85,
        });
    }

    // Check common paths
    let cms_paths = vec![
        ("/wp-admin/", "WordPress"),
        ("/wp-login.php", "WordPress"),
        ("/administrator/", "Joomla"),
        ("/user/login", "Drupal"),
        ("/ghost/", "Ghost"),
        ("/admin/login", "Django Admin"),
    ];

    for (path, cms_name) in cms_paths {
        let url = format!("{}{}", target.trim_end_matches('/'), path);
        rate_limiter.until_ready().await;
        if let Ok(resp) = client.get(&url).send().await {
            if resp.status().is_success() || resp.status().as_u16() == 302 {
                if !techs.iter().any(|t| t.name == cms_name) {
                    techs.push(Technology {
                        name: cms_name.to_string(),
                        version: None,
                        category: "CMS".to_string(),
                        cpe: None,
                        confidence: 70,
                    });
                }
            }
        }
    }

    // Check package.json for JS frameworks
    let pkg_url = format!("{}/package.json", target.trim_end_matches('/'));
    rate_limiter.until_ready().await;
    if let Ok(resp) = client.get(&pkg_url).send().await {
        if resp.status().is_success() {
            if let Ok(text) = resp.text().await {
                if let Ok(json) = serde_json::from_str::<serde_json::Value>(&text) {
                    if let Some(deps) = json.get("dependencies").and_then(|d| d.as_object()) {
                        for (name, version) in deps {
                            let v = version.as_str().map(|s| s.trim_start_matches('^').trim_start_matches('~').to_string());
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

    Ok(techs)
}

fn extract_wp_version(body: &str) -> Option<String> {
    let re = Regex::new(r#"content="WordPress\s+([\d\.]+)"#).ok()?;
    re.captures(body).and_then(|c| c.get(1).map(|m| m.as_str().to_string()))
}