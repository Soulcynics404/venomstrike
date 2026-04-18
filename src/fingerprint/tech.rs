use reqwest::header::HeaderMap;
use regex::Regex;
use crate::reporting::models::Technology;

pub fn detect_technologies(headers: &HeaderMap, body: &str) -> Vec<Technology> {
    let mut techs = Vec::new();

    // X-Powered-By header
    if let Some(powered_by) = headers.get("x-powered-by") {
        let val = powered_by.to_str().unwrap_or("");
        if val.contains("PHP") {
            let version = Regex::new(r"PHP/([\d\.]+)").ok()
                .and_then(|re| re.captures(val))
                .and_then(|c| c.get(1).map(|m| m.as_str().to_string()));
            techs.push(Technology {
                name: "PHP".to_string(),
                version,
                category: "Programming Language".to_string(),
                cpe: Some("cpe:2.3:a:php:php".to_string()),
                confidence: 95,
            });
        }
        if val.contains("Express") {
            techs.push(Technology {
                name: "Express.js".to_string(),
                version: None,
                category: "Web Framework".to_string(),
                cpe: None,
                confidence: 90,
            });
        }
        if val.contains("ASP.NET") {
            techs.push(Technology {
                name: "ASP.NET".to_string(),
                version: None,
                category: "Web Framework".to_string(),
                cpe: None,
                confidence: 95,
            });
        }
    }

    // X-AspNet-Version
    if let Some(aspnet) = headers.get("x-aspnet-version") {
        techs.push(Technology {
            name: "ASP.NET".to_string(),
            version: aspnet.to_str().ok().map(|s| s.to_string()),
            category: "Web Framework".to_string(),
            cpe: None,
            confidence: 95,
        });
    }

    // X-Generator
    if let Some(gen) = headers.get("x-generator") {
        let val = gen.to_str().unwrap_or("");
        techs.push(Technology {
            name: val.to_string(),
            version: None,
            category: "Generator".to_string(),
            cpe: None,
            confidence: 80,
        });
    }

    // Body analysis for JS frameworks
    let js_patterns: Vec<(&str, &str, &str)> = vec![
        (r"react", "React", "JavaScript Framework"),
        (r"angular", "Angular", "JavaScript Framework"),
        (r"vue\.js|vuejs", "Vue.js", "JavaScript Framework"),
        (r"jquery[/-]([\d\.]+)", "jQuery", "JavaScript Library"),
        (r"bootstrap[/-]([\d\.]+)", "Bootstrap", "CSS Framework"),
        (r"next\.js|__NEXT_DATA__", "Next.js", "JavaScript Framework"),
        (r"nuxt", "Nuxt.js", "JavaScript Framework"),
        (r"svelte", "Svelte", "JavaScript Framework"),
        (r"ember", "Ember.js", "JavaScript Framework"),
        (r"backbone", "Backbone.js", "JavaScript Library"),
        (r"lodash", "Lodash", "JavaScript Library"),
        (r"moment\.js", "Moment.js", "JavaScript Library"),
    ];

    for (pattern, name, category) in &js_patterns {
        if let Ok(re) = Regex::new(&format!("(?i){}", pattern)) {
            if re.is_match(body) {
                // Try to extract version
                let version_re = Regex::new(&format!(r"(?i){}[/-]v?([\d]+\.[\d]+\.?[\d]*)", name.to_lowercase())).ok();
                let version = version_re.and_then(|re| {
                    re.captures(body).and_then(|c| c.get(1).map(|m| m.as_str().to_string()))
                });

                if !techs.iter().any(|t| t.name == *name) {
                    techs.push(Technology {
                        name: name.to_string(),
                        version,
                        category: category.to_string(),
                        cpe: None,
                        confidence: 70,
                    });
                }
            }
        }
    }

    // Detect programming language from headers/cookies
    if let Some(cookie_header) = headers.get("set-cookie") {
        let cookie_val = cookie_header.to_str().unwrap_or("");
        if cookie_val.contains("PHPSESSID") {
            if !techs.iter().any(|t| t.name == "PHP") {
                techs.push(Technology {
                    name: "PHP".to_string(),
                    version: None,
                    category: "Programming Language".to_string(),
                    cpe: Some("cpe:2.3:a:php:php".to_string()),
                    confidence: 80,
                });
            }
        }
        if cookie_val.contains("JSESSIONID") {
            techs.push(Technology {
                name: "Java".to_string(),
                version: None,
                category: "Programming Language".to_string(),
                cpe: None,
                confidence: 80,
            });
        }
        if cookie_val.contains("ASP.NET_SessionId") {
            if !techs.iter().any(|t| t.name == "ASP.NET") {
                techs.push(Technology {
                    name: "ASP.NET".to_string(),
                    version: None,
                    category: "Web Framework".to_string(),
                    cpe: None,
                    confidence: 80,
                });
            }
        }
        if cookie_val.contains("csrftoken") || cookie_val.contains("django") {
            techs.push(Technology {
                name: "Django".to_string(),
                version: None,
                category: "Web Framework".to_string(),
                cpe: None,
                confidence: 75,
            });
        }
        if cookie_val.contains("_rails") || cookie_val.contains("rack.session") {
            techs.push(Technology {
                name: "Ruby on Rails".to_string(),
                version: None,
                category: "Web Framework".to_string(),
                cpe: None,
                confidence: 75,
            });
        }
    }

    // Meta generator tag
    if let Ok(re) = Regex::new(r#"<meta[^>]+name=["']generator["'][^>]+content=["']([^"']+)["']"#) {
        if let Some(caps) = re.captures(body) {
            if let Some(gen) = caps.get(1) {
                techs.push(Technology {
                    name: gen.as_str().to_string(),
                    version: None,
                    category: "Generator".to_string(),
                    cpe: None,
                    confidence: 90,
                });
            }
        }
    }

    techs
}