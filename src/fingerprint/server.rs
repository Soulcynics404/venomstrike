use reqwest::header::HeaderMap;
use regex::Regex;
use crate::reporting::models::Technology;

pub fn detect_server(headers: &HeaderMap) -> Option<Technology> {
    if let Some(server) = headers.get("server") {
        let server_str = server.to_str().unwrap_or("");

        let (name, version, cpe) = parse_server_string(server_str);

        return Some(Technology {
            name,
            version,
            category: "Web Server".to_string(),
            cpe,
            confidence: 90,
        });
    }
    None
}

fn parse_server_string(s: &str) -> (String, Option<String>, Option<String>) {
    let s_lower = s.to_lowercase();

    // Apache
    if s_lower.contains("apache") {
        let version = Regex::new(r"Apache/([\d\.]+)")
            .ok()
            .and_then(|re| re.captures(s))
            .and_then(|c| c.get(1).map(|m| m.as_str().to_string()));

        return (
            "Apache".to_string(),
            version,
            Some("cpe:2.3:a:apache:http_server".to_string()),
        );
    }

    // Nginx
    if s_lower.contains("nginx") {
        let version = Regex::new(r"nginx/([\d\.]+)")
            .ok()
            .and_then(|re| re.captures(s))
            .and_then(|c| c.get(1).map(|m| m.as_str().to_string()));

        return (
            "nginx".to_string(),
            version,
            Some("cpe:2.3:a:f5:nginx".to_string()),
        );
    }

    // IIS
    if s_lower.contains("microsoft-iis") || s_lower.contains("iis") {
        let version = Regex::new(r"IIS/([\d\.]+)")
            .ok()
            .and_then(|re| re.captures(s))
            .and_then(|c| c.get(1).map(|m| m.as_str().to_string()));

        return (
            "IIS".to_string(),
            version,
            Some("cpe:2.3:a:microsoft:internet_information_services".to_string()),
        );
    }

    // LiteSpeed
    if s_lower.contains("litespeed") {
        let version = Regex::new(r"LiteSpeed/([\d\.]+)")
            .ok()
            .and_then(|re| re.captures(s))
            .and_then(|c| c.get(1).map(|m| m.as_str().to_string()));

        return (
            "LiteSpeed".to_string(),
            version,
            Some("cpe:2.3:a:litespeedtech:litespeed_web_server".to_string()),
        );
    }

    // Jetty (Java)
    if s_lower.contains("jetty") {
        let version = Regex::new(r"[Jj]etty\(?v?([\d\.]+)")
            .ok()
            .and_then(|re| re.captures(s))
            .and_then(|c| c.get(1).map(|m| m.as_str().to_string()));

        return (
            "Jetty".to_string(),
            version,
            Some("cpe:2.3:a:eclipse:jetty".to_string()),
        );
    }

    // Generic fallback
    let re = Regex::new(r"^([a-zA-Z\-]+)/?(\d+[\.\d]*)?").unwrap();
    if let Some(caps) = re.captures(s) {
        let name = caps.get(1).map(|m| m.as_str().to_string()).unwrap_or(s.to_string());
        let version = caps.get(2).map(|m| m.as_str().to_string());
        (name, version, None)
    } else {
        (s.to_string(), None, None)
    }
}