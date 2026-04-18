use reqwest::header::HeaderMap;
use regex::Regex;
use crate::reporting::models::Technology;

pub fn detect_server(headers: &HeaderMap) -> Option<Technology> {
    if let Some(server) = headers.get("server") {
        let server_str = server.to_str().unwrap_or("");

        let (name, version) = parse_server_string(server_str);

        return Some(Technology {
            name,
            version,
            category: "Web Server".to_string(),
            cpe: None,
            confidence: 90,
        });
    }
    None
}

fn parse_server_string(s: &str) -> (String, Option<String>) {
    let re = Regex::new(r"^([a-zA-Z\-]+)/?(\d+[\.\d]*)?\s*").unwrap();

    if let Some(caps) = re.captures(s) {
        let name = caps.get(1).map(|m| m.as_str().to_string()).unwrap_or(s.to_string());
        let version = caps.get(2).map(|m| m.as_str().to_string());
        (name, version)
    } else {
        (s.to_string(), None)
    }
}