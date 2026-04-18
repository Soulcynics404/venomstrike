use reqwest::header::HeaderMap;
use crate::reporting::models::Technology;

pub fn detect_waf(headers: &HeaderMap, body: &str) -> Option<Technology> {
    // Cloudflare
    if headers.get("cf-ray").is_some() || headers.get("cf-cache-status").is_some() {
        return Some(Technology {
            name: "Cloudflare WAF".to_string(),
            version: None,
            category: "WAF".to_string(),
            cpe: None,
            confidence: 95,
        });
    }

    // AWS WAF
    if headers.get("x-amzn-requestid").is_some() {
        return Some(Technology {
            name: "AWS WAF".to_string(),
            version: None,
            category: "WAF".to_string(),
            cpe: None,
            confidence: 70,
        });
    }

    // Akamai
    if headers.get("x-akamai-transformed").is_some() {
        return Some(Technology {
            name: "Akamai".to_string(),
            version: None,
            category: "WAF/CDN".to_string(),
            cpe: None,
            confidence: 90,
        });
    }

    // Sucuri
    if headers.iter().any(|(_, v)| v.to_str().unwrap_or("").contains("sucuri")) {
        return Some(Technology {
            name: "Sucuri WAF".to_string(),
            version: None,
            category: "WAF".to_string(),
            cpe: None,
            confidence: 90,
        });
    }

    // ModSecurity
    if headers.get("server").map(|v| v.to_str().unwrap_or("").contains("mod_security")).unwrap_or(false)
        || body.contains("mod_security")
        || body.contains("ModSecurity")
    {
        return Some(Technology {
            name: "ModSecurity".to_string(),
            version: None,
            category: "WAF".to_string(),
            cpe: None,
            confidence: 85,
        });
    }

    // Imperva/Incapsula
    if headers.get("x-iinfo").is_some() || headers.get("x-cdn").map(|v| v.to_str().unwrap_or("").contains("Incapsula")).unwrap_or(false) {
        return Some(Technology {
            name: "Imperva Incapsula".to_string(),
            version: None,
            category: "WAF".to_string(),
            cpe: None,
            confidence: 90,
        });
    }

    None
}