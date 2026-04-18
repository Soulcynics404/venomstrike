use serde::Deserialize;
use crate::reporting::models::CveFinding;
use crate::error::VenomResult;

#[derive(Debug, Deserialize)]
struct NvdResponse {
    #[serde(rename = "totalResults")]
    total_results: Option<u32>,
    vulnerabilities: Option<Vec<NvdVulnerability>>,
}

#[derive(Debug, Deserialize)]
struct NvdVulnerability {
    cve: NvdCve,
}

#[derive(Debug, Deserialize)]
struct NvdCve {
    id: String,
    descriptions: Option<Vec<NvdDescription>>,
    metrics: Option<NvdMetrics>,
    weaknesses: Option<Vec<NvdWeakness>>,
    references: Option<Vec<NvdReference>>,
}

#[derive(Debug, Deserialize)]
struct NvdDescription {
    lang: String,
    value: String,
}

#[derive(Debug, Deserialize)]
struct NvdMetrics {
    #[serde(rename = "cvssMetricV31")]
    cvss_v31: Option<Vec<CvssMetric>>,
    #[serde(rename = "cvssMetricV30")]
    cvss_v30: Option<Vec<CvssMetric>>,
    #[serde(rename = "cvssMetricV2")]
    cvss_v2: Option<Vec<CvssMetricV2>>,
}

#[derive(Debug, Deserialize)]
struct CvssMetric {
    #[serde(rename = "cvssData")]
    cvss_data: CvssData,
}

#[derive(Debug, Deserialize)]
struct CvssData {
    #[serde(rename = "baseScore")]
    base_score: f64,
    #[serde(rename = "baseSeverity")]
    base_severity: Option<String>,
}

#[derive(Debug, Deserialize)]
struct CvssMetricV2 {
    #[serde(rename = "cvssData")]
    cvss_data: CvssDataV2,
    #[serde(rename = "baseSeverity")]
    base_severity: Option<String>,
}

#[derive(Debug, Deserialize)]
struct CvssDataV2 {
    #[serde(rename = "baseScore")]
    base_score: f64,
}

#[derive(Debug, Deserialize)]
struct NvdWeakness {
    description: Vec<NvdDescription>,
}

#[derive(Debug, Deserialize)]
struct NvdReference {
    url: String,
    source: Option<String>,
}

/// Map technology names to correct NVD CPE vendor:product pairs
fn get_cpe_mapping(technology: &str) -> Option<(&str, &str)> {
    let tech_lower = technology.to_lowercase();
    match tech_lower.as_str() {
        "apache" | "apache httpd" | "apache http server" => Some(("apache", "http_server")),
        "nginx" => Some(("f5", "nginx")),
        "iis" | "microsoft-iis" => Some(("microsoft", "internet_information_services")),
        "php" => Some(("php", "php")),
        "wordpress" => Some(("wordpress", "wordpress")),
        "joomla" | "joomla!" => Some(("joomla", "joomla\\!")),
        "drupal" => Some(("drupal", "drupal")),
        "jquery" => Some(("jquery", "jquery")),
        "openssl" => Some(("openssl", "openssl")),
        "tomcat" | "apache tomcat" => Some(("apache", "tomcat")),
        "node.js" | "nodejs" => Some(("nodejs", "node.js")),
        "express" | "express.js" => Some(("expressjs", "express")),
        "django" => Some(("djangoproject", "django")),
        "flask" => Some(("palletsprojects", "flask")),
        "ruby on rails" | "rails" => Some(("rubyonrails", "rails")),
        "spring boot" | "spring" => Some(("vmware", "spring_boot")),
        "mysql" => Some(("oracle", "mysql")),
        "postgresql" => Some(("postgresql", "postgresql")),
        "mongodb" => Some(("mongodb", "mongodb")),
        "redis" => Some(("redis", "redis")),
        "elasticsearch" => Some(("elastic", "elasticsearch")),
        "react" => Some(("facebook", "react")),
        "angular" | "angularjs" => Some(("angularjs", "angular.js")),
        "vue.js" | "vuejs" => Some(("vuejs", "vue.js")),
        "bootstrap" => Some(("getbootstrap", "bootstrap")),
        "lodash" => Some(("lodash", "lodash")),
        "moment.js" => Some(("momentjs", "moment")),
        "log4j" => Some(("apache", "log4j")),
        _ => None,
    }
}

pub async fn query_nvd(
    technology: &str,
    version: &str,
    _cpe_prefix: Option<&str>,
    api_key: Option<&str>,
) -> VenomResult<Vec<CveFinding>> {
    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(30))
        .build()
        .unwrap_or_else(|_| reqwest::Client::new());

    let mut findings = Vec::new();
    let base_url = "https://services.nvd.nist.gov/rest/json/cves/2.0";

    // Strategy 1: Try CPE-based search first (most accurate)
    if let Some((vendor, product)) = get_cpe_mapping(technology) {
        let cpe_name = format!(
            "cpe:2.3:a:{}:{}:{}:*:*:*:*:*:*:*",
            vendor, product, version
        );

        log::info!("NVD CPE query: {}", cpe_name);

        let query_url = format!(
            "{}?cpeName={}",
            base_url,
            urlencoding::encode(&cpe_name)
        );

        let result = make_nvd_request(&client, &query_url, api_key, technology, version).await;
        if let Ok(mut cves) = result {
            if !cves.is_empty() {
                findings.append(&mut cves);
                return Ok(findings);
            }
        }

        // Strategy 2: Try virtual match (matches version ranges)
        let cpe_match = format!(
            "cpe:2.3:a:{}:{}:*:*:*:*:*:*:*:*",
            vendor, product
        );

        let query_url = format!(
            "{}?virtualMatchString={}&cvssV3Severity=CRITICAL&cvssV3Severity=HIGH",
            base_url,
            urlencoding::encode(&cpe_match)
        );

        // Rate limit
        tokio::time::sleep(tokio::time::Duration::from_millis(
            if api_key.is_some() { 600 } else { 6500 }
        )).await;

        let result = make_nvd_request(&client, &query_url, api_key, technology, version).await;
        if let Ok(mut cves) = result {
            if !cves.is_empty() {
                findings.append(&mut cves);
                return Ok(findings);
            }
        }
    }

    // Strategy 3: Keyword search as fallback
    let search_term = build_search_term(technology, version);
    let query_url = format!(
        "{}?keywordSearch={}",
        base_url,
        urlencoding::encode(&search_term)
    );

    // Rate limit
    tokio::time::sleep(tokio::time::Duration::from_millis(
        if api_key.is_some() { 600 } else { 6500 }
    )).await;

    log::info!("NVD keyword query: {}", search_term);

    let result = make_nvd_request(&client, &query_url, api_key, technology, version).await;
    if let Ok(mut cves) = result {
        findings.append(&mut cves);
    }

    Ok(findings)
}

fn build_search_term(technology: &str, version: &str) -> String {
    let tech_lower = technology.to_lowercase();
    match tech_lower.as_str() {
        "apache" | "apache httpd" => format!("Apache HTTP Server {}", version),
        "nginx" => format!("nginx {}", version),
        "php" => format!("PHP {}", version),
        "iis" => format!("Microsoft IIS {}", version),
        _ => format!("{} {}", technology, version),
    }
}

async fn make_nvd_request(
    client: &reqwest::Client,
    query_url: &str,
    api_key: Option<&str>,
    technology: &str,
    version: &str,
) -> VenomResult<Vec<CveFinding>> {
    let mut findings = Vec::new();

    let mut request = client.get(query_url)
        .header("User-Agent", "VenomStrike/1.0 Security Scanner");

    if let Some(key) = api_key {
        request = request.header("apiKey", key);
    }

    match request.send().await {
        Ok(response) => {
            let status = response.status();
            if status.is_success() {
                let body = response.text().await.unwrap_or_default();

                match serde_json::from_str::<NvdResponse>(&body) {
                    Ok(nvd_response) => {
                        let total = nvd_response.total_results.unwrap_or(0);
                        log::info!("NVD returned {} results for {} {}", total, technology, version);

                        if let Some(vulns) = nvd_response.vulnerabilities {
                            for vuln in vulns.into_iter().take(50) {
                                let cve = vuln.cve;

                                let description = cve.descriptions
                                    .as_ref()
                                    .and_then(|descs| descs.iter().find(|d| d.lang == "en"))
                                    .map(|d| d.value.clone())
                                    .unwrap_or_else(|| "No description available.".to_string());

                                let (cvss_score, severity) = extract_cvss(&cve.metrics);

                                // Skip NONE/unknown severity
                                if severity == "NONE" || severity == "UNKNOWN" {
                                    continue;
                                }

                                let cwe_id = cve.weaknesses
                                    .as_ref()
                                    .and_then(|w| w.first())
                                    .and_then(|w| w.description.first())
                                    .map(|d| d.value.clone())
                                    .filter(|s| s != "NVD-CWE-noinfo" && s != "NVD-CWE-Other");

                                let references: Vec<String> = cve.references
                                    .as_ref()
                                    .map(|refs| refs.iter().map(|r| r.url.clone()).collect())
                                    .unwrap_or_default();

                                // Build NVD detail link
                                let nvd_link = format!("https://nvd.nist.gov/vuln/detail/{}", cve.id);
                                let mut all_refs = vec![nvd_link];
                                all_refs.extend(references);

                                findings.push(CveFinding {
                                    cve_id: cve.id,
                                    cvss_score,
                                    severity,
                                    description,
                                    affected_technology: technology.to_string(),
                                    affected_version: version.to_string(),
                                    exploits: Vec::new(),
                                    epss_score: None,
                                    epss_percentile: None,
                                    is_kev: false,
                                    kev_date_added: None,
                                    references: all_refs,
                                    remediation: String::new(),
                                    cwe_id,
                                });
                            }
                        }
                    }
                    Err(e) => {
                        log::warn!("NVD JSON parse error: {}. First 500 chars: {}", e, &body[..body.len().min(500)]);
                    }
                }
            } else if status.as_u16() == 403 {
                log::warn!("NVD API rate limited (403). Use --nvd-key for faster queries.");
            } else {
                log::warn!("NVD API returned status: {}", status);
            }
        }
        Err(e) => {
            log::warn!("NVD API request failed: {}", e);
        }
    }

    Ok(findings)
}

fn extract_cvss(metrics: &Option<NvdMetrics>) -> (f64, String) {
    if let Some(m) = metrics {
        // Try CVSS v3.1 first
        if let Some(v31) = &m.cvss_v31 {
            if let Some(first) = v31.first() {
                let score = first.cvss_data.base_score;
                let severity = first.cvss_data.base_severity.clone()
                    .unwrap_or_else(|| score_to_severity(score));
                return (score, severity.to_uppercase());
            }
        }
        // Try CVSS v3.0
        if let Some(v30) = &m.cvss_v30 {
            if let Some(first) = v30.first() {
                let score = first.cvss_data.base_score;
                let severity = first.cvss_data.base_severity.clone()
                    .unwrap_or_else(|| score_to_severity(score));
                return (score, severity.to_uppercase());
            }
        }
        // Try CVSS v2
        if let Some(v2) = &m.cvss_v2 {
            if let Some(first) = v2.first() {
                let score = first.cvss_data.base_score;
                let severity = first.base_severity.clone()
                    .unwrap_or_else(|| score_to_severity(score));
                return (score, severity.to_uppercase());
            }
        }
    }
    (0.0, "UNKNOWN".to_string())
}

fn score_to_severity(score: f64) -> String {
    match score {
        s if s >= 9.0 => "CRITICAL".to_string(),
        s if s >= 7.0 => "HIGH".to_string(),
        s if s >= 4.0 => "MEDIUM".to_string(),
        s if s > 0.0 => "LOW".to_string(),
        _ => "NONE".to_string(),
    }
}