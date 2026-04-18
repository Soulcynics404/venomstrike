use serde::{Deserialize, Serialize};
use crate::reporting::models::CveFinding;
use crate::error::VenomResult;

#[derive(Debug, Deserialize)]
struct NvdResponse {
    #[serde(rename = "resultsPerPage")]
    results_per_page: Option<u32>,
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
    #[serde(rename = "cvssMetricV2")]
    cvss_v2: Option<Vec<CvssMetric>>,
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
struct NvdWeakness {
    description: Vec<NvdDescription>,
}

#[derive(Debug, Deserialize)]
struct NvdReference {
    url: String,
}

pub async fn query_nvd(
    technology: &str,
    version: &str,
    cpe_prefix: Option<&str>,
    api_key: Option<&str>,
) -> VenomResult<Vec<CveFinding>> {
    let client = reqwest::Client::new();
    let mut findings = Vec::new();

    // Build query URL
    let base_url = "https://services.nvd.nist.gov/rest/json/cves/2.0";

    let query_url = if let Some(cpe) = cpe_prefix {
        let cpe_string = format!("{}:{}:*", cpe, version);
        format!("{}?cpeName={}", base_url, urlencoding::encode(&cpe_string))
    } else {
        format!("{}?keywordSearch={} {}&keywordExactMatch", base_url,
            urlencoding::encode(technology),
            urlencoding::encode(version))
    };

    let mut request = client.get(&query_url)
        .header("User-Agent", "VenomStrike/1.0");

    if let Some(key) = api_key {
        request = request.header("apiKey", key);
    }

    // NVD rate limiting: 5 requests per 30 seconds without API key
    tokio::time::sleep(tokio::time::Duration::from_millis(
        if api_key.is_some() { 600 } else { 6000 }
    )).await;

    match request.send().await {
        Ok(response) => {
            if response.status().is_success() {
                if let Ok(nvd_response) = response.json::<NvdResponse>().await {
                    if let Some(vulns) = nvd_response.vulnerabilities {
                        for vuln in vulns.into_iter().take(25) {
                            let cve = vuln.cve;

                            let description = cve.descriptions
                                .as_ref()
                                .and_then(|descs| descs.iter().find(|d| d.lang == "en"))
                                .map(|d| d.value.clone())
                                .unwrap_or_default();

                            let (cvss_score, severity) = extract_cvss(&cve.metrics);

                            let cwe_id = cve.weaknesses
                                .as_ref()
                                .and_then(|w| w.first())
                                .and_then(|w| w.description.first())
                                .map(|d| d.value.clone());

                            let references: Vec<String> = cve.references
                                .as_ref()
                                .map(|refs| refs.iter().map(|r| r.url.clone()).collect())
                                .unwrap_or_default();

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
                                references,
                                remediation: String::new(),
                                cwe_id,
                            });
                        }
                    }
                }
            } else {
                log::warn!("NVD API returned status: {}", response.status());
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
        if let Some(v31) = &m.cvss_v31 {
            if let Some(first) = v31.first() {
                let score = first.cvss_data.base_score;
                let severity = first.cvss_data.base_severity.clone()
                    .unwrap_or_else(|| score_to_severity(score));
                return (score, severity);
            }
        }
        if let Some(v2) = &m.cvss_v2 {
            if let Some(first) = v2.first() {
                let score = first.cvss_data.base_score;
                return (score, score_to_severity(score));
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