use serde::Deserialize;
use crate::error::VenomResult;

#[derive(Debug, Clone)]
pub struct EpssData {
    pub probability: f64,
    pub percentile: f64,
}

#[derive(Debug, Deserialize)]
struct EpssResponse {
    data: Option<Vec<EpssEntry>>,
}

#[derive(Debug, Deserialize)]
struct EpssEntry {
    cve: String,
    epss: String,
    percentile: String,
}

pub async fn get_epss_score(cve_id: &str) -> VenomResult<Option<EpssData>> {
    let client = reqwest::Client::new();
    let url = format!("https://api.first.org/data/v1/epss?cve={}", cve_id);

    match client.get(&url)
        .header("User-Agent", "VenomStrike/1.0")
        .send()
        .await
    {
        Ok(response) => {
            if response.status().is_success() {
                if let Ok(epss_response) = response.json::<EpssResponse>().await {
                    if let Some(data) = epss_response.data {
                        if let Some(entry) = data.first() {
                            let probability = entry.epss.parse::<f64>().unwrap_or(0.0);
                            let percentile = entry.percentile.parse::<f64>().unwrap_or(0.0);
                            return Ok(Some(EpssData { probability, percentile }));
                        }
                    }
                }
            }
            Ok(None)
        }
        Err(e) => {
            log::warn!("EPSS API request failed for {}: {}", cve_id, e);
            Ok(None)
        }
    }
}