use serde::Deserialize;

#[derive(Debug, Clone, Deserialize)]
pub struct KevCatalog {
    pub vulnerabilities: Vec<KevEntry>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct KevEntry {
    #[serde(rename = "cveID")]
    pub cve_id: String,
    #[serde(rename = "dateAdded")]
    pub date_added: String,
    #[serde(rename = "vendorProject")]
    pub vendor: String,
    pub product: String,
    #[serde(rename = "vulnerabilityName")]
    pub name: String,
}

pub async fn load_kev_catalog() -> Result<Vec<KevEntry>, Box<dyn std::error::Error>> {
    let local_path = "data/cisa_kev.json";

    // Try local file first
    if std::path::Path::new(local_path).exists() {
        let content = tokio::fs::read_to_string(local_path).await?;
        let catalog: KevCatalog = serde_json::from_str(&content)?;
        return Ok(catalog.vulnerabilities);
    }

    // Download from CISA
    log::info!("Downloading CISA KEV catalog...");
    let client = reqwest::Client::new();
    let url = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json";

    match client.get(url).send().await {
        Ok(response) => {
            if response.status().is_success() {
                let text = response.text().await?;

                // Save locally for future use
                if let Ok(()) = std::fs::create_dir_all("data") {
                    let _ = std::fs::write(local_path, &text);
                }

                let catalog: KevCatalog = serde_json::from_str(&text)?;
                Ok(catalog.vulnerabilities)
            } else {
                Ok(Vec::new())
            }
        }
        Err(e) => {
            log::warn!("Failed to download CISA KEV: {}", e);
            Ok(Vec::new())
        }
    }
}

pub fn check_kev<'a>(cve_id: &str, kev_data: &'a [KevEntry]) -> Option<&'a KevEntry> {
    kev_data.iter().find(|e| e.cve_id == cve_id)
}