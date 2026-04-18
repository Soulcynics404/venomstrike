pub mod server;
pub mod cms;
pub mod waf;
pub mod tech;

use reqwest::Client;
use crate::core::rate_limiter::VenomRateLimiter;
use crate::reporting::models::Technology;
use crate::error::VenomResult;

pub async fn run_fingerprint(
    target: &str,
    client: &Client,
    rate_limiter: &VenomRateLimiter,
) -> VenomResult<Vec<Technology>> {
    let mut technologies = Vec::new();

    rate_limiter.until_ready().await;
    let response = client.get(target).send().await?;
    let headers = response.headers().clone();
    let body = response.text().await.unwrap_or_default();

    // Server detection
    if let Some(tech) = server::detect_server(&headers) {
        technologies.push(tech);
    }

    // CMS detection
    let cms_techs = cms::detect_cms(target, client, rate_limiter, &headers, &body).await?;
    technologies.extend(cms_techs);

    // WAF detection
    if let Some(waf) = waf::detect_waf(&headers, &body) {
        technologies.push(waf);
    }

    // Technology detection from headers and body
    let techs = tech::detect_technologies(&headers, &body);
    technologies.extend(techs);

    Ok(technologies)
}