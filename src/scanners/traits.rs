use async_trait::async_trait;
use crate::core::crawler::CrawledPage;
use crate::reporting::models::Vulnerability;
use crate::error::VenomResult;

#[async_trait]
pub trait VulnerabilityScanner: Send + Sync {
    /// Name of the scanner module
    fn name(&self) -> &str;

    /// Description of what this scanner checks
    fn description(&self) -> &str;

    /// Run the scan against crawled pages
    async fn scan(
        &self,
        pages: &[CrawledPage],
        client: &reqwest::Client,
    ) -> VenomResult<Vec<Vulnerability>>;

    /// Whether this scanner is enabled
    fn is_enabled(&self) -> bool {
        true
    }
}