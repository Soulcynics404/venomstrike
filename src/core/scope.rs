use url::Url;
use crate::error::{VenomError, VenomResult};

#[derive(Debug, Clone)]
pub struct ScopeEnforcer {
    allowed_domains: Vec<String>,
    excluded_paths: Vec<String>,
}

impl ScopeEnforcer {
    pub fn new(base_url: &str, additional_scope: Vec<String>, excludes: Vec<String>) -> VenomResult<Self> {
        let parsed = Url::parse(base_url).map_err(|e| VenomError::ScopeError(e.to_string()))?;
        let mut allowed = vec![];

        if let Some(host) = parsed.host_str() {
            allowed.push(host.to_string());
        }

        for domain in additional_scope {
            allowed.push(domain);
        }

        Ok(Self {
            allowed_domains: allowed,
            excluded_paths: excludes,
        })
    }

    pub fn is_in_scope(&self, url: &str) -> bool {
        if let Ok(parsed) = Url::parse(url) {
            if let Some(host) = parsed.host_str() {
                let host_str = host.to_string();
                let in_domain = self.allowed_domains.iter().any(|d| {
                    host_str == *d || host_str.ends_with(&format!(".{}", d))
                });

                if !in_domain {
                    return false;
                }

                let path = parsed.path().to_string();
                let excluded = self.excluded_paths.iter().any(|e| path.starts_with(e));
                return !excluded;
            }
        }
        false
    }

    pub fn check_scope(&self, url: &str) -> VenomResult<()> {
        if self.is_in_scope(url) {
            Ok(())
        } else {
            Err(VenomError::ScopeError(format!("URL {} is out of scope", url)))
        }
    }
}