use std::sync::Arc;
use reqwest::Client;
use std::path::Path;
use tokio::fs;
use crate::core::rate_limiter::VenomRateLimiter;
use crate::reporting::models::SubdomainInfo;
use crate::error::VenomResult;

pub async fn discover_subdomains(
    domain: &str,
    client: &Client,
    rate_limiter: &VenomRateLimiter,
    wordlist_path: &Path,
) -> VenomResult<Vec<SubdomainInfo>> {
    let mut subdomains = Vec::new();

    // Load wordlist
    let wordlist = if wordlist_path.exists() {
        fs::read_to_string(wordlist_path).await?
    } else {
        // Default minimal wordlist
        "www\nmail\nftp\napi\ndev\nstaging\nadmin\ntest\nbeta\napp\ncdn\nshop\nblog\nforum\nm\nmobile".to_string()
    };

    let words: Vec<&str> = wordlist.lines().collect();

    // Use concurrent tasks
    let semaphore = Arc::new(tokio::sync::Semaphore::new(20));
    let mut handles = Vec::new();

    for word in words {
        let subdomain = format!("{}.{}", word.trim(), domain);
        let client = client.clone();
        let rl = rate_limiter.clone();
        let permit = semaphore.clone();

        let handle = tokio::spawn(async move {
            let _permit = permit.acquire().await.ok()?;
            rl.until_ready().await;

            let url = format!("https://{}", subdomain);
            match client.get(&url).send().await {
                Ok(resp) => Some(SubdomainInfo {
                    subdomain,
                    ip: String::new(),
                    status_code: Some(resp.status().as_u16()),
                    title: None,
                }),
                Err(_) => {
                    // Try HTTP
                    let url_http = format!("http://{}", subdomain);
                    match client.get(&url_http).send().await {
                        Ok(resp) => Some(SubdomainInfo {
                            subdomain,
                            ip: String::new(),
                            status_code: Some(resp.status().as_u16()),
                            title: None,
                        }),
                        Err(_) => None,
                    }
                }
            }
        });

        handles.push(handle);
    }

    for handle in handles {
        if let Ok(Some(info)) = handle.await {
            subdomains.push(info);
        }
    }

    Ok(subdomains)
}