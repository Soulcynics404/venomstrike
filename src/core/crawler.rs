use reqwest::Client;
use scraper::{Html, Selector};
use std::collections::HashSet;
use url::Url;
use crate::core::scope::ScopeEnforcer;
use crate::core::rate_limiter::VenomRateLimiter;
use crate::error::VenomResult;

pub struct Crawler {
    client: Client,
    scope: ScopeEnforcer,
    rate_limiter: VenomRateLimiter,
    max_depth: u32,
    visited: HashSet<String>,
}

impl Crawler {
    pub fn new(
        client: Client,
        scope: ScopeEnforcer,
        rate_limiter: VenomRateLimiter,
        max_depth: u32,
    ) -> Self {
        Self {
            client,
            scope,
            rate_limiter,
            max_depth,
            visited: HashSet::new(),
        }
    }

    pub async fn crawl(&mut self, start_url: &str) -> VenomResult<Vec<CrawledPage>> {
        let mut pages = Vec::new();
        let mut queue: Vec<(String, u32)> = vec![(start_url.to_string(), 0)];

        while let Some((url, depth)) = queue.pop() {
            if depth > self.max_depth || self.visited.contains(&url) || !self.scope.is_in_scope(&url) {
                continue;
            }

            self.visited.insert(url.clone());
            self.rate_limiter.until_ready().await;

            match self.client.get(&url).send().await {
                Ok(response) => {
                    let status = response.status().as_u16();
                    let headers = response.headers().clone();
                    let body = response.text().await.unwrap_or_default();

                    let links = extract_links(&body, &url);
                    let forms = extract_forms(&body, &url);
                    let params = extract_url_params(&url);

                    for link in &links {
                        if !self.visited.contains(link) && self.scope.is_in_scope(link) {
                            queue.push((link.clone(), depth + 1));
                        }
                    }

                    pages.push(CrawledPage {
                        url: url.clone(),
                        status_code: status,
                        headers: headers.iter().map(|(k, v)| {
                            (k.to_string(), v.to_str().unwrap_or("").to_string())
                        }).collect(),
                        body,
                        links,
                        forms,
                        params,
                    });
                }
                Err(e) => {
                    log::warn!("Failed to crawl {}: {}", url, e);
                }
            }
        }

        Ok(pages)
    }
}

#[derive(Debug, Clone)]
pub struct CrawledPage {
    pub url: String,
    pub status_code: u16,
    pub headers: Vec<(String, String)>,
    pub body: String,
    pub links: Vec<String>,
    pub forms: Vec<FormData>,
    pub params: Vec<(String, String)>,
}

#[derive(Debug, Clone)]
pub struct FormData {
    pub action: String,
    pub method: String,
    pub inputs: Vec<FormInput>,
}

#[derive(Debug, Clone)]
pub struct FormInput {
    pub name: String,
    pub input_type: String,
    pub value: String,
}

fn extract_links(html: &str, base_url: &str) -> Vec<String> {
    let document = Html::parse_document(html);
    let selector = Selector::parse("a[href]").unwrap();
    let base = Url::parse(base_url).ok();
    let mut links = Vec::new();

    for element in document.select(&selector) {
        if let Some(href) = element.value().attr("href") {
            let resolved = if let Some(ref base) = base {
                base.join(href).map(|u| u.to_string()).unwrap_or_default()
            } else {
                href.to_string()
            };
            if !resolved.is_empty() && (resolved.starts_with("http://") || resolved.starts_with("https://")) {
                links.push(resolved);
            }
        }
    }
    links
}

fn extract_forms(html: &str, base_url: &str) -> Vec<FormData> {
    let document = Html::parse_document(html);
    let form_selector = Selector::parse("form").unwrap();
    let input_selector = Selector::parse("input, textarea, select").unwrap();
    let base = Url::parse(base_url).ok();
    let mut forms = Vec::new();

    for form in document.select(&form_selector) {
        let action_raw = form.value().attr("action").unwrap_or("");
        let action = if let Some(ref base) = base {
            base.join(action_raw).map(|u| u.to_string()).unwrap_or(base_url.to_string())
        } else {
            action_raw.to_string()
        };
        let method = form.value().attr("method").unwrap_or("GET").to_uppercase();

        let mut inputs = Vec::new();
        for input in form.select(&input_selector) {
            let name = input.value().attr("name").unwrap_or("").to_string();
            let input_type = input.value().attr("type").unwrap_or("text").to_string();
            let value = input.value().attr("value").unwrap_or("").to_string();
            if !name.is_empty() {
                inputs.push(FormInput { name, input_type, value });
            }
        }

        forms.push(FormData { action, method, inputs });
    }
    forms
}

fn extract_url_params(url: &str) -> Vec<(String, String)> {
    if let Ok(parsed) = Url::parse(url) {
        parsed.query_pairs().map(|(k, v)| (k.to_string(), v.to_string())).collect()
    } else {
        vec![]
    }
}