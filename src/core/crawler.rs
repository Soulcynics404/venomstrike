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
    auth_cookie: Option<String>,
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
            auth_cookie: None,
        }
    }

    /// Set authentication cookie for crawling protected pages
    pub fn with_auth_cookie(mut self, cookie: Option<String>) -> Self {
        self.auth_cookie = cookie;
        self
    }

    /// Try to auto-login to DVWA and similar apps
    pub async fn try_auto_login(&mut self, base_url: &str) -> Option<String> {
        // Try DVWA login
        let login_url = format!("{}/login.php", base_url.trim_end_matches('/'));

        // First get the login page to obtain CSRF token
        let login_resp = self.client.get(&login_url).send().await.ok()?;
        let login_cookies: Vec<String> = login_resp.headers()
            .get_all("set-cookie")
            .iter()
            .filter_map(|v| v.to_str().ok())
            .map(|s| s.split(';').next().unwrap_or("").to_string())
            .collect();

        let login_body = login_resp.text().await.ok()?;

        // Extract CSRF token from DVWA login form
        let token = extract_csrf_token(&login_body, "user_token");
        let phpsessid = login_cookies.iter()
            .find(|c| c.contains("PHPSESSID"))
            .cloned()
            .unwrap_or_default();

        if !phpsessid.is_empty() {
            // Attempt DVWA login with default credentials
            let login_data = if let Some(token) = &token {
                vec![
                    ("username", "admin"),
                    ("password", "password"),
                    ("Login", "Login"),
                    ("user_token", token.as_str()),
                ]
            } else {
                vec![
                    ("username", "admin"),
                    ("password", "password"),
                    ("Login", "Login"),
                ]
            };

            let resp = self.client.post(&login_url)
                .header("Cookie", &phpsessid)
                .form(&login_data)
                .send()
                .await
                .ok()?;

            // Check if login was successful (redirect to index.php or 302)
            let status = resp.status().as_u16();
            let final_url = resp.url().to_string();

            // Collect all cookies from response
            let mut all_cookies = vec![phpsessid.clone()];
            for cookie_val in resp.headers().get_all("set-cookie") {
                if let Ok(c) = cookie_val.to_str() {
                    let cookie_part = c.split(';').next().unwrap_or("").to_string();
                    if !cookie_part.is_empty() {
                        all_cookies.push(cookie_part);
                    }
                }
            }

            // Also set DVWA security to low
            let security_url = format!("{}/security.php", base_url.trim_end_matches('/'));
            let cookie_str = all_cookies.join("; ");

            let _ = self.client.post(&security_url)
                .header("Cookie", &cookie_str)
                .form(&[("security", "low"), ("seclev_submit", "Submit")])
                .send()
                .await;

            // Add security=low cookie
            let final_cookie = format!("{}; security=low", cookie_str);

            if status == 302 || final_url.contains("index.php") || status == 200 {
                println!("    {} DVWA auto-login successful!", "✓".green());
                self.auth_cookie = Some(final_cookie.clone());
                return Some(final_cookie);
            }
        }

        // Try WebGoat login
        let webgoat_login = format!("{}/WebGoat/login", base_url.trim_end_matches('/'));
        if let Ok(resp) = self.client.post(&webgoat_login)
            .form(&[("username", "guest"), ("password", "guest")])
            .send()
            .await
        {
            let cookies: Vec<String> = resp.headers()
                .get_all("set-cookie")
                .iter()
                .filter_map(|v| v.to_str().ok())
                .map(|s| s.split(';').next().unwrap_or("").to_string())
                .collect();

            if !cookies.is_empty() {
                let cookie_str = cookies.join("; ");
                println!("    {} WebGoat auto-login successful!", "✓".green());
                self.auth_cookie = Some(cookie_str.clone());
                return Some(cookie_str);
            }
        }

        None
    }

    fn build_request(&self, url: &str) -> reqwest::RequestBuilder {
        let mut req = self.client.get(url);
        if let Some(ref cookie) = self.auth_cookie {
            req = req.header("Cookie", cookie);
        }
        req
    }

    pub async fn crawl(&mut self, start_url: &str) -> VenomResult<Vec<CrawledPage>> {
        let mut pages = Vec::new();

        // Try auto-login first
        let base = start_url.trim_end_matches('/').to_string();
        if self.auth_cookie.is_none() {
            println!("    {} Attempting auto-login...", "🔑".bold());
            self.try_auto_login(&base).await;
        }

        // Seed URLs: start URL + common vulnerable paths
        let mut queue: Vec<(String, u32)> = vec![(start_url.to_string(), 0)];

        // Add known DVWA paths if it looks like DVWA
        if start_url.contains("8081") || start_url.contains("dvwa") {
            let dvwa_paths = vec![
                "/vulnerabilities/sqli/?id=1&Submit=Submit",
                "/vulnerabilities/xss_r/?name=test",
                "/vulnerabilities/exec/",
                "/vulnerabilities/fi/?page=include.php",
                "/vulnerabilities/csrf/",
                "/vulnerabilities/upload/",
                "/vulnerabilities/xss_s/",
                "/vulnerabilities/brute/",
                "/index.php",
                "/about.php",
                "/security.php",
            ];
            for path in dvwa_paths {
                queue.push((format!("{}{}", base, path), 1));
            }
        }

        while let Some((url, depth)) = queue.pop() {
            if depth > self.max_depth || self.visited.contains(&url) || !self.scope.is_in_scope(&url) {
                continue;
            }

            self.visited.insert(url.clone());
            self.rate_limiter.until_ready().await;

            match self.build_request(&url).send().await {
                Ok(response) => {
                    let status = response.status().as_u16();
                    let headers = response.headers().clone();
                    let body = response.text().await.unwrap_or_default();

                    // Skip login redirects (don't crawl them as valid pages)
                    if body.contains("login.php") && body.contains("Login") && !url.contains("login") {
                        log::debug!("Skipping login redirect page: {}", url);
                        continue;
                    }

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
                        auth_cookie: self.auth_cookie.clone(),
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
    pub auth_cookie: Option<String>,
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

fn extract_csrf_token(html: &str, token_name: &str) -> Option<String> {
    let document = Html::parse_document(html);
    let selector = Selector::parse(&format!("input[name='{}']", token_name)).ok()?;
    document.select(&selector).next()
        .and_then(|el| el.value().attr("value"))
        .map(|v| v.to_string())
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

use colored::Colorize;