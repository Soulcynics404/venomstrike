use reqwest::{Client, ClientBuilder, header::{HeaderMap, HeaderValue, COOKIE, USER_AGENT, AUTHORIZATION}};
use std::time::Duration;
use crate::error::VenomResult;

#[derive(Debug, Clone)]
pub struct SessionManager {
    client: Client,
    cookies: Option<String>,
    auth_token: Option<String>,
}

impl SessionManager {
    pub fn new(
        timeout_secs: u64,
        user_agent: &str,
        proxy: Option<&str>,
        cookie: Option<String>,
        auth: Option<String>,
        follow_redirects: bool,
    ) -> VenomResult<Self> {
        let mut headers = HeaderMap::new();
        headers.insert(USER_AGENT, HeaderValue::from_str(user_agent).unwrap_or(
            HeaderValue::from_static("VenomStrike/1.0")
        ));

        if let Some(ref c) = cookie {
            if let Ok(v) = HeaderValue::from_str(c) {
                headers.insert(COOKIE, v);
            }
        }

        if let Some(ref a) = auth {
            if let Ok(v) = HeaderValue::from_str(a) {
                headers.insert(AUTHORIZATION, v);
            }
        }

        let mut builder = ClientBuilder::new()
            .timeout(Duration::from_secs(timeout_secs))
            .default_headers(headers)
            .danger_accept_invalid_certs(true)
            .redirect(if follow_redirects {
                reqwest::redirect::Policy::limited(10)
            } else {
                reqwest::redirect::Policy::none()
            })
            .pool_max_idle_per_host(20)
            .cookie_store(true);

        if let Some(proxy_url) = proxy {
            if let Ok(p) = reqwest::Proxy::all(proxy_url) {
                builder = builder.proxy(p);
            }
        }

        let client = builder.build().map_err(|e| {
            crate::error::VenomError::ConfigError(format!("Failed to build HTTP client: {}", e))
        })?;

        Ok(Self {
            client,
            cookies: cookie,
            auth_token: auth,
        })
    }

    pub fn client(&self) -> &Client {
        &self.client
    }
}