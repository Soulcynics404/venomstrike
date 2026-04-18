use url::Url;

pub fn normalize_url(url: &str) -> String {
    if !url.starts_with("http://") && !url.starts_with("https://") {
        format!("https://{}", url)
    } else {
        url.to_string()
    }
}

pub fn get_base_url(url: &str) -> Option<String> {
    Url::parse(url).ok().map(|u| {
        format!("{}://{}", u.scheme(), u.host_str().unwrap_or(""))
    })
}

pub fn inject_into_url(url: &str, param: &str, value: &str) -> String {
    if let Ok(mut parsed) = Url::parse(url) {
        let pairs: Vec<(String, String)> = parsed.query_pairs()
            .map(|(k, v)| {
                if k == param { (k.to_string(), value.to_string()) }
                else { (k.to_string(), v.to_string()) }
            }).collect();
        parsed.query_pairs_mut().clear();
        for (k, v) in pairs {
            parsed.query_pairs_mut().append_pair(&k, &v);
        }
        parsed.to_string()
    } else {
        url.to_string()
    }
}

pub fn extract_domain(url: &str) -> Option<String> {
    Url::parse(url).ok().and_then(|u| u.host_str().map(|h| h.to_string()))
}

pub fn is_same_domain(url1: &str, url2: &str) -> bool {
    extract_domain(url1) == extract_domain(url2)
}