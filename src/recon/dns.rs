use trust_dns_resolver::TokioAsyncResolver;
use trust_dns_resolver::config::*;
use crate::reporting::models::DnsRecord;
use crate::error::VenomResult;

pub async fn enumerate_dns(domain: &str) -> VenomResult<Vec<DnsRecord>> {
    let resolver = TokioAsyncResolver::tokio(
        ResolverConfig::default(),
        ResolverOpts::default(),
    );

    let mut records = Vec::new();

    // A records
    if let Ok(response) = resolver.lookup_ip(domain).await {
        for ip in response.iter() {
            records.push(DnsRecord {
                record_type: "A".to_string(),
                value: ip.to_string(),
            });
        }
    }

    // MX records
    if let Ok(response) = resolver.mx_lookup(domain).await {
        for mx in response.iter() {
            records.push(DnsRecord {
                record_type: "MX".to_string(),
                value: format!("{} (priority: {})", mx.exchange(), mx.preference()),
            });
        }
    }

    // NS records
    if let Ok(response) = resolver.ns_lookup(domain).await {
        for ns in response.iter() {
            records.push(DnsRecord {
                record_type: "NS".to_string(),
                value: ns.to_string(),
            });
        }
    }

    // TXT records
    if let Ok(response) = resolver.txt_lookup(domain).await {
        for txt in response.iter() {
            records.push(DnsRecord {
                record_type: "TXT".to_string(),
                value: txt.to_string(),
            });
        }
    }

    Ok(records)
}