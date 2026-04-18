use std::sync::Arc;
use tokio::net::TcpStream;
use tokio::time::{timeout, Duration};
use std::process::Command;
use crate::reporting::models::PortInfo;
use crate::error::VenomResult;

const COMMON_PORTS: &[u16] = &[
    21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445, 993, 995,
    1723, 3306, 3389, 5432, 5900, 8000, 8080, 8443, 8888, 9090, 27017,
];

pub async fn basic_port_scan(host: &str) -> VenomResult<Vec<PortInfo>> {
    let mut open_ports = Vec::new();
    let semaphore = Arc::new(tokio::sync::Semaphore::new(50));
    let mut handles = Vec::new();

    for &port in COMMON_PORTS {
        let host = host.to_string();
        let sem = semaphore.clone();

        let handle = tokio::spawn(async move {
            let _permit = sem.acquire().await.ok()?;
            let addr = format!("{}:{}", host, port);

            match timeout(Duration::from_secs(3), TcpStream::connect(&addr)).await {
                Ok(Ok(_)) => Some(PortInfo {
                    port,
                    state: "open".to_string(),
                    service: guess_service(port),
                    version: None,
                }),
                _ => None,
            }
        });
        handles.push(handle);
    }

    for handle in handles {
        if let Ok(Some(port_info)) = handle.await {
            open_ports.push(port_info);
        }
    }

    open_ports.sort_by_key(|p| p.port);
    Ok(open_ports)
}

pub async fn nmap_scan(host: &str) -> VenomResult<Vec<PortInfo>> {
    let output = Command::new("nmap")
        .args(&["-sV", "-T4", "--top-ports", "100", "-oX", "-", host])
        .output();

    match output {
        Ok(result) => {
            let stdout = String::from_utf8_lossy(&result.stdout);
            parse_nmap_xml(&stdout)
        }
        Err(_) => {
            log::warn!("Nmap not available, falling back to basic scan");
            basic_port_scan(host).await
        }
    }
}

fn parse_nmap_xml(xml: &str) -> VenomResult<Vec<PortInfo>> {
    let mut ports = Vec::new();

    // Simple XML parsing for nmap output
    for line in xml.lines() {
        if line.contains("<port protocol=") && line.contains("state=\"open\"") {
            let port_num = extract_attr(line, "portid")
                .and_then(|s| s.parse::<u16>().ok())
                .unwrap_or(0);

            let service = extract_attr(line, "name").unwrap_or_else(|| guess_service(port_num));
            let version = extract_attr(line, "product");

            if port_num > 0 {
                ports.push(PortInfo {
                    port: port_num,
                    state: "open".to_string(),
                    service,
                    version,
                });
            }
        }
    }

    // Fallback: if XML parsing didn't work, try grep-style
    if ports.is_empty() {
        for line in xml.lines() {
            let trimmed = line.trim();
            if trimmed.contains("/tcp") && trimmed.contains("open") {
                let parts: Vec<&str> = trimmed.split_whitespace().collect();
                if parts.len() >= 3 {
                    if let Some(port_str) = parts[0].split('/').next() {
                        if let Ok(port_num) = port_str.parse::<u16>() {
                            ports.push(PortInfo {
                                port: port_num,
                                state: "open".to_string(),
                                service: parts.get(2).unwrap_or(&"unknown").to_string(),
                                version: parts.get(3).map(|s| s.to_string()),
                            });
                        }
                    }
                }
            }
        }
    }

    Ok(ports)
}

fn extract_attr(line: &str, attr: &str) -> Option<String> {
    let search = format!("{}=\"", attr);
    if let Some(start) = line.find(&search) {
        let rest = &line[start + search.len()..];
        if let Some(end) = rest.find('"') {
            return Some(rest[..end].to_string());
        }
    }
    None
}

fn guess_service(port: u16) -> String {
    match port {
        21 => "ftp",
        22 => "ssh",
        23 => "telnet",
        25 => "smtp",
        53 => "dns",
        80 => "http",
        110 => "pop3",
        143 => "imap",
        443 => "https",
        445 => "smb",
        3306 => "mysql",
        3389 => "rdp",
        5432 => "postgresql",
        5900 => "vnc",
        8080 => "http-proxy",
        8443 => "https-alt",
        27017 => "mongodb",
        _ => "unknown",
    }.to_string()
}