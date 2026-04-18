<div align="center">

# 🐍 VenomStrike

### Advanced Web Vulnerability Scanner & VAPT Reporter

![Rust](https://img.shields.io/badge/Rust-000000?style=for-the-badge&logo=rust&logoColor=white)
![License](https://img.shields.io/badge/License-MIT-green.svg?style=for-the-badge)
![Platform](https://img.shields.io/badge/Platform-Linux%20%7C%20macOS%20%7C%20Windows-blue?style=for-the-badge)

**A comprehensive command-line web vulnerability scanner built in Rust that performs automated security assessments and generates professional VAPT reports.**

[Features](#features) • [Installation](#installation) • [Usage](#usage) • [Architecture](#architecture) • [Reports](#reports) • [Contributing](#contributing)

</div>

---

## 🎯 Features

### Scanning Pipeline
| Phase | Description |
|-------|-------------|
| **Phase 1: Reconnaissance** | DNS enumeration, subdomain discovery, port scanning (optional Nmap integration) |
| **Phase 2: Fingerprinting** | Web server, CMS, programming language, JS libraries, WAF detection |
| **Phase 3: CVE Intelligence** | NVD API 2.0 + ExploitDB + EPSS scores + CISA KEV catalog |
| **Phase 4: Active Scanning** | Custom-built scanners for 11+ vulnerability types |
| **Phase 5: VAPT Reporting** | HTML, JSON, PDF, and SARIF report generation |

### Vulnerability Scanners
- ✅ SQL Injection (error-based, boolean-blind, time-based)
- ✅ Cross-Site Scripting (XSS) with encoding bypass
- ✅ Server-Side Request Forgery (SSRF)
- ✅ Local/Remote File Inclusion (LFI/RFI)
- ✅ Server-Side Template Injection (SSTI)
- ✅ OS Command Injection
- ✅ CORS Misconfiguration
- ✅ Open Redirect
- ✅ CSRF Detection
- ✅ Security Header Analysis
- ✅ SSL/TLS Certificate Checks

### CVE Intelligence Engine (Core Differentiator)
- 🔍 **NIST NVD API 2.0** — CVE lookup by CPE string
- 💀 **ExploitDB Integration** — Maps CVEs to available exploits
- 📊 **EPSS Scores** — Exploitation probability from FIRST.org
- 🚨 **CISA KEV Catalog** — Known Exploited Vulnerabilities
- 🛡️ **Remediation Guidance** — Prioritized fix recommendations

### Report Formats
- 📄 **HTML** — Interactive report with severity charts and executive summary
- 📋 **JSON** — Machine-readable for CI/CD pipeline integration
- 📑 **PDF** — Client-ready professional format
- 🔗 **SARIF** — GitHub Security tab integration

---

## 📦 Installation

### Prerequisites
- Rust 1.70+ (install via [rustup](https://rustup.rs))
- OpenSSL development libraries
- Optional: Nmap, wkhtmltopdf, Docker

### Build from Source

```bash
# Clone the repository
git clone https://github.com/Soulcynics404/venomstrike.git
cd venomstrike

# Install system dependencies (Kali Linux / Debian)
sudo apt install -y build-essential pkg-config libssl-dev wkhtmltopdf nmap

# Build
cargo build --release

# Install globally (optional)
sudo cp target/release/venomstrike /usr/local/bin/
```

# Docker
```bash
docker build -t venomstrike .
docker run venomstrike scan --target https://example.com
```

## 🚀 Usage
### Full Scan
```bash
venomstrike scan --target https://example.com --formats html,json,sarif
```

## Scan with All Options

```bash
venomstrike scan \
  --target https://example.com \
  --threads 20 \
  --rate-limit 15 \
  --phases recon,fingerprint,cve,active,report \
  --formats html,json,pdf,sarif \
  --output ./reports \
  --nmap \
  --nvd-key YOUR_NVD_API_KEY \
  --cookie "session=abc123" \
  --verbose
```

## Reconnaissance Only
```bash
venomstrike recon --target https://example.com --nmap
```

## CVE Lookup
```bash
venomstrike cve-lookup --technology apache --version 2.4.51
```

## Generate Report from Previous Scan
```bash
venomstrike report --input ./reports/scan_results.json --formats html,pdf
```

---

## Command Reference

| Command | Description |
|---------|-------------|
| `scan` | Full vulnerability scan |
| `recon` | Reconnaissance phase only |
| `cve-lookup` | CVE lookup for a specific technology |
| `report` | Generate reports from JSON results |

### Key Options

| Option | Description | Default |
|--------|-------------|---------|
| `--target` | Target URL | Required |
| `--threads` | Concurrent threads | 10 |
| `--rate-limit` | Requests per second | 10 |
| `--phases` | Scan phases to run | all |
| `--formats` | Report output formats | html,json |
| `--nmap` | Enable Nmap port scanning | false |
| `--nvd-key` | NVD API key for faster lookups | None |
| `--proxy` | HTTP/SOCKS5 proxy | None |
| `--cookie` | Session cookie | None |
| `--auth` | Authorization header | None |
| `--verbose` | Detailed output | false |

---

## 🏗️ Architecture

```text
venomstrike/
├── src/
│   ├── main.rs           # Entry point
│   ├── lib.rs            # Library root
│   ├── cli.rs            # CLI argument parsing (clap)
│   ├── config.rs         # Configuration management
│   ├── error.rs          # Custom error types
│   ├── core/
│   │   ├── engine.rs     # Main scan orchestrator
│   │   ├── rate_limiter.rs # Request rate limiting
│   │   ├── scope.rs      # Scope enforcement
│   │   ├── session.rs    # HTTP session management
│   │   └── crawler.rs    # Web crawler
│   ├── recon/            # Phase 1: Reconnaissance
│   ├── fingerprint/      # Phase 2: Technology detection
│   ├── cve/              # Phase 3: CVE intelligence
│   ├── scanners/         # Phase 4: Vulnerability scanners
│   │   ├── traits.rs     # Scanner plugin trait
│   │   ├── sqli.rs       # SQL Injection
│   │   ├── xss.rs        # Cross-Site Scripting
│   │   └── ...           # Additional scanners
│   ├── reporting/        # Phase 5: Report generation
│   └── utils/            # Utility functions
├── payloads/             # External payload files
├── config/               # Configuration files
├── data/                 # CVE databases
└── tests/                # Test suite
```

### Plugin Architecture

Adding a new scanner is simple — implement the `VulnerabilityScanner` trait:

```rust
use async_trait::async_trait;
use crate::scanners::traits::VulnerabilityScanner;

pub struct MyCustomScanner;

#[async_trait]
impl VulnerabilityScanner for MyCustomScanner {
    fn name(&self) -> &str { "My Custom Scanner" }
    fn description(&self) -> &str { "Checks for custom vulnerability" }

    async fn scan(
        &self,
        pages: &[CrawledPage],
        client: &reqwest::Client,
    ) -> VenomResult<Vec<Vulnerability>> {
        // Your scanning logic here
        Ok(vec![])
    }
}
```

Then register it in `src/scanners/mod.rs`.

---

## 🧪 Testing

### Run Tests

```bash
cargo test
```

### Test Against Vulnerable Applications

```bash
# Start vulnerable apps
docker-compose up -d

# Scan DVWA
venomstrike scan --target http://localhost:8081 --formats html

# Scan WebGoat
venomstrike scan --target http://localhost:8082/WebGoat --formats html

# Scan Juice Shop
venomstrike scan --target http://localhost:8083 --formats html

# Stop apps
docker-compose down
```

---

## 🔑 Environment Variables

| Variable | Description |
|----------|-------------|
| `NVD_API_KEY` | NIST NVD API key for faster CVE lookups |

Get a free NVD API key: https://nvd.nist.gov/developers/request-an-api-key

---

## 📊 Sample Report Output

```text
┳ VenomStrike v1.0.0
🎯 Target: https://example.com

══ Phase 1: Reconnaissance ══
  → DNS: A → 93.184.216.34
  → Found 5 subdomains
  → Found 3 open ports

══ Phase 2: Technology Fingerprinting ══
  → Apache v2.4.51
  → PHP v8.1.0
  → WordPress v6.4.2

══ Phase 3: CVE Intelligence Engine ══
  ⚠ CVE-2023-25690 [CRITICAL] CVSS: 9.8
  ⚠ CVE-2023-31122 [HIGH] CVSS: 7.5

══ Phase 4: Active Vulnerability Scanning ══
  🔥 [CRITICAL] SQL Injection at /page?id=1
  🔥 [HIGH] Reflected XSS at /search?q=test

══ Scan Complete ══
  Critical: 2 | High: 3 | Medium: 5 | Low: 8 | Info: 4
```

---

## ⚠️ Disclaimer

**VenomStrike is designed for authorized security testing only.** Always obtain proper written authorization before scanning any target. Unauthorized scanning is illegal and unethical. The authors are not responsible for any misuse of this tool.

---

## 📜 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

---

## 🤝 Contributing

Contributions are welcome! Please:

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/new-scanner`)
3. Commit your changes (`git commit -am 'Add new scanner'`)
4. Push to the branch (`git push origin feature/new-scanner`)
5. Open a Pull Request

---

<p align="center">Built with ❤️ and � Rust by <a href="https://github.com/Soulcynics404">Soulcynics404</a></p>
