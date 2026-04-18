use clap::{Parser, Subcommand};

#[derive(Parser, Debug)]
#[command(
    name = "venomstrike",
    version = "1.0.0",
    author = "Soulcynics404",
    about = "🐍 VenomStrike — Advanced Web Vulnerability Scanner & VAPT Reporter",
    long_about = "A comprehensive web vulnerability scanner that performs reconnaissance, \
    technology fingerprinting, CVE intelligence gathering, active vulnerability scanning, \
    and generates professional VAPT reports."
)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Commands,
}

#[derive(Subcommand, Debug)]
pub enum Commands {
    /// Run a full vulnerability scan against a target
    Scan {
        /// Target URL (e.g., https://example.com)
        #[arg(short, long)]
        target: String,

        /// Configuration file path
        #[arg(short, long)]
        config: Option<String>,

        /// Output directory for reports
        #[arg(short, long, default_value = "./reports")]
        output: String,

        /// Output formats (html, json, pdf, sarif)
        #[arg(short, long, value_delimiter = ',', default_value = "html,json")]
        formats: Vec<String>,

        /// Number of concurrent threads
        #[arg(long, default_value = "10")]
        threads: usize,

        /// Requests per second rate limit
        #[arg(long, default_value = "10")]
        rate_limit: u32,

        /// Scanning phases to execute (recon,fingerprint,cve,active,report)
        #[arg(long, value_delimiter = ',', default_value = "recon,fingerprint,cve,active,report")]
        phases: Vec<String>,

        /// Enable Nmap integration for port scanning
        #[arg(long, default_value = "false")]
        nmap: bool,

        /// HTTP/SOCKS5 proxy URL
        #[arg(long)]
        proxy: Option<String>,

        /// NVD API key for faster CVE lookups
        #[arg(long, env = "NVD_API_KEY")]
        nvd_key: Option<String>,

        /// Custom User-Agent string
        #[arg(long)]
        user_agent: Option<String>,

        /// Scope domains (comma-separated)
        #[arg(long, value_delimiter = ',')]
        scope: Option<Vec<String>>,

        /// Verbose output
        #[arg(short, long)]
        verbose: bool,

        /// Timeout in seconds per request
        #[arg(long, default_value = "30")]
        timeout: u64,

        /// Cookie string for authenticated scanning
        #[arg(long)]
        cookie: Option<String>,

        /// Authorization header value
        #[arg(long)]
        auth: Option<String>,
    },

    /// Run only the reconnaissance phase
    Recon {
        #[arg(short, long)]
        target: String,

        #[arg(long, default_value = "false")]
        nmap: bool,

        #[arg(short, long)]
        verbose: bool,
    },

    /// Run only the CVE intelligence lookup for a technology
    CveLookup {
        /// Technology name (e.g., "apache")
        #[arg(short, long)]
        technology: String,

        /// Version (e.g., "2.4.51")
        #[arg(short, long)]
        version: String,

        /// NVD API key
        #[arg(long, env = "NVD_API_KEY")]
        nvd_key: Option<String>,
    },

    /// Generate a report from a previous scan's JSON output
    Report {
        /// Path to scan results JSON
        #[arg(short, long)]
        input: String,

        /// Output formats
        #[arg(short, long, value_delimiter = ',', default_value = "html")]
        formats: Vec<String>,

        /// Output directory
        #[arg(short, long, default_value = "./reports")]
        output: String,
    },
}