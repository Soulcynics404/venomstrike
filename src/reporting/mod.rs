pub mod models;
pub mod html;
pub mod json;
pub mod pdf;
pub mod sarif;

use std::path::Path;
use crate::reporting::models::ScanReport;
use crate::error::VenomResult;

pub async fn generate_report(report: &ScanReport, format: &str, output_dir: &Path) -> VenomResult<()> {
    std::fs::create_dir_all(output_dir).map_err(|e| {
        crate::error::VenomError::ReportError(format!("Cannot create output dir: {}", e))
    })?;

    match format.to_lowercase().as_str() {
        "html" => html::generate_html_report(report, output_dir).await,
        "json" => json::generate_json_report(report, output_dir).await,
        "pdf" => pdf::generate_pdf_report(report, output_dir).await,
        "sarif" => sarif::generate_sarif_report(report, output_dir).await,
        _ => Err(crate::error::VenomError::ReportError(format!("Unknown format: {}", format))),
    }
}