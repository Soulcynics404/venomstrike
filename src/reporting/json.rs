use std::path::Path;
use crate::reporting::models::ScanReport;
use crate::error::VenomResult;

pub async fn generate_json_report(report: &ScanReport, output_dir: &Path) -> VenomResult<()> {
    let filename = format!("venomstrike_report_{}.json", report.id);
    let filepath = output_dir.join(&filename);

    let json = serde_json::to_string_pretty(report).map_err(|e| {
        crate::error::VenomError::ReportError(format!("JSON serialization failed: {}", e))
    })?;

    std::fs::write(&filepath, json).map_err(|e| {
        crate::error::VenomError::ReportError(format!("Failed to write JSON report: {}", e))
    })?;

    println!("  📄 JSON report saved: {}", filepath.display());
    Ok(())
}