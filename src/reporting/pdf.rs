use std::path::Path;
use std::process::Command;
use crate::reporting::models::ScanReport;
use crate::error::VenomResult;

pub async fn generate_pdf_report(report: &ScanReport, output_dir: &Path) -> VenomResult<()> {
    // First generate HTML, then convert to PDF using wkhtmltopdf
    let html_filename = format!("venomstrike_report_{}.html", report.id);
    let html_path = output_dir.join(&html_filename);

    // Ensure HTML report exists
    if !html_path.exists() {
        crate::reporting::html::generate_html_report(report, output_dir).await?;
    }

    let pdf_filename = format!("venomstrike_report_{}.pdf", report.id);
    let pdf_path = output_dir.join(&pdf_filename);

    // Try wkhtmltopdf
    let result = Command::new("wkhtmltopdf")
        .args(&[
            "--page-size", "A4",
            "--margin-top", "15mm",
            "--margin-bottom", "15mm",
            "--margin-left", "10mm",
            "--margin-right", "10mm",
            "--encoding", "UTF-8",
            "--enable-local-file-access",
            "--quiet",
            html_path.to_str().unwrap_or(""),
            pdf_path.to_str().unwrap_or(""),
        ])
        .output();

    match result {
        Ok(output) => {
            if output.status.success() {
                println!("  📄 PDF report saved: {}", pdf_path.display());
            } else {
                let stderr = String::from_utf8_lossy(&output.stderr);
                log::warn!("wkhtmltopdf warning: {}", stderr);
                if pdf_path.exists() {
                    println!("  📄 PDF report saved (with warnings): {}", pdf_path.display());
                } else {
                    return Err(crate::error::VenomError::ReportError(
                        format!("PDF generation failed: {}", stderr)
                    ));
                }
            }
        }
        Err(_) => {
            println!("  ⚠️  wkhtmltopdf not found. Install with: sudo apt install wkhtmltopdf");
            println!("  📄 HTML report available at: {}", html_path.display());
        }
    }

    Ok(())
}