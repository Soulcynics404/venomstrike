use std::path::Path;
use crate::reporting::models::ScanReport;
use crate::error::VenomResult;

pub async fn generate_html_report(report: &ScanReport, output_dir: &Path) -> VenomResult<()> {
    let filename = format!("venomstrike_report_{}.html", report.id);
    let filepath = output_dir.join(&filename);

    let summary = report.executive_summary();
    let roadmap = report.remediation_roadmap();

    let html = format!(r#"<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>VenomStrike VAPT Report — {target}</title>
<style>
    :root {{ --critical: #dc3545; --high: #fd7e14; --medium: #ffc107; --low: #28a745; --info: #17a2b8; }}
    * {{ margin: 0; padding: 0; box-sizing: border-box; }}
    body {{ font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; background: #0a0a0a; color: #e0e0e0; line-height: 1.6; }}
    .container {{ max-width: 1200px; margin: 0 auto; padding: 20px; }}
    .header {{ background: linear-gradient(135deg, #1a1a2e, #16213e); padding: 40px; border-radius: 12px; margin-bottom: 30px; border: 1px solid #333; }}
    .header h1 {{ color: #ff4444; font-size: 2.5em; margin-bottom: 10px; }}
    .header .subtitle {{ color: #888; font-size: 1.2em; }}
    .section {{ background: #1a1a1a; border-radius: 10px; padding: 25px; margin-bottom: 20px; border: 1px solid #333; }}
    .section h2 {{ color: #ff6b6b; margin-bottom: 15px; border-bottom: 2px solid #333; padding-bottom: 10px; }}
    .section h3 {{ color: #4ecdc4; margin: 15px 0 10px; }}
    .stats-grid {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(150px, 1fr)); gap: 15px; margin: 20px 0; }}
    .stat-card {{ background: #222; border-radius: 8px; padding: 20px; text-align: center; border-left: 4px solid; }}
    .stat-card.critical {{ border-color: var(--critical); }}
    .stat-card.high {{ border-color: var(--high); }}
    .stat-card.medium {{ border-color: var(--medium); }}
    .stat-card.low {{ border-color: var(--low); }}
    .stat-card.info {{ border-color: var(--info); }}
    .stat-card .number {{ font-size: 2.5em; font-weight: bold; }}
    .stat-card .label {{ color: #888; font-size: 0.9em; }}
    .finding {{ background: #222; border-radius: 8px; padding: 20px; margin: 10px 0; border-left: 4px solid; }}
    .finding.critical {{ border-color: var(--critical); }}
    .finding.high {{ border-color: var(--high); }}
    .finding.medium {{ border-color: var(--medium); }}
    .finding.low {{ border-color: var(--low); }}
    .finding.info {{ border-color: var(--info); }}
    .severity-badge {{ display: inline-block; padding: 3px 12px; border-radius: 20px; font-size: 0.8em; font-weight: bold; color: white; }}
    .severity-badge.critical {{ background: var(--critical); }}
    .severity-badge.high {{ background: var(--high); }}
    .severity-badge.medium {{ background: var(--medium); color: #000; }}
    .severity-badge.low {{ background: var(--low); }}
    .severity-badge.info {{ background: var(--info); }}
    .finding h4 {{ margin-bottom: 8px; }}
    .finding .meta {{ color: #888; font-size: 0.9em; margin: 5px 0; }}
    .finding .detail {{ margin: 10px 0; }}
    .finding .detail strong {{ color: #4ecdc4; }}
    .evidence {{ background: #111; padding: 10px; border-radius: 5px; font-family: monospace; font-size: 0.9em; margin: 10px 0; overflow-x: auto; word-break: break-all; }}
    table {{ width: 100%; border-collapse: collapse; margin: 15px 0; }}
    th, td {{ padding: 10px 15px; text-align: left; border-bottom: 1px solid #333; }}
    th {{ background: #222; color: #4ecdc4; }}
    tr:hover {{ background: #1e1e1e; }}
    .chart-container {{ display: flex; justify-content: center; align-items: center; height: 200px; margin: 20px 0; }}
    .donut {{ width: 180px; height: 180px; border-radius: 50%; position: relative; }}
    .risk-badge {{ display: inline-block; padding: 8px 20px; border-radius: 25px; font-size: 1.3em; font-weight: bold; color: white; }}
    a {{ color: #4ecdc4; text-decoration: none; }}
    a:hover {{ text-decoration: underline; }}
    .roadmap-item {{ display: flex; gap: 15px; padding: 15px; background: #222; border-radius: 8px; margin: 8px 0; }}
    .roadmap-priority {{ min-width: 40px; height: 40px; display: flex; align-items: center; justify-content: center; border-radius: 50%; background: #333; font-weight: bold; }}
    .footer {{ text-align: center; padding: 30px; color: #555; margin-top: 40px; border-top: 1px solid #333; }}
</style>
</head>
<body>
<div class="container">

<div class="header">
    <h1>🐍 VenomStrike VAPT Report</h1>
    <div class="subtitle">Vulnerability Assessment & Penetration Testing Report</div>
    <div style="margin-top: 15px; color: #aaa;">
        <div><strong>Target:</strong> {target}</div>
        <div><strong>Date:</strong> {scan_date}</div>
        <div><strong>Duration:</strong> {duration}</div>
        <div><strong>Scanner:</strong> VenomStrike v1.0.0</div>
    </div>
</div>

<!-- Executive Summary -->
<div class="section">
    <h2>📊 Executive Summary</h2>
    <p>This report presents the findings of an automated vulnerability assessment performed against <strong>{target}</strong>.</p>
    <div style="margin: 20px 0; text-align: center;">
        <span>Overall Risk Level: </span>
        <span class="risk-badge" style="background: {risk_color};">{overall_risk}</span>
    </div>
    <div class="stats-grid">
        <div class="stat-card critical"><div class="number" style="color: var(--critical);">{critical}</div><div class="label">Critical</div></div>
        <div class="stat-card high"><div class="number" style="color: var(--high);">{high}</div><div class="label">High</div></div>
        <div class="stat-card medium"><div class="number" style="color: var(--medium);">{medium}</div><div class="label">Medium</div></div>
        <div class="stat-card low"><div class="number" style="color: var(--low);">{low}</div><div class="label">Low</div></div>
        <div class="stat-card info"><div class="number" style="color: var(--info);">{info_count}</div><div class="label">Info</div></div>
    </div>
    <p><strong>Technologies Found:</strong> {tech_count} | <strong>CVEs Found:</strong> {cve_count} | <strong>Total Findings:</strong> {total}</p>
</div>

<!-- Scope & Methodology -->
<div class="section">
    <h2>📋 Scope & Methodology</h2>
    <h3>Scope</h3>
    <p>Target: {target}</p>
    <h3>Methodology</h3>
    <p>{methodology}</p>
</div>

<!-- Technologies -->
<div class="section">
    <h2>🔍 Detected Technologies</h2>
    <table>
        <tr><th>Technology</th><th>Version</th><th>Category</th><th>Confidence</th></tr>
        {tech_rows}
    </table>
</div>

<!-- CVE Findings -->
<div class="section">
    <h2>🛡️ CVE Intelligence Findings</h2>
    {cve_findings_html}
</div>

<!-- Vulnerability Findings -->
<div class="section">
    <h2>🔥 Active Scan Findings</h2>
    {vuln_findings_html}
</div>

<!-- Remediation Roadmap -->
<div class="section">
    <h2>🗺️ Remediation Roadmap</h2>
    {roadmap_html}
</div>

<div class="footer">
    <p>Generated by VenomStrike v1.0.0 — Advanced Web Vulnerability Scanner & VAPT Reporter</p>
    <p>Report ID: {report_id}</p>
</div>

</div>
</body>
</html>"#,
        target = html_escape::encode_text(&report.target),
        scan_date = summary.scan_date,
        duration = summary.duration,
        overall_risk = summary.overall_risk,
        risk_color = risk_color(&summary.overall_risk),
        critical = summary.critical,
        high = summary.high,
        medium = summary.medium,
        low = summary.low,
        info_count = summary.info,
        tech_count = summary.technologies_found,
        cve_count = summary.cves_found,
        total = summary.total_findings,
        methodology = html_escape::encode_text(&report.methodology),
        tech_rows = generate_tech_rows(&report.technologies),
        cve_findings_html = generate_cve_html(&report.cve_findings),
        vuln_findings_html = generate_vuln_html(&report.vulnerabilities),
        roadmap_html = generate_roadmap_html(&roadmap),
        report_id = report.id,
    );

    std::fs::write(&filepath, html).map_err(|e| {
        crate::error::VenomError::ReportError(format!("Failed to write HTML report: {}", e))
    })?;

    println!("  📄 HTML report saved: {}", filepath.display());
    Ok(())
}

fn risk_color(risk: &str) -> &str {
    match risk {
        "CRITICAL" => "#dc3545",
        "HIGH" => "#fd7e14",
        "MEDIUM" => "#ffc107",
        "LOW" => "#28a745",
        _ => "#17a2b8",
    }
}

fn generate_tech_rows(technologies: &[crate::reporting::models::Technology]) -> String {
    technologies.iter().map(|t| {
        format!("<tr><td>{}</td><td>{}</td><td>{}</td><td>{}%</td></tr>",
            html_escape::encode_text(&t.name),
            html_escape::encode_text(t.version.as_deref().unwrap_or("Unknown")),
            html_escape::encode_text(&t.category),
            t.confidence
        )
    }).collect::<Vec<_>>().join("\n")
}

fn generate_cve_html(findings: &[crate::reporting::models::CveFinding]) -> String {
    if findings.is_empty() {
        return "<p>No CVEs found for detected technologies.</p>".to_string();
    }

    findings.iter().map(|f| {
        let sev_class = f.severity.to_lowercase();
        let exploits_html = if f.exploits.is_empty() {
            String::from("<em>No public exploits found</em>")
        } else {
            f.exploits.iter().map(|e| {
                format!("<a href=\"{}\" target=\"_blank\">{} ({})</a>", e.url, e.id, e.source)
            }).collect::<Vec<_>>().join(", ")
        };

        let kev_html = if f.is_kev {
            format!("<span style='color: red; font-weight: bold;'>🚨 CISA KEV (Added: {})</span>",
                f.kev_date_added.as_deref().unwrap_or("N/A"))
        } else { String::new() };

        let epss_html = f.epss_score.map(|s| {
            format!("<div class='detail'><strong>EPSS Score:</strong> {:.2}% probability of exploitation</div>", s * 100.0)
        }).unwrap_or_default();

        format!(r#"<div class="finding {sev_class}">
    <h4><span class="severity-badge {sev_class}">{severity}</span> {cve_id} — CVSS: {cvss}</h4>
    <div class="meta">Affects: {tech} v{version} {kev}</div>
    <div class="detail"><strong>Description:</strong> {desc}</div>
    {epss}
    <div class="detail"><strong>Exploits:</strong> {exploits}</div>
    <div class="detail"><strong>Remediation:</strong><pre style="white-space: pre-wrap;">{remediation}</pre></div>
</div>"#,
            sev_class = sev_class,
            severity = f.severity,
            cve_id = f.cve_id,
            cvss = f.cvss_score,
            tech = html_escape::encode_text(&f.affected_technology),
            version = html_escape::encode_text(&f.affected_version),
            kev = kev_html,
            desc = html_escape::encode_text(&f.description),
            epss = epss_html,
            exploits = exploits_html,
            remediation = html_escape::encode_text(&f.remediation),
        )
    }).collect::<Vec<_>>().join("\n")
}

fn generate_vuln_html(vulns: &[crate::reporting::models::Vulnerability]) -> String {
    if vulns.is_empty() {
        return "<p>No active vulnerabilities detected.</p>".to_string();
    }

    vulns.iter().map(|v| {
        let sev_class = v.severity.to_lowercase();
        let param_html = v.parameter.as_ref().map(|p| {
            format!("<div class='detail'><strong>Vulnerable Parameter:</strong> <code>{}</code></div>", html_escape::encode_text(p))
        }).unwrap_or_default();

        let payload_html = v.payload.as_ref().map(|p| {
            format!(r#"<div class='detail'><strong>🎯 Payload That Found Bug:</strong>
            <div class='evidence' style='background: #1a0000; border: 1px solid #ff4444; color: #ff6b6b; padding: 12px; font-size: 1.05em;'>{}</div></div>"#,
                html_escape::encode_text(p))
        }).unwrap_or_default();

        let refs_html = if !v.references.is_empty() {
            let links: String = v.references.iter().map(|r| {
                format!("<li><a href='{}' target='_blank'>{}</a></li>", r, html_escape::encode_text(r))
            }).collect::<Vec<_>>().join("");
            format!("<div class='detail'><strong>📚 References & Exploit Links:</strong><ul>{}</ul></div>", links)
        } else {
            String::new()
        };

        format!(r#"<div class="finding {sev_class}">
    <h4><span class="severity-badge {sev_class}">{severity}</span> {title}</h4>
    <div class="meta">URL: <a href="{url}">{url}</a> | Type: {vuln_type} {cwe}</div>
    <div class="detail"><strong>Description:</strong> {desc}</div>
    {param}
    {payload}
    <div class="detail"><strong>Evidence:</strong> <div class="evidence">{evidence}</div></div>
    <div class="detail"><strong>Impact:</strong> {impact}</div>
    <div class="detail"><strong>Remediation:</strong><pre style="white-space: pre-wrap;">{remediation}</pre></div>
    {refs}
</div>"#,
            sev_class = sev_class,
            severity = v.severity,
            title = html_escape::encode_text(&v.title),
            url = html_escape::encode_text(&v.url),
            vuln_type = html_escape::encode_text(&v.vulnerability_type),
            cwe = v.cwe_id.as_ref().map(|c| format!("| {}", c)).unwrap_or_default(),
            desc = html_escape::encode_text(&v.description),
            param = param_html,
            payload = payload_html,
            evidence = html_escape::encode_text(&v.evidence),
            impact = html_escape::encode_text(&v.impact),
            remediation = html_escape::encode_text(&v.remediation),
            refs = refs_html,
        )
    }).collect::<Vec<_>>().join("\n")
}

fn generate_roadmap_html(roadmap: &[crate::reporting::models::RemediationItem]) -> String {
    if roadmap.is_empty() {
        return "<p>No remediation items.</p>".to_string();
    }

    roadmap.iter().map(|r| {
        let sev_class = r.severity.to_lowercase();
        format!(r#"<div class="roadmap-item">
    <div class="roadmap-priority" style="background: {};">#{}</div>
    <div>
        <strong>{}</strong> <span class="severity-badge {}">{}</span><br>
        <span style="color: #888;">Timeline: {}</span><br>
        <span>{}</span>
    </div>
</div>"#,
            risk_color(&r.severity), r.priority,
            html_escape::encode_text(&r.title),
            sev_class, r.severity,
            r.effort,
            html_escape::encode_text(&r.description),
        )
    }).collect::<Vec<_>>().join("\n")
}