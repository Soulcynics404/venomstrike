use assert_cmd::Command;
use predicates::prelude::*;

#[test]
fn test_help_output() {
    let mut cmd = Command::cargo_bin("venomstrike").unwrap();
    cmd.arg("--help");
    cmd.assert()
        .success()
        .stdout(predicate::str::contains("vulnerability scanner"));
}

#[test]
fn test_version_output() {
    let mut cmd = Command::cargo_bin("venomstrike").unwrap();
    cmd.arg("--version");
    cmd.assert()
        .success();
}

#[test]
fn test_scan_help() {
    let mut cmd = Command::cargo_bin("venomstrike").unwrap();
    cmd.args(&["scan", "--help"]);
    cmd.assert()
        .success()
        .stdout(predicate::str::contains("--target"));
}

#[test]
fn test_recon_help() {
    let mut cmd = Command::cargo_bin("venomstrike").unwrap();
    cmd.args(&["recon", "--help"]);
    cmd.assert()
        .success()
        .stdout(predicate::str::contains("--target"));
}

#[test]
fn test_cve_lookup_help() {
    let mut cmd = Command::cargo_bin("venomstrike").unwrap();
    cmd.args(&["cve-lookup", "--help"]);
    cmd.assert()
        .success()
        .stdout(predicate::str::contains("--technology"));
}

#[test]
fn test_report_help() {
    let mut cmd = Command::cargo_bin("venomstrike").unwrap();
    cmd.args(&["report", "--help"]);
    cmd.assert()
        .success()
        .stdout(predicate::str::contains("--input"));
}
