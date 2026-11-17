use std::process::Command;

#[test]
fn info_json_reports_plugin_versions() {
    let output = Command::new(env!("CARGO_BIN_EXE_sriov"))
        .arg("info")
        .env("RUST_LOG", "netavark_sriov=info")
        .output()
        .expect("run sriov info");
    assert!(
        output.status.success(),
        "stderr {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        output.stderr.is_empty(),
        "stderr {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let parsed: serde_json::Value = serde_json::from_slice(&output.stdout).expect("info json");
    assert_eq!(parsed["api_version"], "1.0.0");
    assert_eq!(parsed["version"], "0.1.0");
}
