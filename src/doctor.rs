use std::process::Command;

use serde::Serialize;

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ToolCheck {
    pub name: String,
    pub executable: String,
    pub required: bool,
    pub available: bool,
    pub version: Option<String>,
    pub remediation: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct DoctorReport {
    pub status: String,
    pub package_version: &'static str,
    pub replay_available: bool,
    pub probe_rs_discovery_available: bool,
    pub probe_rs_guarded_flash_available: bool,
    pub tools: Vec<ToolCheck>,
}

pub fn inspect() -> DoctorReport {
    let tools = vec![
        inspect_tool(
            "probe-rs-cli",
            "probe-rs",
            false,
            "The probe-rs CLI is optional; install it for manual diagnostics and comparison.",
        ),
        inspect_tool(
            "openocd",
            "openocd",
            false,
            "Install a suitable OpenOCD distribution for fallback targets.",
        ),
    ];
    DoctorReport {
        status: "replay_and_probe_rs_guarded_flash_ready".to_string(),
        package_version: env!("CARGO_PKG_VERSION"),
        replay_available: true,
        probe_rs_discovery_available: true,
        probe_rs_guarded_flash_available: true,
        tools,
    }
}

fn inspect_tool(name: &str, executable: &str, required: bool, remediation: &str) -> ToolCheck {
    let output = Command::new(executable).arg("--version").output();
    match output {
        Ok(output) => {
            let stdout = String::from_utf8_lossy(&output.stdout);
            let stderr = String::from_utf8_lossy(&output.stderr);
            let version = stdout
                .lines()
                .chain(stderr.lines())
                .find(|line| !line.trim().is_empty())
                .map(|line| line.trim().to_string());
            ToolCheck {
                name: name.to_string(),
                executable: executable.to_string(),
                required,
                available: output.status.success(),
                version,
                remediation: (!output.status.success()).then(|| remediation.to_string()),
            }
        }
        Err(_) => ToolCheck {
            name: name.to_string(),
            executable: executable.to_string(),
            required,
            available: false,
            version: None,
            remediation: Some(remediation.to_string()),
        },
    }
}
