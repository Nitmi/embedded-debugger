use std::path::PathBuf;

use clap::{Args, Parser, Subcommand, ValueEnum};
use serde::Serialize;
use serde_json::{Value, json};

use crate::{
    backend::{
        probe_rs,
        replay::{ReplayBackend, ReplayFixture},
    },
    doctor,
    error::{DebugError, Result},
    service::{DebugService, inspect_evidence},
};

#[derive(Debug, Parser)]
#[command(name = "embedded-debugger", version, about)]
pub struct Cli {
    #[arg(long, global = true, help = "emit one versioned JSON result on stdout")]
    pub json: bool,

    #[arg(long, global = true, value_enum, default_value_t = BackendArg::Replay)]
    pub backend: BackendArg,

    #[arg(long, global = true, value_name = "FILE")]
    pub fixture: Option<PathBuf>,

    #[command(subcommand)]
    pub command: Command,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum BackendArg {
    Replay,
    ProbeRs,
    Openocd,
}

#[derive(Debug, Subcommand)]
pub enum Command {
    Doctor,
    Probes {
        #[command(subcommand)]
        command: ProbeCommand,
    },
    Flash {
        #[command(subcommand)]
        command: FlashCommand,
    },
    Replay {
        #[command(subcommand)]
        command: ReplayCommand,
    },
    Snapshot {
        #[command(subcommand)]
        command: SnapshotCommand,
    },
}

#[derive(Debug, Subcommand)]
pub enum ProbeCommand {
    List,
}

#[derive(Debug, Subcommand)]
pub enum FlashCommand {
    Plan(FlashSelection),
    Execute(FlashExecute),
}

#[derive(Debug, Args)]
pub struct FlashSelection {
    pub firmware: PathBuf,

    #[arg(long)]
    pub probe: Option<String>,

    #[arg(long)]
    pub target: Option<String>,
}

#[derive(Debug, Args)]
pub struct FlashExecute {
    #[command(flatten)]
    pub selection: FlashSelection,

    #[arg(long, help = "exact confirm_digest returned by flash plan")]
    pub confirm: String,

    #[arg(long, value_name = "FILE")]
    pub evidence: PathBuf,
}

#[derive(Debug, Subcommand)]
pub enum ReplayCommand {
    Validate,
}

#[derive(Debug, Subcommand)]
pub enum SnapshotCommand {
    Inspect { evidence: PathBuf },
}

#[derive(Debug)]
pub struct CommandResult {
    pub operation: &'static str,
    pub data: Value,
    pub human: String,
}

impl CommandResult {
    fn serializable<T: Serialize>(
        operation: &'static str,
        value: &T,
        human: impl Into<String>,
    ) -> Self {
        Self {
            operation,
            data: serde_json::to_value(value).expect("command result always serializes"),
            human: human.into(),
        }
    }
}

impl Cli {
    pub fn operation_name(&self) -> &'static str {
        match &self.command {
            Command::Doctor => "doctor",
            Command::Probes { .. } => "probes.list",
            Command::Flash {
                command: FlashCommand::Plan(_),
            } => "flash.plan",
            Command::Flash {
                command: FlashCommand::Execute(_),
            } => "flash.execute",
            Command::Replay { .. } => "replay.validate",
            Command::Snapshot { .. } => "snapshot.inspect",
        }
    }
}

pub fn execute(cli: &Cli) -> Result<CommandResult> {
    match &cli.command {
        Command::Doctor => {
            let report = doctor::inspect();
            Ok(CommandResult::serializable(
                "doctor",
                &report,
                format!(
                    "Replay backend: ready\nprobe-rs discovery: ready (embedded library)\nprobe-rs CLI: {}\nOpenOCD: {}",
                    availability(&report, "probe-rs-cli"),
                    availability(&report, "openocd")
                ),
            ))
        }
        Command::Snapshot {
            command: SnapshotCommand::Inspect { evidence },
        } => {
            let bundle = inspect_evidence(evidence)?;
            Ok(CommandResult::serializable(
                "snapshot.inspect",
                &bundle,
                format!(
                    "Evidence {}: {} on {} ({:?})",
                    bundle.capture_id, bundle.target.name, bundle.probe.id, bundle.core.state
                ),
            ))
        }
        Command::Probes {
            command: ProbeCommand::List,
        } => list_probes(cli),
        Command::Replay {
            command: ReplayCommand::Validate,
        } => {
            ensure_replay(cli.backend)?;
            let fixture_path = replay_fixture_path(cli)?;
            let fixture = ReplayFixture::load(fixture_path)?;
            Ok(CommandResult::serializable(
                "replay.validate",
                &json!({
                    "valid": true,
                    "fixture": fixture_path,
                    "probe": fixture.probe,
                    "target": fixture.target,
                    "capabilities": fixture.capabilities,
                }),
                format!(
                    "Valid replay fixture: {} ({})",
                    fixture.target.name, fixture.probe.id
                ),
            ))
        }
        Command::Flash {
            command: FlashCommand::Plan(selection),
        } => {
            ensure_replay(cli.backend)?;
            let service = DebugService::new(ReplayBackend::from_path(replay_fixture_path(cli)?)?);
            let plan = service.plan_flash(
                &selection.firmware,
                selection.probe.as_deref(),
                selection.target.as_deref(),
            )?;
            let human = format!(
                "Plan {}\nTarget: {}\nProbe: {}\nFirmware: {} bytes ({})\nRisk: {}\nConfirm: {}",
                plan.plan_id,
                plan.target.name,
                plan.probe.id,
                plan.firmware.size,
                plan.firmware.sha256,
                plan.risk,
                plan.confirm_digest
            );
            Ok(CommandResult::serializable("flash.plan", &plan, human))
        }
        Command::Flash {
            command: FlashCommand::Execute(arguments),
        } => {
            ensure_replay(cli.backend)?;
            let mut service =
                DebugService::new(ReplayBackend::from_path(replay_fixture_path(cli)?)?);
            let result = service.execute_flash(
                &arguments.selection.firmware,
                arguments.selection.probe.as_deref(),
                arguments.selection.target.as_deref(),
                &arguments.confirm,
                &arguments.evidence,
            )?;
            let human = format!(
                "Flashed and verified {} bytes\nTarget: {}\nSnapshot: {:?}, PC={}\nEvidence: {}",
                result.flash.bytes_programmed,
                result.session.target.name,
                result.snapshot.state,
                result.snapshot.pc,
                result.evidence.path
            );
            Ok(CommandResult::serializable("flash.execute", &result, human))
        }
    }
}

fn list_probes(cli: &Cli) -> Result<CommandResult> {
    let (backend, probes) = match cli.backend {
        BackendArg::Replay => {
            let service = DebugService::new(ReplayBackend::from_path(replay_fixture_path(cli)?)?);
            ("replay", service.probes()?)
        }
        BackendArg::ProbeRs => ("probe-rs", probe_rs::list_probes()),
        BackendArg::Openocd => {
            return Err(DebugError::new(
                crate::error::ErrorCode::CapabilityUnavailable,
                "OpenOCD discovery is not implemented in this milestone",
                6,
                json!({"backend": "openocd", "capability": "probe_discovery"}),
            ));
        }
    };
    let human = if probes.is_empty() {
        "No debug probes found.".to_string()
    } else {
        probes
            .iter()
            .map(|probe| {
                format!(
                    "{}  {:04X}:{:04X}  {}  {}",
                    probe.id,
                    probe.vendor_id,
                    probe.product_id,
                    probe.product.as_deref().unwrap_or("unknown"),
                    if probe.accessible {
                        "accessible"
                    } else {
                        "permission denied"
                    }
                )
            })
            .collect::<Vec<_>>()
            .join("\n")
    };
    Ok(CommandResult::serializable(
        "probes.list",
        &json!({"backend": backend, "probes": probes}),
        human,
    ))
}

fn replay_fixture_path(cli: &Cli) -> Result<&std::path::Path> {
    cli.fixture.as_deref().ok_or_else(|| {
        DebugError::config(
            "the replay backend requires --fixture <FILE>",
            json!({"backend": "replay"}),
        )
    })
}

fn ensure_replay(backend: BackendArg) -> Result<()> {
    if backend == BackendArg::Replay {
        Ok(())
    } else {
        Err(DebugError::new(
            crate::error::ErrorCode::CapabilityUnavailable,
            "selected hardware backend is not implemented in this milestone",
            6,
            json!({"backend": format!("{backend:?}").to_ascii_lowercase()}),
        ))
    }
}

fn availability(report: &doctor::DoctorReport, name: &str) -> &'static str {
    if report
        .tools
        .iter()
        .find(|tool| tool.name == name)
        .is_some_and(|tool| tool.available)
    {
        "available"
    } else {
        "not found (optional for Replay)"
    }
}
