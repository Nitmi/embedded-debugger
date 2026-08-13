use std::path::PathBuf;

use clap::{Args, Parser, Subcommand, ValueEnum};
use serde::Serialize;
use serde_json::{Value, json};

use crate::{
    backend::{
        DebugBackend,
        probe_rs::{self, ProbeRsBackend},
        replay::{ReplayBackend, ReplayFixture},
    },
    doctor,
    error::{DebugError, Result},
    model::{Address, FlashRange},
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
    Test(ProbeTestSelection),
}

#[derive(Debug, Args)]
pub struct ProbeTestSelection {
    #[arg(long, help = "exact probe selector from probes list")]
    pub probe: String,

    #[arg(long, help = "exact target name")]
    pub target: String,
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

    #[arg(
        long,
        value_name = "ADDRESS",
        value_parser = parse_address,
        help = "raw BIN load address (required by probe-rs)"
    )]
    pub base_address: Option<Address>,
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
    Capture(SnapshotSelection),
    Inspect { evidence: PathBuf },
}

#[derive(Debug, Args)]
pub struct SnapshotSelection {
    #[arg(long, help = "exact probe selector from probes list")]
    pub probe: String,

    #[arg(long, help = "exact target name")]
    pub target: String,
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
            Command::Probes {
                command: ProbeCommand::List,
            } => "probes.list",
            Command::Probes {
                command: ProbeCommand::Test(_),
            } => "probes.test",
            Command::Flash {
                command: FlashCommand::Plan(_),
            } => "flash.plan",
            Command::Flash {
                command: FlashCommand::Execute(_),
            } => "flash.execute",
            Command::Replay { .. } => "replay.validate",
            Command::Snapshot {
                command: SnapshotCommand::Capture(_),
            } => "snapshot.capture",
            Command::Snapshot {
                command: SnapshotCommand::Inspect { .. },
            } => "snapshot.inspect",
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
                    "Replay backend: ready\nprobe-rs guarded flash: ready (embedded library)\nprobe-rs CLI: {}\nOpenOCD: {}",
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
        Command::Snapshot {
            command: SnapshotCommand::Capture(selection),
        } => capture_snapshot(cli, selection),
        Command::Probes {
            command: ProbeCommand::List,
        } => list_probes(cli),
        Command::Probes {
            command: ProbeCommand::Test(selection),
        } => test_probe(cli, selection),
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
        } => match cli.backend {
            BackendArg::Replay => {
                let service =
                    DebugService::new(ReplayBackend::from_path(replay_fixture_path(cli)?)?);
                run_flash_plan(&service, selection)
            }
            BackendArg::ProbeRs => {
                let backend = ProbeRsBackend::new(required_native_target(selection)?)?;
                run_flash_plan(&DebugService::new(backend), selection)
            }
            BackendArg::Openocd => Err(unsupported_openocd("flash")),
        },
        Command::Flash {
            command: FlashCommand::Execute(arguments),
        } => match cli.backend {
            BackendArg::Replay => {
                let mut service =
                    DebugService::new(ReplayBackend::from_path(replay_fixture_path(cli)?)?);
                run_flash_execute(&mut service, arguments)
            }
            BackendArg::ProbeRs => {
                let backend = ProbeRsBackend::new(required_native_target(&arguments.selection)?)?;
                run_flash_execute(&mut DebugService::new(backend), arguments)
            }
            BackendArg::Openocd => Err(unsupported_openocd("flash")),
        },
    }
}

fn run_flash_plan<B: DebugBackend>(
    service: &DebugService<B>,
    selection: &FlashSelection,
) -> Result<CommandResult> {
    let plan = service.plan_flash(
        &selection.firmware,
        selection.probe.as_deref(),
        selection.target.as_deref(),
        selection.base_address,
    )?;
    let human = format!(
        "Plan {}\nTarget: {}\nProbe: {}\nFirmware: {} bytes at {} ({})\nErase ranges: {}\nRisk: {}\nConfirm: {}",
        plan.plan_id,
        plan.target.name,
        plan.probe.id,
        plan.firmware.size,
        plan.firmware
            .base_address
            .map_or_else(|| "unknown".to_string(), |address| address.to_string()),
        plan.firmware.sha256,
        describe_ranges(&plan.erase_ranges),
        plan.risk,
        plan.confirm_digest
    );
    Ok(CommandResult::serializable("flash.plan", &plan, human))
}

fn describe_ranges(ranges: &[FlashRange]) -> String {
    ranges
        .iter()
        .map(|range| format!("{} + {} bytes", range.start, range.length))
        .collect::<Vec<_>>()
        .join(", ")
}

fn run_flash_execute<B: DebugBackend>(
    service: &mut DebugService<B>,
    arguments: &FlashExecute,
) -> Result<CommandResult> {
    let result = service.execute_flash(
        &arguments.selection.firmware,
        arguments.selection.probe.as_deref(),
        arguments.selection.target.as_deref(),
        arguments.selection.base_address,
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

fn list_probes(cli: &Cli) -> Result<CommandResult> {
    let (backend, probes) = match cli.backend {
        BackendArg::Replay => {
            let service = DebugService::new(ReplayBackend::from_path(replay_fixture_path(cli)?)?);
            ("replay", service.probes()?)
        }
        BackendArg::ProbeRs => ("probe-rs", probe_rs::list_probes()),
        BackendArg::Openocd => {
            return Err(unsupported_openocd("probe_discovery"));
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

fn test_probe(cli: &Cli, selection: &ProbeTestSelection) -> Result<CommandResult> {
    let report = match cli.backend {
        BackendArg::Replay => {
            let mut service =
                DebugService::new(ReplayBackend::from_path(replay_fixture_path(cli)?)?);
            service.test_probe_connection(&selection.probe, &selection.target)?
        }
        BackendArg::ProbeRs => {
            let backend = ProbeRsBackend::new(&selection.target)?;
            let mut service = DebugService::new(backend);
            service.test_probe_connection(&selection.probe, &selection.target)?
        }
        BackendArg::Openocd => return Err(unsupported_openocd("probe_connection_test")),
    };
    let human = format!(
        "Connected and disconnected {} on {}\nTarget: {} ({} core(s), {})\nRisk: {}\nEffects: {}",
        report.session.probe.id,
        report.session.backend,
        report.session.target.name,
        report.session.target.core_count,
        report.session.target.architecture,
        report.risk,
        describe_debug_control_effects(&report.effects)
    );
    Ok(CommandResult::serializable("probes.test", &report, human))
}

fn capture_snapshot(cli: &Cli, selection: &SnapshotSelection) -> Result<CommandResult> {
    let report = match cli.backend {
        BackendArg::Replay => {
            let mut service =
                DebugService::new(ReplayBackend::from_path(replay_fixture_path(cli)?)?);
            service.capture_snapshot(&selection.probe, &selection.target)?
        }
        BackendArg::ProbeRs => {
            let backend = ProbeRsBackend::new(&selection.target)?;
            let mut service = DebugService::new(backend);
            service.capture_snapshot(&selection.probe, &selection.target)?
        }
        BackendArg::Openocd => return Err(unsupported_openocd("multi_core_snapshot")),
    };
    let core_lines = report
        .cores
        .iter()
        .map(|core| match &core.snapshot {
            Some(snapshot) => format!(
                "core {} ({}, {}): original={:?}, captured={:?}, restored={:?}, PC={}, SP={}",
                core.index,
                core.name,
                core.architecture,
                core.original_state
                    .expect("available cores always contain an original state"),
                snapshot.captured_state,
                snapshot.state,
                snapshot.pc,
                snapshot.sp
            ),
            None => format!(
                "core {} ({}, {}): unavailable ({})",
                core.index,
                core.name,
                core.architecture,
                core.unavailable_reason.as_deref().unwrap_or("unknown")
            ),
        })
        .collect::<Vec<_>>()
        .join("\n");
    let available_cores = report.cores.iter().filter(|core| core.available).count();
    let human = format!(
        "Observed {} described core(s), {} available on {}\n{}\nRisk: {}\nEffects: {}",
        report.cores.len(),
        available_cores,
        report.session.target.name,
        core_lines,
        report.risk,
        describe_debug_control_effects(&report.effects)
    );
    Ok(CommandResult::serializable(
        "snapshot.capture",
        &report,
        human,
    ))
}

fn describe_debug_control_effects(effects: &crate::model::DebugControlEffects) -> String {
    if effects.volatile_target_state_notes.is_empty() {
        return "no backend-managed volatile target changes declared".to_string();
    }
    effects.volatile_target_state_notes.join("; ")
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

fn required_native_target(selection: &FlashSelection) -> Result<&str> {
    selection.target.as_deref().ok_or_else(|| {
        DebugError::config(
            "the probe-rs backend requires an exact --target name",
            json!({"backend": "probe-rs"}),
        )
    })
}

fn parse_address(value: &str) -> std::result::Result<Address, String> {
    Address::parse(value).map_err(|error| error.message)
}

fn unsupported_openocd(capability: &str) -> DebugError {
    DebugError::new(
        crate::error::ErrorCode::CapabilityUnavailable,
        "OpenOCD backend is not implemented in this milestone",
        6,
        json!({"backend": "openocd", "capability": capability}),
    )
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
