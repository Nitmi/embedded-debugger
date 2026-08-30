use std::{ffi::OsString, io, path::PathBuf};

use clap::{Args, Parser, Subcommand, ValueEnum};
use serde::Serialize;
use serde_json::{Value, json};

use crate::{
    backend::{
        DebugBackend,
        openocd::{
            self, GdbInspectOptions, GdbMiTestOptions, OpenOcdGdbSessionOptions,
            OpenOcdHardwareBreakpointOptions, OpenOcdHardwareWatchpointHitOptions,
            OpenOcdHardwareWatchpointMode, OpenOcdHardwareWatchpointOptions, OpenOcdInspectOptions,
            OpenOcdMemorySnapshotOptions, OpenOcdRegisterSnapshotOptions, OpenOcdResumeOptions,
            OpenOcdServerOptions, OpenOcdStackElfOptions, OpenOcdStackSnapshotOptions,
            OpenOcdTargetOptions,
        },
        probe_rs::{self, ProbeRsBackend},
        replay::{ReplayBackend, ReplayFixture},
    },
    doctor,
    error::{DebugError, Result},
    firmware::{FirmwareFormat, FirmwareInputOptions, parse_esp_flash_size},
    model::{
        Address, ContinueUntilHaltOptions, CoreExecutionAction,
        DEFAULT_CONTINUE_UNTIL_HALT_POLL_INTERVAL_MS, DEFAULT_CONTINUE_UNTIL_HALT_TIMEOUT_MS,
        FlashRange, MemoryRegionKind,
    },
    service::{DebugService, inspect_evidence},
    session, supervisor,
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
    Registers {
        #[command(subcommand)]
        command: RegisterCommand,
    },
    Memory {
        #[command(subcommand)]
        command: MemoryCommand,
    },
    Core {
        #[command(subcommand)]
        command: CoreCommand,
    },
    Session {
        #[command(subcommand)]
        command: SessionCommand,
    },
    Mcp {
        #[command(subcommand)]
        command: McpCommand,
    },
    Supervisor {
        #[command(subcommand)]
        command: SupervisorCommand,
    },
    Openocd {
        #[command(subcommand)]
        command: OpenOcdCommand,
    },
}

#[derive(Debug, Subcommand)]
pub enum OpenOcdCommand {
    Inspect(OpenOcdInspectSelection),
    Breakpoint {
        #[command(subcommand)]
        command: OpenOcdBreakpointCommand,
    },
    Watchpoint {
        #[command(subcommand)]
        command: OpenOcdWatchpointCommand,
    },
    Gdb {
        #[command(subcommand)]
        command: OpenOcdGdbCommand,
    },
    Reset {
        #[command(subcommand)]
        command: OpenOcdResetCommand,
    },
    Resume {
        #[command(subcommand)]
        command: OpenOcdResumeCommand,
    },
    Stack {
        #[command(subcommand)]
        command: OpenOcdStackCommand,
    },
    Memory {
        #[command(subcommand)]
        command: OpenOcdMemoryCommand,
    },
    Registers {
        #[command(subcommand)]
        command: OpenOcdRegistersCommand,
    },
    Server {
        #[command(subcommand)]
        command: OpenOcdServerCommand,
    },
    Session {
        #[command(subcommand)]
        command: OpenOcdSessionCommand,
    },
    Target {
        #[command(subcommand)]
        command: OpenOcdTargetCommand,
    },
}

#[derive(Debug, Subcommand)]
pub enum OpenOcdBreakpointCommand {
    Plan(OpenOcdBreakpointSelection),
    Test(OpenOcdBreakpointTestSelection),
}

#[derive(Debug, Args)]
pub struct OpenOcdBreakpointSelection {
    #[command(flatten)]
    pub session: OpenOcdSessionSelection,

    #[arg(
        long,
        value_name = "ADDRESS",
        value_parser = parse_address,
        help = "exact non-zero numeric instruction address for one temporary hardware breakpoint"
    )]
    pub address: Address,
}

#[derive(Debug, Args)]
pub struct OpenOcdBreakpointTestSelection {
    #[command(flatten)]
    pub breakpoint: OpenOcdBreakpointSelection,

    #[arg(
        long,
        help = "exact confirm_digest returned by openocd breakpoint plan"
    )]
    pub confirm: String,
}

#[derive(Debug, Subcommand)]
pub enum OpenOcdWatchpointCommand {
    Plan(OpenOcdWatchpointSelection),
    Test(OpenOcdWatchpointTestSelection),
    Hit {
        #[command(subcommand)]
        command: OpenOcdWatchpointHitCommand,
    },
}

#[derive(Debug, Subcommand)]
pub enum OpenOcdWatchpointHitCommand {
    Plan(OpenOcdWatchpointHitSelection),
    Test(OpenOcdWatchpointHitTestSelection),
}

#[derive(Debug, Args)]
pub struct OpenOcdWatchpointSelection {
    #[command(flatten)]
    pub session: OpenOcdSessionSelection,

    #[arg(
        long,
        value_name = "ADDRESS",
        value_parser = parse_address,
        help = "exact non-zero naturally aligned numeric RAM address"
    )]
    pub address: Address,

    #[arg(
        long,
        value_name = "LENGTH",
        value_parser = parse_length,
        help = "exact hardware-watchpoint byte width: 1, 2, 4, or 8"
    )]
    pub length: u64,

    #[arg(long, value_name = "ADDRESS", value_parser = parse_address)]
    pub region_start: Address,

    #[arg(
        long,
        value_name = "LENGTH",
        value_parser = parse_length,
        help = "declared containing RAM region length"
    )]
    pub region_length: u64,

    #[arg(long, value_enum, help = "confirmed region type; only RAM is accepted")]
    pub region_kind: OpenOcdMemoryRegionKindArg,

    #[arg(
        long,
        value_enum,
        help = "hardware-only GDB watchpoint mode; write-only is intentionally unavailable"
    )]
    pub mode: OpenOcdWatchpointModeArg,
}

#[derive(Debug, Args)]
pub struct OpenOcdWatchpointTestSelection {
    #[command(flatten)]
    pub watchpoint: OpenOcdWatchpointSelection,

    #[arg(
        long,
        help = "exact confirm_digest returned by openocd watchpoint plan"
    )]
    pub confirm: String,
}

#[derive(Debug, Args)]
pub struct OpenOcdWatchpointHitSelection {
    #[command(flatten)]
    pub watchpoint: OpenOcdWatchpointSelection,

    #[arg(
        long,
        value_name = "ADDRESS",
        value_parser = parse_address,
        help = "confirmed start of the half-open PC interval allowed to attribute the hit"
    )]
    pub expected_pc_start: Address,

    #[arg(
        long,
        value_name = "LENGTH",
        value_parser = parse_length,
        help = "non-zero expected PC interval length, at most 1 MiB"
    )]
    pub expected_pc_length: u64,

    #[arg(
        long,
        default_value_t = openocd::DEFAULT_OPENOCD_WATCHPOINT_HIT_TIMEOUT_MS,
        value_name = "MILLISECONDS",
        help = "bounded wait for one correlated hardware-watchpoint stop"
    )]
    pub hit_timeout_ms: u64,
}

#[derive(Debug, Args)]
pub struct OpenOcdWatchpointHitTestSelection {
    #[command(flatten)]
    pub hit: OpenOcdWatchpointHitSelection,

    #[arg(
        long,
        help = "exact confirm_digest returned by openocd watchpoint hit plan"
    )]
    pub confirm: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum OpenOcdWatchpointModeArg {
    Read,
    Access,
}

impl From<OpenOcdWatchpointModeArg> for OpenOcdHardwareWatchpointMode {
    fn from(value: OpenOcdWatchpointModeArg) -> Self {
        match value {
            OpenOcdWatchpointModeArg::Read => Self::Read,
            OpenOcdWatchpointModeArg::Access => Self::Access,
        }
    }
}

#[derive(Debug, Args)]
pub struct OpenOcdInspectSelection {
    #[arg(long, default_value = "openocd", value_name = "PATH")]
    pub executable: PathBuf,

    #[arg(long = "config", value_name = "FILE")]
    pub config_files: Vec<PathBuf>,

    #[arg(long = "search", value_name = "DIR")]
    pub search_dirs: Vec<PathBuf>,

    #[arg(
        long,
        default_value_t = openocd::DEFAULT_OPENOCD_VERSION_TIMEOUT_MS,
        help = "bounded OpenOCD --version deadline in milliseconds (100..=30000)"
    )]
    pub timeout_ms: u64,
}

#[derive(Debug, Subcommand)]
pub enum OpenOcdGdbCommand {
    Inspect(GdbInspectSelection),
    Test(GdbMiTestSelection),
}

#[derive(Debug, Args)]
pub struct GdbInspectSelection {
    #[arg(long, default_value = "gdb", value_name = "PATH")]
    pub executable: PathBuf,

    #[arg(
        long,
        default_value_t = openocd::DEFAULT_GDB_VERSION_TIMEOUT_MS,
        help = "bounded GDB --version deadline in milliseconds (100..=30000)"
    )]
    pub timeout_ms: u64,
}

#[derive(Debug, Args)]
pub struct GdbMiTestSelection {
    #[arg(long, default_value = "gdb", value_name = "PATH")]
    pub executable: PathBuf,

    #[arg(
        long,
        default_value_t = openocd::DEFAULT_GDB_VERSION_TIMEOUT_MS,
        help = "bounded GDB --version deadline in milliseconds (100..=30000)"
    )]
    pub version_timeout_ms: u64,

    #[arg(
        long,
        default_value_t = openocd::DEFAULT_GDB_MI_STARTUP_TIMEOUT_MS,
        help = "bounded MI startup and version handshake deadline in milliseconds (100..=60000)"
    )]
    pub startup_timeout_ms: u64,

    #[arg(
        long,
        default_value_t = openocd::DEFAULT_GDB_MI_SHUTDOWN_TIMEOUT_MS,
        help = "bounded MI exit deadline in milliseconds (100..=30000)"
    )]
    pub shutdown_timeout_ms: u64,
}

#[derive(Debug, Subcommand)]
pub enum OpenOcdServerCommand {
    Plan(OpenOcdServerSelection),
    Test(OpenOcdServerTestSelection),
}

#[derive(Debug, Args)]
pub struct OpenOcdServerSelection {
    #[arg(long, default_value = "openocd", value_name = "PATH")]
    pub executable: PathBuf,

    #[arg(long = "config", value_name = "FILE")]
    pub config_files: Vec<PathBuf>,

    #[arg(long = "search", value_name = "DIR")]
    pub search_dirs: Vec<PathBuf>,

    #[arg(
        long,
        default_value_t = openocd::DEFAULT_OPENOCD_VERSION_TIMEOUT_MS,
        help = "bounded OpenOCD --version deadline in milliseconds (100..=30000)"
    )]
    pub version_timeout_ms: u64,

    #[arg(
        long,
        default_value_t = openocd::DEFAULT_OPENOCD_SERVER_STARTUP_TIMEOUT_MS,
        help = "bounded server readiness deadline in milliseconds (100..=60000)"
    )]
    pub startup_timeout_ms: u64,

    #[arg(
        long,
        default_value_t = openocd::DEFAULT_OPENOCD_SERVER_SHUTDOWN_TIMEOUT_MS,
        help = "bounded graceful shutdown deadline in milliseconds (100..=30000)"
    )]
    pub shutdown_timeout_ms: u64,
}

#[derive(Debug, Args)]
pub struct OpenOcdServerTestSelection {
    #[command(flatten)]
    pub server: OpenOcdServerSelection,

    #[arg(long, help = "exact confirm_digest returned by openocd server plan")]
    pub confirm: String,
}

#[derive(Debug, Subcommand)]
pub enum OpenOcdSessionCommand {
    Plan(OpenOcdSessionSelection),
    Test(OpenOcdSessionTestSelection),
}

#[derive(Debug, Args)]
pub struct OpenOcdSessionSelection {
    #[arg(long, default_value = "openocd", value_name = "PATH")]
    pub openocd_executable: PathBuf,

    #[arg(long, default_value = "gdb", value_name = "PATH")]
    pub gdb_executable: PathBuf,

    #[arg(
        long,
        value_name = "FILE",
        help = "exact Espressif Xtensa target configuration loaded through XTENSA_GNU_CONFIG"
    )]
    pub gdb_xtensa_config: Option<PathBuf>,

    #[arg(
        long,
        value_name = "NAME",
        help = "exact OpenOCD 'target current' name required before GDB starts"
    )]
    pub expected_target: String,

    #[arg(long = "config", value_name = "FILE")]
    pub config_files: Vec<PathBuf>,

    #[arg(long = "search", value_name = "DIR")]
    pub search_dirs: Vec<PathBuf>,

    #[arg(
        long,
        default_value_t = openocd::DEFAULT_OPENOCD_VERSION_TIMEOUT_MS,
        help = "bounded OpenOCD --version deadline in milliseconds (100..=30000)"
    )]
    pub openocd_version_timeout_ms: u64,

    #[arg(
        long,
        default_value_t = openocd::DEFAULT_OPENOCD_SERVER_STARTUP_TIMEOUT_MS,
        help = "bounded OpenOCD server readiness deadline in milliseconds (100..=60000)"
    )]
    pub openocd_startup_timeout_ms: u64,

    #[arg(
        long,
        default_value_t = openocd::DEFAULT_OPENOCD_SERVER_SHUTDOWN_TIMEOUT_MS,
        help = "bounded OpenOCD server shutdown deadline in milliseconds (100..=30000)"
    )]
    pub openocd_shutdown_timeout_ms: u64,

    #[arg(
        long,
        default_value_t = openocd::DEFAULT_GDB_VERSION_TIMEOUT_MS,
        help = "bounded GDB --version deadline in milliseconds (100..=30000)"
    )]
    pub gdb_version_timeout_ms: u64,

    #[arg(
        long,
        default_value_t = openocd::DEFAULT_GDB_MI_STARTUP_TIMEOUT_MS,
        help = "bounded remote MI startup handshake deadline in milliseconds (100..=60000)"
    )]
    pub gdb_startup_timeout_ms: u64,

    #[arg(
        long,
        default_value_t = openocd::DEFAULT_GDB_MI_COMMAND_TIMEOUT_MS,
        help = "bounded remote MI command deadline in milliseconds (100..=60000)"
    )]
    pub gdb_command_timeout_ms: u64,

    #[arg(
        long,
        default_value_t = openocd::DEFAULT_GDB_MI_SHUTDOWN_TIMEOUT_MS,
        help = "bounded remote MI exit deadline in milliseconds (100..=30000)"
    )]
    pub gdb_shutdown_timeout_ms: u64,

    #[arg(
        long,
        default_value_t = openocd::DEFAULT_OPENOCD_TARGET_STATE_TIMEOUT_MS,
        help = "bounded target-state restoration deadline in milliseconds (100..=30000)"
    )]
    pub target_state_timeout_ms: u64,
}

#[derive(Debug, Args)]
pub struct OpenOcdSessionTestSelection {
    #[command(flatten)]
    pub session: OpenOcdSessionSelection,

    #[arg(long, help = "exact confirm_digest returned by openocd session plan")]
    pub confirm: String,
}

#[derive(Debug, Subcommand)]
pub enum OpenOcdRegistersCommand {
    Plan(OpenOcdRegistersSelection),
    Test(OpenOcdRegistersTestSelection),
}

#[derive(Debug, Args)]
pub struct OpenOcdRegistersSelection {
    #[command(flatten)]
    pub session: OpenOcdSessionSelection,

    #[arg(
        long = "register",
        value_name = "NAME",
        help = "selected GDB register name; repeat 1..=64 times"
    )]
    pub registers: Vec<String>,
}

#[derive(Debug, Args)]
pub struct OpenOcdRegistersTestSelection {
    #[command(flatten)]
    pub registers: OpenOcdRegistersSelection,

    #[arg(long, help = "exact confirm_digest returned by openocd registers plan")]
    pub confirm: String,
}

#[derive(Debug, Subcommand)]
pub enum OpenOcdStackCommand {
    Plan(OpenOcdStackSelection),
    Test(OpenOcdStackTestSelection),
}

#[derive(Debug, Args)]
pub struct OpenOcdStackSelection {
    #[command(flatten)]
    pub session: OpenOcdSessionSelection,

    #[arg(
        long,
        value_name = "COUNT",
        help = "exact maximum returned frame count, limited to 1..=32"
    )]
    pub max_frames: u64,

    #[arg(
        long,
        value_name = "FILE",
        help = "exact executable ELF to annotate offline after the confirmed stack snapshot"
    )]
    pub elf: Option<PathBuf>,
}

#[derive(Debug, Args)]
pub struct OpenOcdStackTestSelection {
    #[command(flatten)]
    pub stack: OpenOcdStackSelection,

    #[arg(long, help = "exact confirm_digest returned by openocd stack plan")]
    pub confirm: String,
}

#[derive(Debug, Subcommand)]
pub enum OpenOcdMemoryCommand {
    Plan(OpenOcdMemorySelection),
    Test(OpenOcdMemoryTestSelection),
}

#[derive(Debug, Args)]
pub struct OpenOcdMemorySelection {
    #[command(flatten)]
    pub session: OpenOcdSessionSelection,

    #[arg(long, value_name = "ADDRESS", value_parser = parse_address)]
    pub address: Address,

    #[arg(
        long,
        value_name = "LENGTH",
        value_parser = parse_length,
        help = "exact byte count, limited to 4096"
    )]
    pub length: u64,

    #[arg(long, value_name = "ADDRESS", value_parser = parse_address)]
    pub region_start: Address,

    #[arg(
        long,
        value_name = "LENGTH",
        value_parser = parse_length,
        help = "declared containing RAM/NVM region length"
    )]
    pub region_length: u64,

    #[arg(
        long,
        value_enum,
        help = "confirmed region type; MMIO and unknown regions are not accepted"
    )]
    pub region_kind: OpenOcdMemoryRegionKindArg,
}

#[derive(Debug, Args)]
pub struct OpenOcdMemoryTestSelection {
    #[command(flatten)]
    pub memory: OpenOcdMemorySelection,

    #[arg(long, help = "exact confirm_digest returned by openocd memory plan")]
    pub confirm: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum OpenOcdMemoryRegionKindArg {
    Ram,
    Nvm,
}

impl From<OpenOcdMemoryRegionKindArg> for MemoryRegionKind {
    fn from(value: OpenOcdMemoryRegionKindArg) -> Self {
        match value {
            OpenOcdMemoryRegionKindArg::Ram => Self::Ram,
            OpenOcdMemoryRegionKindArg::Nvm => Self::Nvm,
        }
    }
}

#[derive(Debug, Subcommand)]
pub enum OpenOcdResetCommand {
    Plan(OpenOcdResetSelection),
    Test(OpenOcdResetTestSelection),
}

#[derive(Debug, Args)]
pub struct OpenOcdResetSelection {
    #[command(flatten)]
    pub server: OpenOcdServerSelection,

    #[arg(
        long,
        value_name = "NAME",
        help = "exact OpenOCD 'target current' name verified before and after global reset"
    )]
    pub expected_target: String,

    #[arg(
        long,
        default_value_t = openocd::DEFAULT_OPENOCD_TARGET_STATE_TIMEOUT_MS,
        help = "bounded reset/recovery state transition deadline in milliseconds (100..=30000)"
    )]
    pub target_state_timeout_ms: u64,
}

#[derive(Debug, Args)]
pub struct OpenOcdResetTestSelection {
    #[command(flatten)]
    pub reset: OpenOcdResetSelection,

    #[arg(long, help = "exact confirm_digest returned by openocd reset plan")]
    pub confirm: String,
}

#[derive(Debug, Subcommand)]
pub enum OpenOcdResumeCommand {
    Plan(OpenOcdResumeSelection),
    Test(OpenOcdResumeTestSelection),
}

#[derive(Debug, Args)]
pub struct OpenOcdResumeSelection {
    #[command(flatten)]
    pub server: OpenOcdServerSelection,

    #[arg(
        long,
        value_name = "NAME",
        help = "exact OpenOCD 'target current' name allowed to receive at most one resume"
    )]
    pub expected_target: String,

    #[arg(
        long,
        default_value_t = openocd::DEFAULT_OPENOCD_TARGET_STATE_TIMEOUT_MS,
        help = "bounded final-running verification deadline in milliseconds (100..=30000)"
    )]
    pub target_state_timeout_ms: u64,
}

#[derive(Debug, Args)]
pub struct OpenOcdResumeTestSelection {
    #[command(flatten)]
    pub resume: OpenOcdResumeSelection,

    #[arg(long, help = "exact confirm_digest returned by openocd resume plan")]
    pub confirm: String,
}

#[derive(Debug, Subcommand)]
pub enum OpenOcdTargetCommand {
    Plan(OpenOcdTargetSelection),
    Test(OpenOcdTargetTestSelection),
}

#[derive(Debug, Args)]
pub struct OpenOcdTargetSelection {
    #[command(flatten)]
    pub server: OpenOcdServerSelection,

    #[arg(
        long,
        value_name = "NAME",
        help = "exact OpenOCD 'target current' name required before target control"
    )]
    pub expected_target: String,

    #[arg(
        long,
        default_value_t = openocd::DEFAULT_OPENOCD_TARGET_STATE_TIMEOUT_MS,
        help = "bounded halt/resume state transition deadline in milliseconds (100..=30000)"
    )]
    pub target_state_timeout_ms: u64,
}

#[derive(Debug, Args)]
pub struct OpenOcdTargetTestSelection {
    #[command(flatten)]
    pub target: OpenOcdTargetSelection,

    #[arg(long, help = "exact confirm_digest returned by openocd target plan")]
    pub confirm: String,
}

#[derive(Debug, Subcommand)]
pub enum SessionCommand {
    Serve(SessionServeSelection),
}

#[derive(Debug, Subcommand)]
pub enum McpCommand {
    Serve(McpServeSelection),
}

#[derive(Debug, Subcommand)]
pub enum SupervisorCommand {
    Mcp(SupervisorMcpSelection),
}

#[derive(Debug, Args)]
pub struct McpServeSelection {
    #[arg(
        long,
        help = "exact target used to initialize a native probe-rs backend; Replay may omit it"
    )]
    pub target: Option<String>,

    #[arg(
        long,
        default_value_t = session::DEFAULT_SESSION_IDLE_TIMEOUT_MS,
        help = "close the active lease and exit after this many idle milliseconds; 0 disables (100..=86400000)"
    )]
    pub idle_timeout_ms: u64,
}

#[derive(Debug, Args)]
pub struct SupervisorMcpSelection {
    #[arg(
        long,
        help = "exact target used to initialize a native probe-rs backend; Replay may omit it"
    )]
    pub target: Option<String>,

    #[arg(
        long,
        default_value_t = session::DEFAULT_SESSION_IDLE_TIMEOUT_MS,
        help = "child MCP lease idle timeout in milliseconds; 0 disables (100..=86400000)"
    )]
    pub idle_timeout_ms: u64,

    #[arg(
        long,
        default_value_t = supervisor::default_max_restarts(),
        help = "maximum child restarts after an unexpected exit (0..=32)"
    )]
    pub max_restarts: u32,

    #[arg(
        long,
        default_value_t = supervisor::default_restart_delay_ms(),
        help = "delay between child restarts in milliseconds (0..=60000)"
    )]
    pub restart_delay_ms: u64,
}

#[derive(Debug, Args)]
pub struct SessionServeSelection {
    #[arg(long, help = "exact target name that this JSONL server is bound to")]
    pub target: String,

    #[arg(
        long,
        default_value_t = session::DEFAULT_SESSION_IDLE_TIMEOUT_MS,
        help = "close the active lease and exit after this many idle milliseconds; 0 disables (100..=86400000)"
    )]
    pub idle_timeout_ms: u64,
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
        value_enum,
        help = "firmware semantics; .elf requires an explicit idf selection"
    )]
    pub format: Option<FirmwareFormatArg>,

    #[arg(
        long,
        value_name = "ADDRESS",
        value_parser = parse_address,
        help = "raw BIN load address (required by probe-rs)"
    )]
    pub base_address: Option<Address>,

    #[arg(
        long,
        value_name = "SIZE",
        value_parser = parse_esp_flash_size,
        help = "physical SPI Flash capacity for ESP-IDF generation, for example 8MB"
    )]
    pub flash_size: Option<u64>,

    #[arg(
        long,
        value_name = "REVISION",
        help = "ESP chip revision encoded as major * 100 + minor"
    )]
    pub chip_revision: Option<u16>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum FirmwareFormatArg {
    Bin,
    Idf,
}

impl From<FirmwareFormatArg> for FirmwareFormat {
    fn from(value: FirmwareFormatArg) -> Self {
        match value {
            FirmwareFormatArg::Bin => Self::Bin,
            FirmwareFormatArg::Idf => Self::EspIdf,
        }
    }
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
    ResetCapture(SnapshotSelection),
    Inspect { evidence: PathBuf },
}

#[derive(Debug, Args)]
pub struct SnapshotSelection {
    #[arg(long, help = "exact probe selector from probes list")]
    pub probe: String,

    #[arg(long, help = "exact target name")]
    pub target: String,
}

#[derive(Debug, Subcommand)]
pub enum RegisterCommand {
    Read(RegisterReadSelection),
}

#[derive(Debug, Args)]
pub struct RegisterReadSelection {
    #[arg(
        value_name = "NAME",
        num_args = 0..=64,
        help = "register names or aliases; omit to read the bounded register inventory"
    )]
    pub names: Vec<String>,

    #[arg(long, help = "exact probe selector from probes list")]
    pub probe: String,

    #[arg(long, help = "exact target name")]
    pub target: String,

    #[arg(long, default_value_t = 0, help = "zero-based target core index")]
    pub core: u32,
}

#[derive(Debug, Subcommand)]
pub enum MemoryCommand {
    Read(MemoryReadSelection),
}

#[derive(Debug, Args)]
pub struct MemoryReadSelection {
    #[arg(value_name = "ADDRESS", value_parser = parse_address)]
    pub address: Address,

    #[arg(
        value_name = "LENGTH",
        value_parser = parse_length,
        help = "exact byte count, limited to 4096; decimal or 0x-prefixed hexadecimal"
    )]
    pub length: u64,

    #[arg(long, help = "exact probe selector from probes list")]
    pub probe: String,

    #[arg(long, help = "exact target name")]
    pub target: String,

    #[arg(long, default_value_t = 0, help = "zero-based target core index")]
    pub core: u32,
}

#[derive(Debug, Subcommand)]
pub enum CoreCommand {
    Status(CoreSelection),
    Halt(CoreSelection),
    Run(CoreSelection),
    Continue(CoreSelection),
    ContinueUntilHalt(CoreContinueUntilHaltSelection),
    Step(CoreSelection),
}

#[derive(Debug, Args)]
pub struct CoreContinueUntilHaltSelection {
    #[command(flatten)]
    pub selection: CoreSelection,

    #[arg(
        long,
        default_value_t = DEFAULT_CONTINUE_UNTIL_HALT_TIMEOUT_MS,
        help = "bounded wait deadline in milliseconds (10..=60000)"
    )]
    pub timeout_ms: u64,

    #[arg(
        long,
        default_value_t = DEFAULT_CONTINUE_UNTIL_HALT_POLL_INTERVAL_MS,
        help = "status polling interval in milliseconds (10..=1000 and no greater than timeout)"
    )]
    pub poll_interval_ms: u64,
}

#[derive(Debug, Args)]
pub struct CoreSelection {
    #[arg(long, help = "exact probe selector from probes list")]
    pub probe: String,

    #[arg(long, help = "exact target name")]
    pub target: String,

    #[arg(long, default_value_t = 0, help = "zero-based target core index")]
    pub core: u32,
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
                command: SnapshotCommand::ResetCapture(_),
            } => "snapshot.reset_capture",
            Command::Snapshot {
                command: SnapshotCommand::Inspect { .. },
            } => "snapshot.inspect",
            Command::Registers {
                command: RegisterCommand::Read(_),
            } => "registers.read",
            Command::Memory {
                command: MemoryCommand::Read(_),
            } => "memory.read",
            Command::Core {
                command: CoreCommand::Status(_),
            } => "core.status",
            Command::Core {
                command: CoreCommand::Halt(_),
            } => "core.halt",
            Command::Core {
                command: CoreCommand::Run(_),
            } => "core.run",
            Command::Core {
                command: CoreCommand::Continue(_),
            } => "core.continue",
            Command::Core {
                command: CoreCommand::ContinueUntilHalt(_),
            } => "core.continue_until_halt",
            Command::Core {
                command: CoreCommand::Step(_),
            } => "core.step",
            Command::Session { .. } => "session.serve",
            Command::Mcp { .. } => "mcp.serve",
            Command::Supervisor { .. } => "supervisor.mcp",
            Command::Openocd {
                command: OpenOcdCommand::Inspect(_),
            } => "openocd.inspect",
            Command::Openocd {
                command:
                    OpenOcdCommand::Breakpoint {
                        command: OpenOcdBreakpointCommand::Plan(_),
                    },
            } => "openocd.breakpoint.plan",
            Command::Openocd {
                command:
                    OpenOcdCommand::Breakpoint {
                        command: OpenOcdBreakpointCommand::Test(_),
                    },
            } => "openocd.breakpoint.test",
            Command::Openocd {
                command:
                    OpenOcdCommand::Watchpoint {
                        command: OpenOcdWatchpointCommand::Plan(_),
                    },
            } => "openocd.watchpoint.plan",
            Command::Openocd {
                command:
                    OpenOcdCommand::Watchpoint {
                        command: OpenOcdWatchpointCommand::Test(_),
                    },
            } => "openocd.watchpoint.test",
            Command::Openocd {
                command:
                    OpenOcdCommand::Watchpoint {
                        command:
                            OpenOcdWatchpointCommand::Hit {
                                command: OpenOcdWatchpointHitCommand::Plan(_),
                            },
                    },
            } => "openocd.watchpoint.hit.plan",
            Command::Openocd {
                command:
                    OpenOcdCommand::Watchpoint {
                        command:
                            OpenOcdWatchpointCommand::Hit {
                                command: OpenOcdWatchpointHitCommand::Test(_),
                            },
                    },
            } => "openocd.watchpoint.hit.test",
            Command::Openocd {
                command:
                    OpenOcdCommand::Gdb {
                        command: OpenOcdGdbCommand::Inspect(_),
                    },
            } => "openocd.gdb.inspect",
            Command::Openocd {
                command:
                    OpenOcdCommand::Gdb {
                        command: OpenOcdGdbCommand::Test(_),
                    },
            } => "openocd.gdb.test",
            Command::Openocd {
                command:
                    OpenOcdCommand::Reset {
                        command: OpenOcdResetCommand::Plan(_),
                    },
            } => "openocd.reset.plan",
            Command::Openocd {
                command:
                    OpenOcdCommand::Reset {
                        command: OpenOcdResetCommand::Test(_),
                    },
            } => "openocd.reset.test",
            Command::Openocd {
                command:
                    OpenOcdCommand::Resume {
                        command: OpenOcdResumeCommand::Plan(_),
                    },
            } => "openocd.resume.plan",
            Command::Openocd {
                command:
                    OpenOcdCommand::Resume {
                        command: OpenOcdResumeCommand::Test(_),
                    },
            } => "openocd.resume.test",
            Command::Openocd {
                command:
                    OpenOcdCommand::Stack {
                        command: OpenOcdStackCommand::Plan(selection),
                    },
            } if selection.elf.is_some() => "openocd.stack.annotated.plan",
            Command::Openocd {
                command:
                    OpenOcdCommand::Stack {
                        command: OpenOcdStackCommand::Plan(_),
                    },
            } => "openocd.stack.plan",
            Command::Openocd {
                command:
                    OpenOcdCommand::Stack {
                        command: OpenOcdStackCommand::Test(selection),
                    },
            } if selection.stack.elf.is_some() => "openocd.stack.annotated.test",
            Command::Openocd {
                command:
                    OpenOcdCommand::Stack {
                        command: OpenOcdStackCommand::Test(_),
                    },
            } => "openocd.stack.test",
            Command::Openocd {
                command:
                    OpenOcdCommand::Memory {
                        command: OpenOcdMemoryCommand::Plan(_),
                    },
            } => "openocd.memory.plan",
            Command::Openocd {
                command:
                    OpenOcdCommand::Memory {
                        command: OpenOcdMemoryCommand::Test(_),
                    },
            } => "openocd.memory.test",
            Command::Openocd {
                command:
                    OpenOcdCommand::Registers {
                        command: OpenOcdRegistersCommand::Plan(_),
                    },
            } => "openocd.registers.plan",
            Command::Openocd {
                command:
                    OpenOcdCommand::Registers {
                        command: OpenOcdRegistersCommand::Test(_),
                    },
            } => "openocd.registers.test",
            Command::Openocd {
                command:
                    OpenOcdCommand::Server {
                        command: OpenOcdServerCommand::Plan(_),
                    },
            } => "openocd.server.plan",
            Command::Openocd {
                command:
                    OpenOcdCommand::Server {
                        command: OpenOcdServerCommand::Test(_),
                    },
            } => "openocd.server.test",
            Command::Openocd {
                command:
                    OpenOcdCommand::Session {
                        command: OpenOcdSessionCommand::Plan(_),
                    },
            } => "openocd.session.plan",
            Command::Openocd {
                command:
                    OpenOcdCommand::Session {
                        command: OpenOcdSessionCommand::Test(_),
                    },
            } => "openocd.session.test",
            Command::Openocd {
                command:
                    OpenOcdCommand::Target {
                        command: OpenOcdTargetCommand::Plan(_),
                    },
            } => "openocd.target.plan",
            Command::Openocd {
                command:
                    OpenOcdCommand::Target {
                        command: OpenOcdTargetCommand::Test(_),
                    },
            } => "openocd.target.test",
        }
    }

    pub fn is_session_server(&self) -> bool {
        matches!(self.command, Command::Session { .. })
    }

    pub fn is_mcp_server(&self) -> bool {
        matches!(self.command, Command::Mcp { .. })
    }

    pub fn is_supervisor_server(&self) -> bool {
        matches!(self.command, Command::Supervisor { .. })
    }
}

pub fn serve_session_stdio(cli: &Cli) -> Result<()> {
    let Command::Session {
        command: SessionCommand::Serve(selection),
    } = &cli.command
    else {
        return Err(DebugError::new(
            crate::error::ErrorCode::ProtocolError,
            "requested command is not the session JSONL server",
            6,
            json!({"operation": cli.operation_name()}),
        ));
    };
    let options = session::SessionServerOptions::from_idle_timeout_ms(selection.idle_timeout_ms)?;

    match cli.backend {
        BackendArg::Replay => serve_session_backend(
            ReplayBackend::from_path(replay_fixture_path(cli)?)?,
            options,
        ),
        BackendArg::ProbeRs => {
            serve_session_backend(ProbeRsBackend::new(&selection.target)?, options)
        }
        BackendArg::Openocd => Err(unsupported_openocd("persistent_session")),
    }
}

pub fn serve_mcp_stdio(cli: &Cli) -> Result<()> {
    let Command::Mcp {
        command: McpCommand::Serve(selection),
    } = &cli.command
    else {
        return Err(DebugError::new(
            crate::error::ErrorCode::ProtocolError,
            "requested command is not the MCP stdio server",
            6,
            json!({"operation": cli.operation_name()}),
        ));
    };
    let options = session::SessionServerOptions::from_idle_timeout_ms(selection.idle_timeout_ms)?;

    match cli.backend {
        BackendArg::Replay => serve_mcp_backend(
            ReplayBackend::from_path(replay_fixture_path(cli)?)?,
            options,
        ),
        BackendArg::ProbeRs => {
            let target = selection.target.as_deref().ok_or_else(|| {
                DebugError::config(
                    "MCP probe-rs server requires an exact target",
                    json!({"required_argument": "--target"}),
                )
            })?;
            serve_mcp_backend(ProbeRsBackend::new(target)?, options)
        }
        BackendArg::Openocd => Err(unsupported_openocd("mcp_server")),
    }
}

fn serve_session_backend<B: DebugBackend>(
    backend: B,
    options: session::SessionServerOptions,
) -> Result<()> {
    let stdout = io::stdout();
    let stderr = io::stderr();
    session::serve_stdio_jsonl(backend, stdout.lock(), stderr.lock(), options)
}

fn serve_mcp_backend<B: DebugBackend>(
    backend: B,
    options: session::SessionServerOptions,
) -> Result<()> {
    let stdout = io::stdout();
    let stderr = io::stderr();
    session::serve_mcp_stdio(backend, stdout.lock(), stderr.lock(), options)
}

pub fn serve_supervisor_mcp(cli: &Cli) -> Result<()> {
    let Command::Supervisor {
        command: SupervisorCommand::Mcp(selection),
    } = &cli.command
    else {
        return Err(DebugError::new(
            crate::error::ErrorCode::ProtocolError,
            "requested command is not the MCP supervisor",
            6,
            json!({"operation": cli.operation_name()}),
        ));
    };
    session::SessionServerOptions::from_idle_timeout_ms(selection.idle_timeout_ms)?;
    let supervisor_options = supervisor::SupervisorOptions::from_values(
        selection.max_restarts,
        selection.restart_delay_ms,
    )?;
    if cli.backend == BackendArg::Openocd {
        return Err(unsupported_openocd("mcp_supervisor"));
    }
    if cli.backend == BackendArg::ProbeRs && selection.target.is_none() {
        return Err(DebugError::config(
            "MCP supervisor with probe-rs requires an exact target",
            json!({"required_argument": "--target"}),
        ));
    }
    match cli.backend {
        BackendArg::Replay => {
            ReplayBackend::from_path(replay_fixture_path(cli)?)?;
        }
        BackendArg::ProbeRs => {
            ProbeRsBackend::new(
                selection
                    .target
                    .as_deref()
                    .expect("probe-rs supervisor target was validated"),
            )?;
        }
        BackendArg::Openocd => unreachable!("OpenOCD supervisor was rejected above"),
    }

    let executable = std::env::current_exe().map_err(|error| {
        DebugError::io(
            "locate embedded-debugger executable for supervisor",
            None,
            &error,
        )
    })?;
    let mut child_args = vec![
        OsString::from("--backend"),
        OsString::from(match cli.backend {
            BackendArg::Replay => "replay",
            BackendArg::ProbeRs => "probe-rs",
            BackendArg::Openocd => "openocd",
        }),
    ];
    if let Some(fixture) = &cli.fixture {
        child_args.push(OsString::from("--fixture"));
        child_args.push(fixture.as_os_str().to_os_string());
    }
    child_args.extend([OsString::from("mcp"), OsString::from("serve")]);
    if let Some(target) = &selection.target {
        child_args.push(OsString::from("--target"));
        child_args.push(OsString::from(target));
    }
    child_args.push(OsString::from("--idle-timeout-ms"));
    child_args.push(OsString::from(selection.idle_timeout_ms.to_string()));

    supervisor::serve_mcp(&executable, &child_args, supervisor_options)
}

pub fn execute(cli: &Cli) -> Result<CommandResult> {
    match &cli.command {
        Command::Doctor => {
            let report = doctor::inspect();
            Ok(CommandResult::serializable(
                "doctor",
                &report,
                format!(
                    "Replay backend: ready\nprobe-rs guarded flash: ready (embedded library)\nprobe-rs CLI: {}\nOpenOCD host inspection: ready\nOpenOCD executable: {}",
                    availability(&report, "probe-rs-cli"),
                    availability(&report, "openocd")
                ),
            ))
        }
        Command::Openocd {
            command: OpenOcdCommand::Inspect(selection),
        } => {
            let report = openocd::inspect(&OpenOcdInspectOptions {
                executable: selection.executable.clone(),
                config_files: selection.config_files.clone(),
                search_dirs: selection.search_dirs.clone(),
                timeout_ms: selection.timeout_ms,
            })?;
            Ok(CommandResult::serializable(
                "openocd.inspect",
                &report,
                format!(
                    "OpenOCD host inspection complete\nExecutable: {}\nVersion: {}\nTop-level configs: {}\nTarget operations: disabled",
                    report.executable.resolved,
                    report.executable.version_line,
                    report.configuration.top_level_files.len(),
                ),
            ))
        }
        Command::Openocd {
            command:
                OpenOcdCommand::Gdb {
                    command: OpenOcdGdbCommand::Inspect(selection),
                },
        } => {
            let report = openocd::inspect_gdb(&GdbInspectOptions {
                executable: selection.executable.clone(),
                timeout_ms: selection.timeout_ms,
            })?;
            Ok(CommandResult::serializable(
                "openocd.gdb.inspect",
                &report,
                format!(
                    "GDB host inspection complete\nExecutable: {}\nVersion: {}\nMI process: disabled\nRemote target connection: disabled",
                    report.executable.resolved, report.executable.version_line,
                ),
            ))
        }
        Command::Openocd {
            command:
                OpenOcdCommand::Gdb {
                    command: OpenOcdGdbCommand::Test(selection),
                },
        } => {
            let report = openocd::test_gdb_mi(&gdb_mi_test_options(selection))?;
            Ok(CommandResult::serializable(
                "openocd.gdb.test",
                &report,
                format!(
                    "GDB/MI host lifecycle complete\nExecutable: {}\nInterpreter: {}\nVersion command: {}^{}\nExit command: {}^{}\nRemote target connection: disabled",
                    report.executable.resolved,
                    report.protocol.interpreter,
                    report.handshake.version_command.token,
                    report.handshake.version_command.result_class,
                    report.shutdown.token,
                    report.shutdown.result_class.as_deref().unwrap_or("missing"),
                ),
            ))
        }
        Command::Openocd {
            command:
                OpenOcdCommand::Server {
                    command: OpenOcdServerCommand::Plan(selection),
                },
        } => {
            let report = openocd::plan_server(&openocd_server_options(selection))?;
            Ok(CommandResult::serializable(
                "openocd.server.plan",
                &report,
                format!(
                    "OpenOCD managed server plan ready\nRisk: {}\nExecutable: {}\nTop-level configs: {}\nConfirm digest: {}",
                    report.risk,
                    report.executable.resolved,
                    report.configuration.top_level_files.len(),
                    report.confirm_digest,
                ),
            ))
        }
        Command::Openocd {
            command:
                OpenOcdCommand::Server {
                    command: OpenOcdServerCommand::Test(selection),
                },
        } => {
            let report = openocd::test_server(
                &openocd_server_options(&selection.server),
                &selection.confirm,
            )?;
            Ok(CommandResult::serializable(
                "openocd.server.test",
                &report,
                format!(
                    "OpenOCD managed lifecycle complete\nTcl: {}:{}\nGDB: {}:{}\nVersion: {}\nShutdown: graceful",
                    report.readiness.bind_address,
                    report.readiness.tcl_port,
                    report.readiness.bind_address,
                    report.readiness.gdb_port,
                    report.readiness.tcl_version_response,
                ),
            ))
        }
        Command::Openocd {
            command:
                OpenOcdCommand::Session {
                    command: OpenOcdSessionCommand::Plan(selection),
                },
        } => {
            let report = openocd::plan_session(&openocd_session_options(selection))?;
            Ok(CommandResult::serializable(
                "openocd.session.plan",
                &report,
                format!(
                    "OpenOCD + GDB session plan ready\nRisk: {}\nOpenOCD: {}\nGDB: {}\nInitial/final target state: running\nConfirm digest: {}",
                    report.risk,
                    report.openocd.executable.resolved,
                    report.gdb.executable.resolved,
                    report.confirm_digest,
                ),
            ))
        }
        Command::Openocd {
            command:
                OpenOcdCommand::Breakpoint {
                    command: OpenOcdBreakpointCommand::Plan(selection),
                },
        } => {
            let report = openocd::plan_hardware_breakpoint(&openocd_breakpoint_options(selection))?;
            Ok(CommandResult::serializable(
                "openocd.breakpoint.plan",
                &report,
                format!(
                    "OpenOCD temporary hardware-breakpoint plan ready\nRisk: {}\nTarget: {}\nAddress: {}\nBreakpoint execution requested: false\nAdditional Tcl resume after failure: false\nGDB detach/exit may resume target: true\nConfirm digest: {}",
                    report.risk,
                    report.target_state_policy.expected_current_target,
                    report.breakpoint_policy.requested_address,
                    report.confirm_digest,
                ),
            ))
        }
        Command::Openocd {
            command:
                OpenOcdCommand::Breakpoint {
                    command: OpenOcdBreakpointCommand::Test(selection),
                },
        } => {
            let report = openocd::test_hardware_breakpoint(
                &openocd_breakpoint_options(&selection.breakpoint),
                &selection.confirm,
            )?;
            Ok(CommandResult::serializable(
                "openocd.breakpoint.test",
                &report,
                format!(
                    "OpenOCD temporary hardware-breakpoint roundtrip complete\nTarget: {}\nAddress: {}\nInserted kind: {}\nBreakpoint table rows after delete: {}\nTarget state: {} -> {}\nShutdown: graceful",
                    report.target_restoration.initial.target_name,
                    report.exchange.roundtrip.inserted.address,
                    report.exchange.roundtrip.inserted.breakpoint_type,
                    report.exchange.roundtrip.table_after_delete.reported_rows,
                    report.target_restoration.initial.state,
                    report
                        .target_restoration
                        .final_observation
                        .as_ref()
                        .map_or("missing", |observation| observation.state.as_str()),
                ),
            ))
        }
        Command::Openocd {
            command:
                OpenOcdCommand::Watchpoint {
                    command: OpenOcdWatchpointCommand::Plan(selection),
                },
        } => {
            let report = openocd::plan_hardware_watchpoint(&openocd_watchpoint_options(selection))?;
            Ok(CommandResult::serializable(
                "openocd.watchpoint.plan",
                &report,
                format!(
                    "OpenOCD temporary hardware-watchpoint plan ready\nRisk: {}\nTarget: {}\nMode: {:?}\nRange: {} + {} bytes\nExpression evaluation may read declared RAM: true\nWatchpoint execution requested: false\nAdditional Tcl resume after failure: false\nGDB detach/exit may resume target: true\nConfirm digest: {}",
                    report.risk,
                    report.target_state_policy.expected_current_target,
                    report.watchpoint_policy.mode,
                    report.watchpoint_policy.requested_address,
                    report.watchpoint_policy.requested_length_bytes,
                    report.confirm_digest,
                ),
            ))
        }
        Command::Openocd {
            command:
                OpenOcdCommand::Watchpoint {
                    command: OpenOcdWatchpointCommand::Test(selection),
                },
        } => {
            let report = openocd::test_hardware_watchpoint(
                &openocd_watchpoint_options(&selection.watchpoint),
                &selection.confirm,
            )?;
            Ok(CommandResult::serializable(
                "openocd.watchpoint.test",
                &report,
                format!(
                    "OpenOCD temporary hardware-watchpoint roundtrip complete\nTarget: {}\nMode: {:?}\nExpression: {}\nInserted field: {}\nListed kind: {}\nBreakpoint table rows after delete: {}\nTarget state: {} -> {}\nShutdown: graceful",
                    report.target_restoration.initial.target_name,
                    report.watchpoint_policy.mode,
                    report.watchpoint_policy.expression,
                    report.exchange.roundtrip.inserted.result_field,
                    report
                        .exchange
                        .roundtrip
                        .table_before_delete
                        .watchpoint
                        .breakpoint_type,
                    report.exchange.roundtrip.table_after_delete.reported_rows,
                    report.target_restoration.initial.state,
                    report
                        .target_restoration
                        .final_observation
                        .as_ref()
                        .map_or("missing", |observation| observation.state.as_str()),
                ),
            ))
        }
        Command::Openocd {
            command:
                OpenOcdCommand::Watchpoint {
                    command:
                        OpenOcdWatchpointCommand::Hit {
                            command: OpenOcdWatchpointHitCommand::Plan(selection),
                        },
                },
        } => {
            let report =
                openocd::plan_hardware_watchpoint_hit(&openocd_watchpoint_hit_options(selection))?;
            Ok(CommandResult::serializable(
                "openocd.watchpoint.hit.plan",
                &report,
                format!(
                    "OpenOCD bounded hardware-watchpoint hit plan ready\nRisk: {}\nTarget: {}\nMode: {:?}\nWatch range: {} + {} bytes\nExpected PC: {}..{}\nHit timeout: {} ms\nExactly one continue: true\nAutomatic retry: false\nConfirm digest: {}",
                    report.risk,
                    report.target_state_policy.expected_current_target,
                    report.watchpoint_policy.mode,
                    report.watchpoint_policy.requested_address,
                    report.watchpoint_policy.requested_length_bytes,
                    report.hit_policy.expected_pc_start,
                    report.hit_policy.expected_pc_end_exclusive,
                    report.hit_policy.hit_timeout_ms,
                    report.confirm_digest,
                ),
            ))
        }
        Command::Openocd {
            command:
                OpenOcdCommand::Watchpoint {
                    command:
                        OpenOcdWatchpointCommand::Hit {
                            command: OpenOcdWatchpointHitCommand::Test(selection),
                        },
                },
        } => {
            let report = openocd::test_hardware_watchpoint_hit(
                &openocd_watchpoint_hit_options(&selection.hit),
                &selection.confirm,
            )?;
            Ok(CommandResult::serializable(
                "openocd.watchpoint.hit.test",
                &report,
                format!(
                    "OpenOCD bounded hardware-watchpoint hit complete\nTarget: {}\nMode: {:?}\nExpression: {}\nStop reason: {}\nFrame PC: {}\nPost-hit count: {}\nBreakpoint table rows after delete: {}\nTarget state: {} -> {}\nShutdown: graceful",
                    report.target_restoration.initial.target_name,
                    report.watchpoint_policy.mode,
                    report.watchpoint_policy.expression,
                    report.exchange.roundtrip.hit.stop_reason,
                    report.exchange.roundtrip.hit.frame_address,
                    report
                        .exchange
                        .roundtrip
                        .table_after_hit
                        .watchpoint
                        .hit_count,
                    report.exchange.roundtrip.table_after_delete.reported_rows,
                    report.target_restoration.initial.state,
                    report
                        .target_restoration
                        .final_observation
                        .as_ref()
                        .map_or("missing", |observation| observation.state.as_str()),
                ),
            ))
        }
        Command::Openocd {
            command:
                OpenOcdCommand::Reset {
                    command: OpenOcdResetCommand::Plan(selection),
                },
        } => {
            let report = openocd::plan_reset(&openocd_reset_options(selection))?;
            Ok(CommandResult::serializable(
                "openocd.reset.plan",
                &report,
                format!(
                    "OpenOCD reset-and-recovery plan ready\nRisk: {}\nOpenOCD: {}\nSelected target: {}\nReset scope: all defined targets\nSelected-target sequence: running -> reset halt -> halted -> running\nConfirm digest: {}",
                    report.risk,
                    report.openocd.executable.resolved,
                    report.reset_policy.expected_current_target,
                    report.confirm_digest,
                ),
            ))
        }
        Command::Openocd {
            command:
                OpenOcdCommand::Reset {
                    command: OpenOcdResetCommand::Test(selection),
                },
        } => {
            let report =
                openocd::test_reset(&openocd_reset_options(&selection.reset), &selection.confirm)?;
            Ok(CommandResult::serializable(
                "openocd.reset.test",
                &report,
                format!(
                    "OpenOCD reset roundtrip complete\nSelected target: {}\nStates: {} -> {} -> {}\nReset scope: all defined targets\nShutdown: graceful",
                    report.initial.target_name,
                    report.initial.state,
                    report
                        .reset
                        .observation
                        .as_ref()
                        .map_or("missing", |observation| observation.state.as_str()),
                    report
                        .recovery
                        .observation
                        .as_ref()
                        .map_or("missing", |observation| observation.state.as_str()),
                ),
            ))
        }
        Command::Openocd {
            command:
                OpenOcdCommand::Resume {
                    command: OpenOcdResumeCommand::Plan(selection),
                },
        } => {
            let report = openocd::plan_resume(&openocd_resume_options(selection))?;
            Ok(CommandResult::serializable(
                "openocd.resume.plan",
                &report,
                format!(
                    "OpenOCD selected-target resume-only plan ready\nRisk: {}\nOpenOCD: {}\nSelected target: {}\nAccepted initial state: halted or running\nMaximum resume commands: {}\nAutomatic retry: false\nConfirm digest: {}",
                    report.risk,
                    report.openocd.executable.resolved,
                    report.resume_policy.expected_current_target,
                    report.resume_policy.maximum_resume_command_count,
                    report.confirm_digest,
                ),
            ))
        }
        Command::Openocd {
            command:
                OpenOcdCommand::Resume {
                    command: OpenOcdResumeCommand::Test(selection),
                },
        } => {
            let report = openocd::test_resume(
                &openocd_resume_options(&selection.resume),
                &selection.confirm,
            )?;
            Ok(CommandResult::serializable(
                "openocd.resume.test",
                &report,
                format!(
                    "OpenOCD selected-target resume-only recovery complete\nSelected target: {}\nStates: {} -> {}\nResume commands: {}\nAutomatic retries: {}\nShutdown: graceful",
                    report.initial.target_name,
                    report.initial.state,
                    report.final_observation.state,
                    report.resume_command_count,
                    report.automatic_retry_count,
                ),
            ))
        }
        Command::Openocd {
            command:
                OpenOcdCommand::Stack {
                    command: OpenOcdStackCommand::Plan(selection),
                },
        } => {
            if selection.elf.is_some() {
                let report = openocd::plan_stack_elf(&openocd_stack_elf_options(selection))?;
                return Ok(CommandResult::serializable(
                    "openocd.stack.annotated.plan",
                    &report,
                    format!(
                        "OpenOCD ELF-annotated stack plan ready\nRisk: {}\nTarget: {}\nMaximum returned frames: {}\nELF SHA-256: {}\nRuntime firmware identity verified: false\nConfirm digest: {}",
                        report.risk,
                        report.stack.target_state_policy.expected_current_target,
                        report.stack.stack_policy.maximum_frames_requested,
                        report.elf.sha256,
                        report.confirm_digest,
                    ),
                ));
            }
            let report = openocd::plan_stack_snapshot(&openocd_stack_options(selection))?;
            Ok(CommandResult::serializable(
                "openocd.stack.plan",
                &report,
                format!(
                    "OpenOCD bounded stack snapshot plan ready\nRisk: {}\nTarget: {}\nMaximum returned frames: {}\nImplicit unwind-read addresses: unbound\nInitial/final target state: running\nConfirm digest: {}",
                    report.risk,
                    report.target_state_policy.expected_current_target,
                    report.stack_policy.maximum_frames_requested,
                    report.confirm_digest,
                ),
            ))
        }
        Command::Openocd {
            command:
                OpenOcdCommand::Stack {
                    command: OpenOcdStackCommand::Test(selection),
                },
        } => {
            if selection.stack.elf.is_some() {
                let report = openocd::test_stack_elf(
                    &openocd_stack_elf_options(&selection.stack),
                    &selection.confirm,
                )?;
                let top = report
                    .annotations
                    .frames
                    .first()
                    .and_then(|frame| frame.inline_annotations.first())
                    .and_then(|annotation| annotation.function.as_deref())
                    .unwrap_or("<unresolved>");
                return Ok(CommandResult::serializable(
                    "openocd.stack.annotated.test",
                    &report,
                    format!(
                        "OpenOCD ELF-annotated stack snapshot complete\nTarget: {}\nFrames: {}/{}\nResolved offline: {}\nTop annotation: {}\nRuntime firmware identity verified: false\nTarget state: {} -> {}\nShutdown: graceful",
                        report.stack.target_restoration.initial.target_name,
                        report.stack.exchange.snapshot.returned_frames,
                        report.stack.exchange.snapshot.maximum_frames,
                        report.annotations.resolved_frames,
                        top,
                        report.stack.target_restoration.initial.state,
                        report
                            .stack
                            .target_restoration
                            .final_observation
                            .as_ref()
                            .map_or("missing", |observation| observation.state.as_str()),
                    ),
                ));
            }
            let report = openocd::test_stack_snapshot(
                &openocd_stack_options(&selection.stack),
                &selection.confirm,
            )?;
            let top = report
                .exchange
                .snapshot
                .frames
                .first()
                .map(|frame| {
                    format!(
                        "{} {}",
                        frame.address,
                        frame.function.as_deref().unwrap_or("<unsymbolized>")
                    )
                })
                .unwrap_or_else(|| "missing".to_string());
            Ok(CommandResult::serializable(
                "openocd.stack.test",
                &report,
                format!(
                    "OpenOCD bounded stack snapshot complete\nTarget: {}\nFrames: {}/{}\nTop: {}\nAdditional GDB frames possible: {}\nTarget state: {} -> {}\nShutdown: graceful",
                    report.target_restoration.initial.target_name,
                    report.exchange.snapshot.returned_frames,
                    report.exchange.snapshot.maximum_frames,
                    top,
                    report.exchange.snapshot.additional_gdb_frames_possible,
                    report.target_restoration.initial.state,
                    report
                        .target_restoration
                        .final_observation
                        .as_ref()
                        .map_or("missing", |observation| observation.state.as_str()),
                ),
            ))
        }
        Command::Openocd {
            command:
                OpenOcdCommand::Memory {
                    command: OpenOcdMemoryCommand::Plan(selection),
                },
        } => {
            let report = openocd::plan_memory_snapshot(&openocd_memory_options(selection))?;
            Ok(CommandResult::serializable(
                "openocd.memory.plan",
                &report,
                format!(
                    "OpenOCD bounded memory snapshot plan ready\nRisk: {}\nTarget: {}\nRange: {} + {} byte(s)\nDeclared region: {:?} {} + {} byte(s)\nInitial/final target state: running\nConfirm digest: {}",
                    report.risk,
                    report.target_state_policy.expected_current_target,
                    report.memory_policy.requested_address,
                    report.memory_policy.requested_length_bytes,
                    report.memory_policy.declared_region.kind,
                    report.memory_policy.declared_region.start,
                    report.memory_policy.declared_region.length_bytes,
                    report.confirm_digest,
                ),
            ))
        }
        Command::Openocd {
            command:
                OpenOcdCommand::Memory {
                    command: OpenOcdMemoryCommand::Test(selection),
                },
        } => {
            let report = openocd::test_memory_snapshot(
                &openocd_memory_options(&selection.memory),
                &selection.confirm,
            )?;
            Ok(CommandResult::serializable(
                "openocd.memory.test",
                &report,
                format!(
                    "OpenOCD bounded memory snapshot complete\nTarget: {}\nRange: {} + {} byte(s)\nSHA-256: {}\nTarget state: {} -> {}\nShutdown: graceful",
                    report.target_restoration.initial.target_name,
                    report.exchange.snapshot.address,
                    report.exchange.snapshot.length_bytes,
                    report.exchange.snapshot.sha256,
                    report.target_restoration.initial.state,
                    report
                        .target_restoration
                        .final_observation
                        .as_ref()
                        .map_or("missing", |observation| observation.state.as_str()),
                ),
            ))
        }
        Command::Openocd {
            command:
                OpenOcdCommand::Registers {
                    command: OpenOcdRegistersCommand::Plan(selection),
                },
        } => {
            let report = openocd::plan_register_snapshot(&openocd_register_options(selection))?;
            Ok(CommandResult::serializable(
                "openocd.registers.plan",
                &report,
                format!(
                    "OpenOCD selected-register snapshot plan ready\nRisk: {}\nTarget: {}\nRegisters: {}\nInitial/final target state: running\nConfirm digest: {}",
                    report.risk,
                    report.target_state_policy.expected_current_target,
                    report.register_policy.requested_names.join(", "),
                    report.confirm_digest,
                ),
            ))
        }
        Command::Openocd {
            command:
                OpenOcdCommand::Registers {
                    command: OpenOcdRegistersCommand::Test(selection),
                },
        } => {
            let report = openocd::test_register_snapshot(
                &openocd_register_options(&selection.registers),
                &selection.confirm,
            )?;
            let values = report
                .exchange
                .values
                .iter()
                .map(|register| format!("{}={}", register.requested_name, register.value))
                .collect::<Vec<_>>()
                .join(", ");
            Ok(CommandResult::serializable(
                "openocd.registers.test",
                &report,
                format!(
                    "OpenOCD selected-register snapshot complete\nTarget: {}\nValues: {}\nTarget state: {} -> {}\nShutdown: graceful",
                    report.target_restoration.initial.target_name,
                    values,
                    report.target_restoration.initial.state,
                    report
                        .target_restoration
                        .final_observation
                        .as_ref()
                        .map_or("missing", |observation| observation.state.as_str()),
                ),
            ))
        }
        Command::Openocd {
            command:
                OpenOcdCommand::Target {
                    command: OpenOcdTargetCommand::Plan(selection),
                },
        } => {
            let report = openocd::plan_target(&openocd_target_options(selection))?;
            Ok(CommandResult::serializable(
                "openocd.target.plan",
                &report,
                format!(
                    "OpenOCD target state-roundtrip plan ready\nRisk: {}\nOpenOCD: {}\nTarget: {}\nState sequence: running -> halted -> running\nConfirm digest: {}",
                    report.risk,
                    report.openocd.executable.resolved,
                    report.target_policy.expected_current_target,
                    report.confirm_digest,
                ),
            ))
        }
        Command::Openocd {
            command:
                OpenOcdCommand::Target {
                    command: OpenOcdTargetCommand::Test(selection),
                },
        } => {
            let report = openocd::test_target(
                &openocd_target_options(&selection.target),
                &selection.confirm,
            )?;
            Ok(CommandResult::serializable(
                "openocd.target.test",
                &report,
                format!(
                    "OpenOCD target state roundtrip complete\nTarget: {}\nStates: {} -> {} -> {}\nShutdown: graceful",
                    report.initial.target_name,
                    report.initial.state,
                    report
                        .halt
                        .observation
                        .as_ref()
                        .map_or("missing", |observation| observation.state.as_str()),
                    report
                        .resume
                        .observation
                        .as_ref()
                        .map_or("missing", |observation| observation.state.as_str()),
                ),
            ))
        }
        Command::Openocd {
            command:
                OpenOcdCommand::Session {
                    command: OpenOcdSessionCommand::Test(selection),
                },
        } => {
            let report = openocd::test_session(
                &openocd_session_options(&selection.session),
                &selection.confirm,
            )?;
            Ok(CommandResult::serializable(
                "openocd.session.test",
                &report,
                format!(
                    "OpenOCD + GDB session complete\nEndpoint: {}\nConnect: {}^{}\nDetach: {}^{}\nTarget: {} -> {}",
                    report.exchange.endpoint,
                    report.exchange.connection.token,
                    report.exchange.connection.result_class,
                    report.exchange.detach.token,
                    report.exchange.detach.result_class,
                    report.target_restoration.initial.state,
                    report
                        .target_restoration
                        .final_observation
                        .as_ref()
                        .map_or("missing", |observation| observation.state.as_str()),
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
        Command::Snapshot {
            command: SnapshotCommand::ResetCapture(selection),
        } => capture_reset_snapshot(cli, selection),
        Command::Registers {
            command: RegisterCommand::Read(selection),
        } => read_registers(cli, selection),
        Command::Memory {
            command: MemoryCommand::Read(selection),
        } => read_memory(cli, selection),
        Command::Core { command } => control_core(cli, command),
        Command::Session { .. } => Err(DebugError::new(
            crate::error::ErrorCode::ProtocolError,
            "session serve is a streaming command and must own stdin/stdout",
            6,
            json!({"operation": "session.serve"}),
        )),
        Command::Mcp { .. } => Err(DebugError::new(
            crate::error::ErrorCode::ProtocolError,
            "MCP serve is a streaming command and must own stdin/stdout",
            6,
            json!({"operation": "mcp.serve"}),
        )),
        Command::Supervisor { .. } => Err(DebugError::new(
            crate::error::ErrorCode::ProtocolError,
            "MCP supervisor is a streaming command and must own stdin/stdout",
            6,
            json!({"operation": "supervisor.mcp"}),
        )),
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
    let plan = service.plan_flash_with_options(
        &selection.firmware,
        selection.probe.as_deref(),
        selection.target.as_deref(),
        &firmware_options(selection),
    )?;
    let human = format!(
        "Plan {}\nTarget: {}\nProbe: {}\nFirmware: {} source bytes, {} program bytes ({})\nWrite ranges: {}\nErase ranges: {}\nExecutable: {}\nRisk: {}\nConfirm: {}",
        plan.plan_id,
        plan.target.name,
        plan.probe.id,
        plan.firmware.size,
        plan.firmware.program_size,
        plan.firmware.sha256,
        describe_ranges(&plan.ranges),
        describe_ranges(&plan.erase_ranges),
        plan.execution.supported,
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
    let result = service.execute_flash_with_options(
        &arguments.selection.firmware,
        arguments.selection.probe.as_deref(),
        arguments.selection.target.as_deref(),
        &firmware_options(&arguments.selection),
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

fn firmware_options(selection: &FlashSelection) -> FirmwareInputOptions {
    FirmwareInputOptions {
        format: selection.format.map(Into::into),
        base_address: selection.base_address,
        flash_size: selection.flash_size,
        chip_revision: selection.chip_revision,
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

fn capture_reset_snapshot(cli: &Cli, selection: &SnapshotSelection) -> Result<CommandResult> {
    let report = match cli.backend {
        BackendArg::Replay => {
            let mut service =
                DebugService::new(ReplayBackend::from_path(replay_fixture_path(cli)?)?);
            service.capture_reset_snapshot(&selection.probe, &selection.target)?
        }
        BackendArg::ProbeRs => {
            let backend = ProbeRsBackend::new(&selection.target)?;
            let mut service = DebugService::new(backend);
            service.capture_reset_snapshot(&selection.probe, &selection.target)?
        }
        BackendArg::Openocd => return Err(unsupported_openocd("post_reset_snapshot")),
    };
    let core_lines = report
        .cores
        .iter()
        .map(|core| match &core.snapshot {
            Some(snapshot) => format!(
                "core {} ({}, {}): expected={:?}, captured={:?}, final={:?}, PC={}, SP={}",
                core.index,
                core.name,
                core.architecture,
                core.expected_final_state
                    .unwrap_or(crate::model::CoreState::Running),
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
        "Reset and observed {} described core(s), {} available on {}\n{}\nRisk: {}\nEffects: {}",
        report.cores.len(),
        available_cores,
        report.session.target.name,
        core_lines,
        report.risk,
        describe_debug_control_effects(&report.effects)
    );
    Ok(CommandResult::serializable(
        "snapshot.reset_capture",
        &report,
        human,
    ))
}

fn read_registers(cli: &Cli, selection: &RegisterReadSelection) -> Result<CommandResult> {
    let report = match cli.backend {
        BackendArg::Replay => {
            let mut service =
                DebugService::new(ReplayBackend::from_path(replay_fixture_path(cli)?)?);
            service.read_registers(
                &selection.probe,
                &selection.target,
                selection.core,
                &selection.names,
            )?
        }
        BackendArg::ProbeRs => {
            let backend = ProbeRsBackend::new(&selection.target)?;
            let mut service = DebugService::new(backend);
            service.read_registers(
                &selection.probe,
                &selection.target,
                selection.core,
                &selection.names,
            )?
        }
        BackendArg::Openocd => return Err(unsupported_openocd("register_read")),
    };
    let register_lines = report
        .core
        .registers
        .iter()
        .map(|register| {
            let aliases = if register.aliases.is_empty() {
                String::new()
            } else {
                format!(" ({})", register.aliases.join(", "))
            };
            format!(
                "{}{} [{}; {} bit] = {}",
                register.name, aliases, register.id, register.bits, register.value
            )
        })
        .collect::<Vec<_>>()
        .join("\n");
    let human = format!(
        "Read {} register(s) from core {} ({}, {}) on {}\noriginal={:?}, captured={:?}, restored={:?}\n{}\nRisk: {}\nEffects: {}",
        report.core.registers.len(),
        report.core.index,
        report.core.name,
        report.core.architecture,
        report.session.target.name,
        report.core.original_state,
        report.core.captured_state,
        report.core.state,
        register_lines,
        report.risk,
        describe_debug_control_effects(&report.effects)
    );
    Ok(CommandResult::serializable(
        "registers.read",
        &report,
        human,
    ))
}

fn read_memory(cli: &Cli, selection: &MemoryReadSelection) -> Result<CommandResult> {
    let report = match cli.backend {
        BackendArg::Replay => {
            let mut service =
                DebugService::new(ReplayBackend::from_path(replay_fixture_path(cli)?)?);
            service.read_memory(
                &selection.probe,
                &selection.target,
                selection.core,
                selection.address,
                selection.length,
            )?
        }
        BackendArg::ProbeRs => {
            let backend = ProbeRsBackend::new(&selection.target)?;
            let mut service = DebugService::new(backend);
            service.read_memory(
                &selection.probe,
                &selection.target,
                selection.core,
                selection.address,
                selection.length,
            )?
        }
        BackendArg::Openocd => return Err(unsupported_openocd("memory_read")),
    };
    let human = format!(
        "Read {} byte(s) from {} on core {} ({}, {})\nregion={:?} {} + {} bytes, alias={}\noriginal={:?}, captured={:?}, restored={:?}\nsha256={}\nhex={}\nRisk: {}\nEffects: {}",
        report.range.length,
        report.range.start,
        report.core.index,
        report.core.name,
        report.core.architecture,
        report.range.region.kind,
        report.range.region.start,
        report.range.region.length,
        report.range.region.is_alias,
        report.core.original_state,
        report.core.captured_state,
        report.core.state,
        report.sha256,
        report.data,
        report.risk,
        describe_debug_control_effects(&report.effects)
    );
    Ok(CommandResult::serializable("memory.read", &report, human))
}

fn control_core(cli: &Cli, command: &CoreCommand) -> Result<CommandResult> {
    let (action, selection) = match command {
        CoreCommand::Status(selection) => (CoreExecutionAction::Status, selection),
        CoreCommand::Halt(selection) => (CoreExecutionAction::Halt, selection),
        CoreCommand::Run(selection) => (CoreExecutionAction::Run, selection),
        CoreCommand::Continue(selection) => (CoreExecutionAction::Continue, selection),
        CoreCommand::ContinueUntilHalt(selection) => {
            return continue_until_halt(cli, selection);
        }
        CoreCommand::Step(selection) => (CoreExecutionAction::Step, selection),
    };
    let report = match cli.backend {
        BackendArg::Replay => {
            let mut service =
                DebugService::new(ReplayBackend::from_path(replay_fixture_path(cli)?)?);
            service.control_core(&selection.probe, &selection.target, selection.core, action)?
        }
        BackendArg::ProbeRs => {
            let backend = ProbeRsBackend::new(&selection.target)?;
            let mut service = DebugService::new(backend);
            service.control_core(&selection.probe, &selection.target, selection.core, action)?
        }
        BackendArg::Openocd => return Err(unsupported_openocd("core_control")),
    };
    let human = format!(
        "Core {} ({}, {}) {:?}\noriginal={:?}, final={:?}, changed={}, halt_reason={}\nRisk: {}\nEffects: {}",
        report.core.index,
        report.core.name,
        report.core.architecture,
        report.core.action,
        report.core.original_state,
        report.core.state,
        report.core.state_changed,
        report.core.halt_reason.as_deref().unwrap_or("none"),
        report.risk,
        describe_debug_control_effects(&report.effects)
    );
    let operation = match action {
        CoreExecutionAction::Status => "core.status",
        CoreExecutionAction::Halt => "core.halt",
        CoreExecutionAction::Run => "core.run",
        CoreExecutionAction::Continue => "core.continue",
        CoreExecutionAction::Step => "core.step",
    };
    Ok(CommandResult::serializable(operation, &report, human))
}

fn continue_until_halt(
    cli: &Cli,
    arguments: &CoreContinueUntilHaltSelection,
) -> Result<CommandResult> {
    let selection = &arguments.selection;
    let options = ContinueUntilHaltOptions {
        timeout_ms: arguments.timeout_ms,
        poll_interval_ms: arguments.poll_interval_ms,
    };
    let report = match cli.backend {
        BackendArg::Replay => {
            let mut service =
                DebugService::new(ReplayBackend::from_path(replay_fixture_path(cli)?)?);
            service.continue_until_halt(
                &selection.probe,
                &selection.target,
                selection.core,
                options,
            )?
        }
        BackendArg::ProbeRs => {
            let backend = ProbeRsBackend::new(&selection.target)?;
            let mut service = DebugService::new(backend);
            service.continue_until_halt(
                &selection.probe,
                &selection.target,
                selection.core,
                options,
            )?
        }
        BackendArg::Openocd => return Err(unsupported_openocd("continue_until_halt")),
    };
    let continuation = &report.wait.continuation;
    let human = format!(
        "Core {} ({}, {}) continue-until-halt\nimmediate={:?}, outcome={:?}, final={:?}, halt_reason={}\ntimeout={} ms, poll={} ms, elapsed={} ms, polls={}\nRisk: {}\nEffects: {}",
        continuation.index,
        continuation.name,
        continuation.architecture,
        continuation.state,
        report.wait.outcome,
        report.wait.state,
        report.wait.halt_reason.as_deref().unwrap_or("none"),
        report.wait.timeout_ms,
        report.wait.poll_interval_ms,
        report.wait.elapsed_ms,
        report.wait.poll_count,
        report.risk,
        describe_debug_control_effects(&report.effects)
    );
    Ok(CommandResult::serializable(
        "core.continue_until_halt",
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

fn parse_length(value: &str) -> std::result::Result<u64, String> {
    Address::parse(value)
        .map(|parsed| parsed.0)
        .map_err(|_| "length must be a decimal integer or a 0x-prefixed hexadecimal string".into())
}

fn openocd_server_options(selection: &OpenOcdServerSelection) -> OpenOcdServerOptions {
    OpenOcdServerOptions {
        executable: selection.executable.clone(),
        config_files: selection.config_files.clone(),
        search_dirs: selection.search_dirs.clone(),
        version_timeout_ms: selection.version_timeout_ms,
        startup_timeout_ms: selection.startup_timeout_ms,
        shutdown_timeout_ms: selection.shutdown_timeout_ms,
    }
}

fn gdb_mi_test_options(selection: &GdbMiTestSelection) -> GdbMiTestOptions {
    GdbMiTestOptions {
        executable: selection.executable.clone(),
        version_timeout_ms: selection.version_timeout_ms,
        startup_timeout_ms: selection.startup_timeout_ms,
        shutdown_timeout_ms: selection.shutdown_timeout_ms,
    }
}

fn openocd_session_options(selection: &OpenOcdSessionSelection) -> OpenOcdGdbSessionOptions {
    OpenOcdGdbSessionOptions {
        openocd: OpenOcdServerOptions {
            executable: selection.openocd_executable.clone(),
            config_files: selection.config_files.clone(),
            search_dirs: selection.search_dirs.clone(),
            version_timeout_ms: selection.openocd_version_timeout_ms,
            startup_timeout_ms: selection.openocd_startup_timeout_ms,
            shutdown_timeout_ms: selection.openocd_shutdown_timeout_ms,
        },
        gdb_executable: selection.gdb_executable.clone(),
        gdb_xtensa_config: selection.gdb_xtensa_config.clone(),
        expected_target: selection.expected_target.clone(),
        gdb_version_timeout_ms: selection.gdb_version_timeout_ms,
        gdb_startup_timeout_ms: selection.gdb_startup_timeout_ms,
        gdb_command_timeout_ms: selection.gdb_command_timeout_ms,
        gdb_shutdown_timeout_ms: selection.gdb_shutdown_timeout_ms,
        target_state_timeout_ms: selection.target_state_timeout_ms,
    }
}

fn openocd_register_options(
    selection: &OpenOcdRegistersSelection,
) -> OpenOcdRegisterSnapshotOptions {
    OpenOcdRegisterSnapshotOptions {
        session: openocd_session_options(&selection.session),
        registers: selection.registers.clone(),
    }
}

fn openocd_breakpoint_options(
    selection: &OpenOcdBreakpointSelection,
) -> OpenOcdHardwareBreakpointOptions {
    OpenOcdHardwareBreakpointOptions {
        session: openocd_session_options(&selection.session),
        address: selection.address,
    }
}

fn openocd_watchpoint_options(
    selection: &OpenOcdWatchpointSelection,
) -> OpenOcdHardwareWatchpointOptions {
    OpenOcdHardwareWatchpointOptions {
        session: openocd_session_options(&selection.session),
        address: selection.address,
        length_bytes: selection.length,
        region_start: selection.region_start,
        region_length_bytes: selection.region_length,
        region_kind: selection.region_kind.into(),
        mode: selection.mode.into(),
    }
}

fn openocd_watchpoint_hit_options(
    selection: &OpenOcdWatchpointHitSelection,
) -> OpenOcdHardwareWatchpointHitOptions {
    OpenOcdHardwareWatchpointHitOptions {
        watchpoint: openocd_watchpoint_options(&selection.watchpoint),
        expected_pc_start: selection.expected_pc_start,
        expected_pc_length_bytes: selection.expected_pc_length,
        hit_timeout_ms: selection.hit_timeout_ms,
    }
}

fn openocd_stack_options(selection: &OpenOcdStackSelection) -> OpenOcdStackSnapshotOptions {
    OpenOcdStackSnapshotOptions {
        session: openocd_session_options(&selection.session),
        maximum_frames: selection.max_frames,
    }
}

fn openocd_stack_elf_options(selection: &OpenOcdStackSelection) -> OpenOcdStackElfOptions {
    OpenOcdStackElfOptions {
        stack: openocd_stack_options(selection),
        elf: selection
            .elf
            .clone()
            .expect("ELF options are constructed only when --elf is present"),
    }
}

fn openocd_memory_options(selection: &OpenOcdMemorySelection) -> OpenOcdMemorySnapshotOptions {
    OpenOcdMemorySnapshotOptions {
        session: openocd_session_options(&selection.session),
        address: selection.address,
        length_bytes: selection.length,
        region_start: selection.region_start,
        region_length_bytes: selection.region_length,
        region_kind: selection.region_kind.into(),
    }
}

fn openocd_reset_options(selection: &OpenOcdResetSelection) -> openocd::OpenOcdResetOptions {
    openocd::OpenOcdResetOptions {
        openocd: openocd_server_options(&selection.server),
        expected_target: selection.expected_target.clone(),
        target_state_timeout_ms: selection.target_state_timeout_ms,
    }
}

fn openocd_resume_options(selection: &OpenOcdResumeSelection) -> OpenOcdResumeOptions {
    OpenOcdResumeOptions {
        openocd: openocd_server_options(&selection.server),
        expected_target: selection.expected_target.clone(),
        target_state_timeout_ms: selection.target_state_timeout_ms,
    }
}

fn openocd_target_options(selection: &OpenOcdTargetSelection) -> OpenOcdTargetOptions {
    OpenOcdTargetOptions {
        openocd: openocd_server_options(&selection.server),
        expected_target: selection.expected_target.clone(),
        target_state_timeout_ms: selection.target_state_timeout_ms,
    }
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
        "not found"
    }
}
