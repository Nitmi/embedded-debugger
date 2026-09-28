//! A bounded flash authorization that exists only for one executor process.

use std::{
    fs::{self, OpenOptions},
    io::{self, BufRead, Read, Write},
    path::{Path, PathBuf},
    time::{Duration, Instant},
};

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::json;
use sha2::{Digest, Sha256};
use uuid::Uuid;

use crate::{
    backend::DebugBackend,
    envelope::{ErrorEnvelope, SuccessEnvelope},
    error::{DebugError, ErrorCode, Result},
    firmware::{FirmwareFormat, FirmwareInputOptions},
    model::{FlashExecution, FlashPlan, FlashPolicy, FlashRange},
    service::{ConfirmedFlashOptions, DebugService},
};

const SCOPE_SCHEMA: &str = "embedded-debugger.flash-session.v1";
const MAX_SCOPE_BYTES: u64 = 16 * 1024;
const MAX_REQUEST_BYTES: u64 = 8 * 1024;
const MAX_FLASHES: u32 = 100;
const MAX_SECONDS: u64 = 2 * 60 * 60;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FlashSessionScope {
    pub schema_version: String,
    pub nonce: Uuid,
    pub executor_sha256: String,
    pub scope_path: PathBuf,
    pub created_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
    pub backend: String,
    pub probe: String,
    pub target: String,
    pub firmware_directory: PathBuf,
    pub firmware_format: String,
    pub base_address: Option<crate::model::Address>,
    pub flash_size: Option<u64>,
    pub chip_revision: Option<u16>,
    pub write_window: FlashRange,
    pub erase_window: FlashRange,
    pub max_flashes: u32,
    pub duration_seconds: u64,
}

#[derive(Debug, Serialize)]
pub struct FlashSessionPlan {
    pub scope: FlashSessionScope,
    pub confirm_digest: String,
    pub hardware_access: bool,
}

pub struct ScopeInput<'a> {
    pub backend: &'a str,
    pub probe: &'a str,
    pub target: &'a str,
    pub firmware_directory: &'a Path,
    pub firmware_format: &'a str,
    pub base_address: Option<crate::model::Address>,
    pub flash_size: Option<u64>,
    pub chip_revision: Option<u16>,
    pub write_window: FlashRange,
    pub erase_window: FlashRange,
    pub max_flashes: u32,
    pub duration_seconds: u64,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
#[serde(tag = "operation", rename_all = "snake_case")]
enum Request {
    Flash {
        firmware: PathBuf,
        evidence: PathBuf,
    },
    Close,
}

pub fn plan(output: &Path, input: ScopeInput<'_>) -> Result<FlashSessionPlan> {
    if input.duration_seconds == 0 || input.duration_seconds > MAX_SECONDS {
        return Err(DebugError::config(
            "flash session duration is out of bounds",
            json!({"maximum_seconds": MAX_SECONDS}),
        ));
    }
    let parent = output
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .ok_or_else(|| {
            DebugError::config("session plan needs an explicit output directory", json!({}))
        })?
        .canonicalize()
        .map_err(|error| {
            DebugError::io("resolve session plan directory", output.to_str(), &error)
        })?;
    let filename = output
        .file_name()
        .ok_or_else(|| DebugError::config("session plan needs a filename", json!({})))?;
    let scope_path = parent.join(filename);
    let firmware_directory = input.firmware_directory.canonicalize().map_err(|error| {
        DebugError::io(
            "resolve firmware directory",
            input.firmware_directory.to_str(),
            &error,
        )
    })?;
    let now = Utc::now();
    let scope = FlashSessionScope {
        schema_version: SCOPE_SCHEMA.to_string(),
        nonce: Uuid::new_v4(),
        executor_sha256: current_executable_sha256()?,
        scope_path: scope_path.clone(),
        created_at: now,
        expires_at: now + chrono::Duration::seconds(input.duration_seconds as i64),
        backend: input.backend.to_string(),
        probe: input.probe.to_string(),
        target: input.target.to_string(),
        firmware_directory,
        firmware_format: input.firmware_format.to_string(),
        base_address: input.base_address,
        flash_size: input.flash_size,
        chip_revision: input.chip_revision,
        write_window: input.write_window,
        erase_window: input.erase_window,
        max_flashes: input.max_flashes,
        duration_seconds: input.duration_seconds,
    };
    validate(&scope)?;
    let result = FlashSessionPlan {
        confirm_digest: digest(&scope),
        scope,
        hardware_access: false,
    };
    let mut bytes = serde_json::to_vec_pretty(&result.scope).expect("session scope serializes");
    bytes.push(b'\n');
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&scope_path)
        .map_err(|error| {
            if error.kind() == io::ErrorKind::AlreadyExists {
                DebugError::output_exists(&output.display().to_string())
            } else {
                DebugError::io("create flash session plan", output.to_str(), &error)
            }
        })?;
    file.write_all(&bytes)
        .and_then(|()| file.sync_all())
        .map_err(|error| DebugError::io("write flash session plan", output.to_str(), &error))?;
    Ok(result)
}

pub fn inspect(path: &Path) -> Result<FlashSessionPlan> {
    let canonical_path = path
        .canonicalize()
        .map_err(|error| DebugError::io("resolve flash session plan", path.to_str(), &error))?;
    let file = fs::File::open(path)
        .map_err(|error| DebugError::io("open flash session plan", path.to_str(), &error))?;
    if file
        .metadata()
        .map_err(|error| DebugError::io("stat flash session plan", path.to_str(), &error))?
        .len()
        > MAX_SCOPE_BYTES
    {
        return Err(DebugError::config(
            "flash session plan is too large",
            json!({"path": path}),
        ));
    }
    let mut bytes = Vec::new();
    file.take(MAX_SCOPE_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(|error| DebugError::io("read flash session plan", path.to_str(), &error))?;
    let scope: FlashSessionScope = serde_json::from_slice(&bytes).map_err(|error| {
        DebugError::config(
            "invalid flash session plan",
            json!({"path": path, "error": error.to_string()}),
        )
    })?;
    validate(&scope)?;
    if canonical_path != scope.scope_path {
        return Err(DebugError::config(
            "flash session plan was moved from its approved path",
            json!({"expected": scope.scope_path, "actual": canonical_path}),
        ));
    }
    Ok(FlashSessionPlan {
        confirm_digest: digest(&scope),
        scope,
        hardware_access: false,
    })
}

pub fn serve<B: DebugBackend>(
    mut service: DebugService<B>,
    plan: FlashSessionPlan,
    confirmation: &str,
    mut input: impl BufRead,
    mut output: impl Write,
) -> Result<()> {
    validate(&plan.scope)?;
    if plan.confirm_digest != digest(&plan.scope) || plan.confirm_digest != confirmation {
        return Err(DebugError::confirmation(&plan.confirm_digest, confirmation));
    }
    if plan.scope.backend != service.backend_name() {
        return Err(DebugError::config(
            "session backend differs from selected backend",
            json!({}),
        ));
    }
    if plan.scope.executor_sha256 != current_executable_sha256()? {
        return Err(denied(
            "flash session executor binary differs from the approved binary",
        ));
    }
    if Utc::now() >= plan.scope.expires_at {
        return Err(DebugError::new(
            ErrorCode::PermissionDenied,
            "flash session approval expired",
            8,
            json!({}),
        ));
    }
    let _lease = SessionLease::acquire(&plan.scope.scope_path)?;
    let started = Instant::now();
    let mut remaining = plan.scope.max_flashes;
    send(
        &mut output,
        &SuccessEnvelope::new(
            "flash.session.ready",
            json!({
                "confirm_digest": plan.confirm_digest,
                "remaining": remaining,
                "expires_at": plan.scope.expires_at,
                "hardware_access": false,
            }),
        ),
    )?;
    loop {
        if remaining == 0
            || started.elapsed() >= Duration::from_secs(plan.scope.duration_seconds)
            || Utc::now() >= plan.scope.expires_at
        {
            return Ok(());
        }
        let mut line = Vec::new();
        let count = input
            .by_ref()
            .take(MAX_REQUEST_BYTES + 1)
            .read_until(b'\n', &mut line)
            .map_err(|error| DebugError::io("read flash session request", None, &error))?;
        if count == 0 {
            return Ok(());
        }
        if started.elapsed() >= Duration::from_secs(plan.scope.duration_seconds)
            || Utc::now() >= plan.scope.expires_at
        {
            return fail(
                &mut output,
                denied("flash session expired while awaiting a request"),
            );
        }
        if count as u64 > MAX_REQUEST_BYTES || !line.ends_with(b"\n") {
            return fail(
                &mut output,
                DebugError::config(
                    "flash session request is too large or incomplete",
                    json!({}),
                ),
            );
        }
        let request: Request = match serde_json::from_slice(&line) {
            Ok(request) => request,
            Err(error) => {
                return fail(
                    &mut output,
                    DebugError::config(
                        "invalid flash session request",
                        json!({"error": error.to_string()}),
                    ),
                );
            }
        };
        match request {
            Request::Close => {
                send(
                    &mut output,
                    &SuccessEnvelope::new("flash.session.close", json!({"remaining": remaining})),
                )?;
                return Ok(());
            }
            Request::Flash { firmware, evidence } => {
                // Consume the slot before any possible target mutation. No state
                // survives process exit, and any error stops this executor.
                remaining -= 1;
                match flash(&mut service, &plan.scope, &firmware, &evidence) {
                    Ok(execution) => {
                        send(
                            &mut output,
                            &SuccessEnvelope::new(
                                "flash.session.flash",
                                json!({
                                    "remaining": remaining,
                                    "execution": execution,
                                }),
                            ),
                        )?;
                    }
                    Err(error) => return fail(&mut output, error),
                }
            }
        }
    }
}

fn flash<B: DebugBackend>(
    service: &mut DebugService<B>,
    scope: &FlashSessionScope,
    firmware: &Path,
    evidence: &Path,
) -> Result<FlashExecution> {
    if evidence.exists() {
        return Err(DebugError::output_exists(&evidence.display().to_string()));
    }
    let firmware = firmware
        .canonicalize()
        .map_err(|error| DebugError::io("resolve session firmware", firmware.to_str(), &error))?;
    if !firmware.is_file() || !firmware.starts_with(&scope.firmware_directory) {
        return Err(denied("firmware is outside the approved build directory"));
    }
    let options = FirmwareInputOptions {
        format: Some(match scope.firmware_format.as_str() {
            "bin" => FirmwareFormat::Bin,
            "hex" => FirmwareFormat::IntelHex,
            "idf" => FirmwareFormat::EspIdf,
            _ => return Err(denied("firmware format is not approved")),
        }),
        base_address: scope.base_address,
        flash_size: scope.flash_size,
        chip_revision: scope.chip_revision,
    };
    let policy = FlashPolicy::default();
    let plan = service.plan_flash_with_policy(
        firmware.as_path(),
        Some(&scope.probe),
        Some(&scope.target),
        &options,
        &policy,
    )?;
    check_plan(scope, &plan)?;
    let execution = service.execute_flash_with_policy(
        firmware.as_path(),
        Some(&scope.probe),
        Some(&scope.target),
        ConfirmedFlashOptions {
            firmware: &options,
            policy: &policy,
            confirm_digest: &plan.confirm_digest,
            evidence_path: evidence,
        },
    )?;
    if !execution.flash.verified || !execution.evidence.path.eq(&evidence.display().to_string()) {
        return Err(denied("flash evidence or verification is incomplete"));
    }
    Ok(execution)
}

fn check_plan(scope: &FlashSessionScope, plan: &FlashPlan) -> Result<()> {
    if plan.backend != scope.backend
        || plan.probe.id != scope.probe
        || plan.target.name != scope.target
        || plan.firmware.format != scope.firmware_format
        || !plan.execution.supported
        || plan.policy != FlashPolicy::default()
        || plan.ranges.is_empty()
        || plan.erase_ranges.is_empty()
        || plan.firmware.segments.is_empty()
        || (scope.target == "nRF52840_xxAA"
            && (!contains(
                &FlashRange {
                    start: crate::model::Address(0),
                    length: 0x10_0000,
                },
                &scope.write_window,
            ) || !contains(
                &FlashRange {
                    start: crate::model::Address(0),
                    length: 0x10_0000,
                },
                &scope.erase_window,
            )))
        || plan.firmware.segments.iter().any(|segment| {
            !matches!(
                segment.kind.as_str(),
                "application" | "data" | "bootloader" | "partition_table"
            ) || !contains(
                &scope.write_window,
                &FlashRange {
                    start: segment.start,
                    length: segment.length,
                },
            )
        })
        || !plan
            .ranges
            .iter()
            .all(|range| contains(&scope.write_window, range))
        || !plan
            .erase_ranges
            .iter()
            .all(|range| contains(&scope.erase_window, range))
    {
        return Err(denied(
            "current flash plan is outside the approved code-Flash scope",
        ));
    }
    Ok(())
}

fn validate(scope: &FlashSessionScope) -> Result<()> {
    if scope.schema_version != SCOPE_SCHEMA
        || scope.probe.trim().is_empty()
        || scope.target.trim().is_empty()
        || !matches!(scope.backend.as_str(), "probe-rs" | "replay")
        || !matches!(scope.firmware_format.as_str(), "bin" | "hex" | "idf")
        || scope.max_flashes == 0
        || scope.max_flashes > MAX_FLASHES
        || scope.duration_seconds == 0
        || scope.duration_seconds > MAX_SECONDS
        || scope.created_at >= scope.expires_at
        || (scope.expires_at - scope.created_at).num_seconds() != scope.duration_seconds as i64
        || !scope.firmware_directory.is_absolute()
        || !scope.firmware_directory.is_dir()
        || !scope.scope_path.is_absolute()
        || scope.executor_sha256.len() != 64
        || !scope
            .executor_sha256
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit())
        || (scope.firmware_format == "bin" && scope.base_address.is_none())
        || (scope.firmware_format != "bin" && scope.base_address.is_some())
        || (scope.firmware_format == "idf" && scope.flash_size.is_none())
        || (scope.firmware_format == "hex" && scope.target != "nRF52840_xxAA")
        || (scope.target == "nRF52840_xxAA"
            && (!contains(
                &FlashRange {
                    start: crate::model::Address(0),
                    length: 0x10_0000,
                },
                &scope.write_window,
            ) || !contains(
                &FlashRange {
                    start: crate::model::Address(0),
                    length: 0x10_0000,
                },
                &scope.erase_window,
            )))
        || (scope.firmware_format == "idf" && scope.target != "esp32s3")
        || (scope.firmware_format == "idf"
            && scope.flash_size.is_some_and(|size| {
                let physical_flash = FlashRange {
                    start: crate::model::Address(0),
                    length: size,
                };
                !contains(&physical_flash, &scope.write_window)
                    || !contains(&physical_flash, &scope.erase_window)
            }))
        || (scope.firmware_format != "idf"
            && (scope.flash_size.is_some() || scope.chip_revision.is_some()))
    {
        return Err(DebugError::config(
            "flash session scope is invalid",
            json!({}),
        ));
    }
    valid_window(&scope.write_window)?;
    valid_window(&scope.erase_window)?;
    if !contains(&scope.erase_window, &scope.write_window) {
        return Err(DebugError::config(
            "erase window must contain write window",
            json!({}),
        ));
    }
    Ok(())
}

fn valid_window(range: &FlashRange) -> Result<()> {
    if range.length == 0 || range.start.0.checked_add(range.length).is_none() {
        return Err(DebugError::config(
            "flash session window must be finite and nonempty",
            json!({"range": range}),
        ));
    }
    Ok(())
}

fn contains(outer: &FlashRange, inner: &FlashRange) -> bool {
    outer.start.0 <= inner.start.0
        && inner.length > 0
        && inner
            .start
            .0
            .checked_add(inner.length)
            .is_some_and(|end| end <= outer.start.0 + outer.length)
}

fn digest(scope: &FlashSessionScope) -> String {
    crate::service::sha256_bytes(&serde_json::to_vec(scope).expect("scope serializes"))
}

fn current_executable_sha256() -> Result<String> {
    let executable = std::env::current_exe()
        .map_err(|error| DebugError::io("resolve session executor", None, &error))?;
    let mut file = fs::File::open(&executable)
        .map_err(|error| DebugError::io("open session executor", executable.to_str(), &error))?;
    let mut hasher = Sha256::new();
    let mut buffer = [0_u8; 64 * 1024];
    loop {
        let count = file.read(&mut buffer).map_err(|error| {
            DebugError::io("hash session executor", executable.to_str(), &error)
        })?;
        if count == 0 {
            break;
        }
        hasher.update(&buffer[..count]);
    }
    Ok(hex::encode(hasher.finalize()))
}

fn denied(message: &str) -> DebugError {
    DebugError::new(ErrorCode::PermissionDenied, message, 8, json!({}))
}

fn send(output: &mut impl Write, value: &impl Serialize) -> Result<()> {
    serde_json::to_writer(&mut *output, value).expect("session envelope serializes");
    output
        .write_all(b"\n")
        .and_then(|()| output.flush())
        .map_err(|error| DebugError::io("write flash session response", None, &error))
}

fn fail(output: &mut impl Write, error: DebugError) -> Result<()> {
    send(output, &ErrorEnvelope::new("flash.session.flash", &error))?;
    Err(error)
}

pub fn serve_stdio<B: DebugBackend>(
    service: DebugService<B>,
    plan: FlashSessionPlan,
    confirmation: &str,
) -> Result<()> {
    let stdin = io::stdin();
    let stdout = io::stdout();
    serve(service, plan, confirmation, stdin.lock(), stdout.lock())
}

struct SessionLease {
    file: fs::File,
}

impl SessionLease {
    fn acquire(scope_path: &Path) -> Result<Self> {
        let mut name = scope_path.as_os_str().to_os_string();
        name.push(".active");
        let path = PathBuf::from(name);
        let file = OpenOptions::new().write(true).create_new(true).open(&path)
            .map_err(|error| {
                if error.kind() == io::ErrorKind::AlreadyExists {
                    denied("flash session is active or ended unexpectedly; create and approve a new plan")
                } else {
                    DebugError::io("acquire flash session lease", path.to_str(), &error)
                }
            })?;
        Ok(Self { file })
    }
}

impl Drop for SessionLease {
    fn drop(&mut self) {
        let _ = self.file.sync_all();
        // The sidecar is deliberately retained. Restarting the same approved
        // plan must never restore its original use count.
    }
}

#[cfg(test)]
mod tests {
    use std::{io::Cursor, path::Path};

    use serde_json::{Value, json};
    use tempfile::tempdir;

    use crate::{
        backend::replay::ReplayBackend,
        model::{Address, FlashRange},
        service::DebugService,
    };

    use super::{ScopeInput, digest, inspect, plan, serve, validate};

    const PROBE: &str = "replay:stlink-v3:0039002A3432510433343034";
    const TARGET: &str = "STM32G431CBTx";

    fn scope<'a>(build: &'a Path) -> ScopeInput<'a> {
        ScopeInput {
            backend: "replay",
            probe: PROBE,
            target: TARGET,
            firmware_directory: build,
            firmware_format: "bin",
            base_address: Some(Address(0x0800_0000)),
            flash_size: None,
            chip_revision: None,
            write_window: FlashRange {
                start: Address(0x0800_0000),
                length: 64,
            },
            erase_window: FlashRange {
                start: Address(0x0800_0000),
                length: 2048,
            },
            max_flashes: 2,
            duration_seconds: 120,
        }
    }

    fn backend() -> DebugService<ReplayBackend> {
        let fixture = Path::new(env!("CARGO_MANIFEST_DIR")).join("examples/replay/stm32g4.json");
        DebugService::new(ReplayBackend::from_path(&fixture).unwrap())
    }

    fn responses(bytes: &[u8]) -> Vec<Value> {
        String::from_utf8(bytes.to_vec())
            .unwrap()
            .lines()
            .map(|line| serde_json::from_str(line).unwrap())
            .collect()
    }

    #[test]
    fn two_different_builds_use_one_approved_process() {
        let directory = tempdir().unwrap();
        let build = directory.path().join("build");
        std::fs::create_dir(&build).unwrap();
        let first = build.join("first.bin");
        let second = build.join("second.bin");
        std::fs::write(&first, b"firmware first").unwrap();
        std::fs::write(&second, b"firmware second").unwrap();
        let scope_path = directory.path().join("scope.json");
        let approved = plan(&scope_path, scope(&build)).unwrap();
        assert!(!approved.hardware_access);
        assert_eq!(
            inspect(&scope_path).unwrap().confirm_digest,
            approved.confirm_digest
        );
        let evidence1 = directory.path().join("first.evidence.json");
        let evidence2 = directory.path().join("second.evidence.json");
        let input = format!(
            "{}\n{}\n{}\n",
            json!({"operation":"flash","firmware":first,"evidence":evidence1}),
            json!({"operation":"flash","firmware":second,"evidence":evidence2}),
            json!({"operation":"close"}),
        );
        let mut output = Vec::new();
        serve(
            backend(),
            approved,
            &inspect(&scope_path).unwrap().confirm_digest,
            Cursor::new(input),
            &mut output,
        )
        .unwrap();
        let messages = responses(&output);
        assert_eq!(messages.len(), 3);
        assert_eq!(messages[0]["operation"], "flash.session.ready");
        assert_eq!(messages[1]["data"]["remaining"], 1);
        assert_eq!(messages[2]["data"]["remaining"], 0);
        assert_eq!(messages[1]["data"]["execution"]["flash"]["verified"], true);
        assert_ne!(
            messages[1]["data"]["execution"]["plan"]["confirm_digest"],
            messages[2]["data"]["execution"]["plan"]["confirm_digest"]
        );
        assert!(evidence1.exists());
        assert!(evidence2.exists());
        assert!(scope_path.with_file_name("scope.json.active").exists());
    }

    #[test]
    fn out_of_window_plan_stops_and_cannot_restart() {
        let directory = tempdir().unwrap();
        let build = directory.path().join("build");
        std::fs::create_dir(&build).unwrap();
        let firmware = build.join("too-large.bin");
        std::fs::write(&firmware, [0x42; 100]).unwrap();
        let scope_path = directory.path().join("scope.json");
        let approved = plan(&scope_path, scope(&build)).unwrap();
        let evidence = directory.path().join("rejected.evidence.json");
        let input = format!(
            "{}\n",
            json!({"operation":"flash","firmware":firmware,"evidence":evidence})
        );
        let mut output = Vec::new();
        assert!(
            serve(
                backend(),
                approved,
                &inspect(&scope_path).unwrap().confirm_digest,
                Cursor::new(input),
                &mut output
            )
            .is_err()
        );
        let messages = responses(&output);
        assert_eq!(messages.len(), 2);
        assert_eq!(messages[1]["error"]["code"], "PERMISSION_DENIED");
        assert!(!evidence.exists());
        let mut restarted_output = Vec::new();
        assert!(
            serve(
                backend(),
                inspect(&scope_path).unwrap(),
                &inspect(&scope_path).unwrap().confirm_digest,
                Cursor::new(Vec::<u8>::new()),
                &mut restarted_output
            )
            .is_err()
        );
        assert!(restarted_output.is_empty());
    }

    #[test]
    fn copied_or_changed_scope_cannot_use_old_approval() {
        let directory = tempdir().unwrap();
        let build = directory.path().join("build");
        std::fs::create_dir(&build).unwrap();
        let scope_path = directory.path().join("scope.json");
        let approved = plan(&scope_path, scope(&build)).unwrap();
        let copied = directory.path().join("copy.json");
        std::fs::copy(&scope_path, &copied).unwrap();
        assert!(inspect(&copied).is_err());
        let mut scope_json: Value =
            serde_json::from_slice(&std::fs::read(&scope_path).unwrap()).unwrap();
        scope_json["write_window"]["length"] = json!(128);
        std::fs::write(&scope_path, serde_json::to_vec(&scope_json).unwrap()).unwrap();
        let changed = inspect(&scope_path).unwrap();
        assert_ne!(changed.confirm_digest, approved.confirm_digest);
        let mut output = Vec::new();
        assert!(
            serve(
                backend(),
                changed,
                &approved.confirm_digest,
                Cursor::new(Vec::<u8>::new()),
                &mut output
            )
            .is_err()
        );
        assert!(output.is_empty());
    }

    #[test]
    fn different_executor_binary_cannot_activate_approval() {
        let directory = tempdir().unwrap();
        let build = directory.path().join("build");
        std::fs::create_dir(&build).unwrap();
        let scope_path = directory.path().join("scope.json");
        let mut approved = plan(&scope_path, scope(&build)).unwrap();
        approved.scope.executor_sha256 = "0".repeat(64);
        approved.confirm_digest = digest(&approved.scope);
        let confirmation = approved.confirm_digest.clone();
        let mut output = Vec::new();
        assert!(
            serve(
                backend(),
                approved,
                &confirmation,
                Cursor::new(Vec::<u8>::new()),
                &mut output
            )
            .is_err()
        );
        assert!(output.is_empty());
        assert!(!scope_path.with_file_name("scope.json.active").exists());
    }

    #[test]
    fn invalid_scope_has_no_output_and_no_hardware_access() {
        let directory = tempdir().unwrap();
        let build = directory.path().join("build");
        std::fs::create_dir(&build).unwrap();
        let scope_path = directory.path().join("scope.json");
        let mut input = scope(&build);
        input.max_flashes = 0;
        assert!(plan(&scope_path, input).is_err());
        assert!(!scope_path.exists());
    }

    #[test]
    fn expired_approval_cannot_start() {
        let directory = tempdir().unwrap();
        let build = directory.path().join("build");
        std::fs::create_dir(&build).unwrap();
        let scope_path = directory.path().join("scope.json");
        let mut input = scope(&build);
        input.duration_seconds = 1;
        let approved = plan(&scope_path, input).unwrap();
        std::thread::sleep(std::time::Duration::from_millis(1100));
        let mut output = Vec::new();
        assert!(
            serve(
                backend(),
                approved,
                &inspect(&scope_path).unwrap().confirm_digest,
                Cursor::new(Vec::<u8>::new()),
                &mut output
            )
            .is_err()
        );
        assert!(output.is_empty());
    }

    #[test]
    fn nrf_bin_scope_cannot_include_uicr() {
        let directory = tempdir().unwrap();
        let build = directory.path().join("build");
        std::fs::create_dir(&build).unwrap();
        let mut approved = plan(&directory.path().join("scope.json"), scope(&build)).unwrap();
        approved.scope.target = "nRF52840_xxAA".to_string();
        approved.scope.write_window = FlashRange {
            start: Address(0x1000_1000),
            length: 0x1000,
        };
        approved.scope.erase_window = approved.scope.write_window.clone();
        assert!(validate(&approved.scope).is_err());
    }

    #[test]
    fn idf_scope_cannot_exceed_declared_physical_flash() {
        let directory = tempdir().unwrap();
        let build = directory.path().join("build");
        std::fs::create_dir(&build).unwrap();
        let mut approved = plan(&directory.path().join("scope.json"), scope(&build)).unwrap();
        approved.scope.target = "esp32s3".to_string();
        approved.scope.firmware_format = "idf".to_string();
        approved.scope.base_address = None;
        approved.scope.flash_size = Some(8 * 1024 * 1024);
        approved.scope.write_window = FlashRange {
            start: Address(8 * 1024 * 1024),
            length: 0x1000,
        };
        approved.scope.erase_window = approved.scope.write_window.clone();
        assert!(validate(&approved.scope).is_err());
    }
}
