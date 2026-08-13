use std::{
    fs::{self, OpenOptions},
    io::Write,
    path::{Path, PathBuf},
};

use chrono::{SecondsFormat, Utc};
use serde::Serialize;
use serde_json::json;
use sha2::{Digest, Sha256};
use uuid::Uuid;

use crate::{
    SCHEMA_VERSION,
    backend::DebugBackend,
    error::{DebugError, ErrorCode, Result},
    model::{
        Address, ArtifactReference, EvidenceBundle, FirmwareInfo, FlashExecution, FlashPlan,
        FlashPolicy, FlashRange, OperationRecord, PlannedAction, ProbeInfo, ProbeTestReport,
    },
};

const MAX_FIRMWARE_BYTES: u64 = 64 * 1024 * 1024;

#[derive(Debug, Serialize)]
struct ConfirmationInput<'a> {
    schema_version: &'a str,
    operation: &'a str,
    backend: &'a str,
    probe_id: &'a str,
    target: &'a str,
    firmware_format: &'a str,
    firmware_sha256: &'a str,
    firmware_size: u64,
    ranges: &'a [FlashRange],
    erase_ranges: &'a [FlashRange],
    policy: &'a FlashPolicy,
}

pub struct DebugService<B: DebugBackend> {
    backend: B,
}

impl<B: DebugBackend> DebugService<B> {
    pub fn new(backend: B) -> Self {
        Self { backend }
    }

    pub fn probes(&self) -> Result<Vec<ProbeInfo>> {
        self.backend.list_probes()
    }

    pub fn test_probe_connection(
        &mut self,
        probe_id: &str,
        target: &str,
    ) -> Result<ProbeTestReport> {
        let target_info = self.backend.target().clone();
        if !self.backend.matches_target(target) {
            return Err(DebugError::unavailable(
                ErrorCode::TargetUnavailable,
                "requested target is not available from the selected backend",
                json!({"requested": target, "available": target_info.name}),
            ));
        }
        let probe = select_probe(&self.backend.list_probes()?, Some(probe_id))?;
        let session = self.backend.attach(&probe.id, &target_info.name)?;
        let mut operations = vec![OperationRecord {
            sequence: 1,
            operation: "session.attach".to_string(),
            ok: true,
        }];
        self.backend.disconnect(&session)?;
        operations.push(OperationRecord {
            sequence: 2,
            operation: "session.disconnect".to_string(),
            ok: true,
        });

        Ok(ProbeTestReport {
            risk: "R1_REVERSIBLE_CONTROL".to_string(),
            session,
            operations,
            complete: true,
        })
    }

    pub fn plan_flash(
        &self,
        firmware_path: &Path,
        probe_id: Option<&str>,
        target: Option<&str>,
        base_address: Option<Address>,
    ) -> Result<FlashPlan> {
        let target_info = self.backend.target().clone();
        if let Some(requested) = target
            && !self.backend.matches_target(requested)
        {
            return Err(DebugError::unavailable(
                ErrorCode::TargetUnavailable,
                "requested target is not available from the selected backend",
                json!({"requested": requested, "available": target_info.name}),
            ));
        }
        let capabilities = self.backend.capabilities();
        let required_capabilities = [
            ("flash", capabilities.flash),
            ("verify", capabilities.verify),
            ("halt", capabilities.halt),
            ("run", capabilities.run),
            ("reset", capabilities.reset),
            ("register_read", capabilities.register_read),
        ];
        if let Some((capability, _)) = required_capabilities
            .iter()
            .find(|(_, available)| !available)
        {
            return Err(DebugError::new(
                ErrorCode::CapabilityUnavailable,
                "selected backend cannot complete the guarded flash workflow",
                6,
                json!({"backend": self.backend.name(), "capability": capability}),
            ));
        }
        let (_, mut firmware) = read_firmware(firmware_path)?;
        let layout = self
            .backend
            .plan_flash_ranges(firmware.size, base_address)?;
        firmware.base_address = layout.write_ranges.first().map(|range| range.start);
        if firmware.base_address.is_none() {
            return Err(DebugError::new(
                ErrorCode::Internal,
                "backend returned an empty flash write layout",
                10,
                json!({"backend": self.backend.name()}),
            ));
        }
        let probes = self.backend.list_probes()?;
        let probe = select_probe(&probes, probe_id)?;
        if !self.backend.probe_identity_is_stable(&probe) {
            return Err(DebugError::unavailable(
                ErrorCode::ProbeAmbiguous,
                "selected probe does not expose a stable identity for a device write",
                json!({
                    "probe": probe,
                    "requirement": "non-empty hardware serial number",
                }),
            ));
        }
        let policy = FlashPolicy::default();
        let confirmation = ConfirmationInput {
            schema_version: SCHEMA_VERSION,
            operation: "flash.execute",
            backend: self.backend.name(),
            probe_id: &probe.id,
            target: &target_info.name,
            firmware_format: &firmware.format,
            firmware_sha256: &firmware.sha256,
            firmware_size: firmware.size,
            ranges: &layout.write_ranges,
            erase_ranges: &layout.erase_ranges,
            policy: &policy,
        };
        let confirm_digest = sha256_bytes(
            &serde_json::to_vec(&confirmation).expect("confirmation input always serializes"),
        );
        Ok(FlashPlan {
            plan_id: format!("plan_{}", &confirm_digest[..16]),
            risk: "R2_DEVICE_WRITE".to_string(),
            backend: self.backend.name().to_string(),
            probe,
            target: target_info,
            firmware,
            ranges: layout.write_ranges,
            erase_ranges: layout.erase_ranges,
            policy,
            actions: vec![
                PlannedAction {
                    action: "attach_probe".to_string(),
                    risk: "R1_REVERSIBLE_CONTROL".to_string(),
                },
                PlannedAction {
                    action: "erase_affected_sectors".to_string(),
                    risk: "R2_DEVICE_WRITE".to_string(),
                },
                PlannedAction {
                    action: "program_firmware".to_string(),
                    risk: "R2_DEVICE_WRITE".to_string(),
                },
                PlannedAction {
                    action: "verify_firmware".to_string(),
                    risk: "R0_READ_ONLY".to_string(),
                },
                PlannedAction {
                    action: "reset_and_halt_target".to_string(),
                    risk: "R1_REVERSIBLE_CONTROL".to_string(),
                },
                PlannedAction {
                    action: "capture_core_snapshot".to_string(),
                    risk: "R0_READ_ONLY".to_string(),
                },
                PlannedAction {
                    action: "resume_target".to_string(),
                    risk: "R1_REVERSIBLE_CONTROL".to_string(),
                },
                PlannedAction {
                    action: "disconnect_probe".to_string(),
                    risk: "R0_READ_ONLY".to_string(),
                },
            ],
            confirm_digest,
        })
    }

    pub fn execute_flash(
        &mut self,
        firmware_path: &Path,
        probe_id: Option<&str>,
        target: Option<&str>,
        base_address: Option<Address>,
        confirm_digest: &str,
        evidence_path: &Path,
    ) -> Result<FlashExecution> {
        let plan = self.plan_flash(firmware_path, probe_id, target, base_address)?;
        if plan.confirm_digest != confirm_digest {
            return Err(DebugError::confirmation(
                &plan.confirm_digest,
                confirm_digest,
            ));
        }
        let mut evidence_reservation = EvidenceReservation::new(evidence_path)?;

        let (firmware_bytes, mut current_firmware) = read_firmware(firmware_path)?;
        current_firmware.base_address = plan.firmware.base_address;
        if current_firmware.sha256 != plan.firmware.sha256
            || current_firmware.size != plan.firmware.size
        {
            return Err(DebugError::new(
                ErrorCode::PlanStale,
                "firmware changed after the flash plan was created",
                2,
                json!({
                    "planned_sha256": plan.firmware.sha256,
                    "current_sha256": current_firmware.sha256,
                }),
            ));
        }

        let session = self.backend.attach(&plan.probe.id, &plan.target.name)?;
        let result = (|| {
            let base_address = current_firmware.base_address.ok_or_else(|| {
                DebugError::new(
                    ErrorCode::Internal,
                    "flash plan omitted the raw BIN base address",
                    10,
                    json!({"plan_id": plan.plan_id}),
                )
            })?;
            let mut flash = self.backend.program(
                &session,
                &firmware_bytes,
                base_address,
                &current_firmware.sha256,
            )?;
            flash.verified = self.backend.verify(&session, &current_firmware.sha256)?;
            if !flash.verified {
                return Err(DebugError::verification(
                    "firmware verification failed",
                    json!({"firmware_sha256": current_firmware.sha256}),
                ));
            }
            self.backend.reset(&session)?;
            let snapshot = self.backend.snapshot(&session)?;
            let evidence = EvidenceBundle {
                schema_version: SCHEMA_VERSION.to_string(),
                capture_id: format!("cap_{}", Uuid::new_v4().simple()),
                captured_at: Utc::now().to_rfc3339_opts(SecondsFormat::Millis, true),
                backend: self.backend.name().to_string(),
                probe: session.probe.clone(),
                target: session.target.clone(),
                firmware: current_firmware.clone(),
                plan_id: Some(plan.plan_id.clone()),
                confirm_digest: Some(plan.confirm_digest.clone()),
                ranges: plan.ranges.clone(),
                erase_ranges: plan.erase_ranges.clone(),
                policy: Some(plan.policy.clone()),
                flash: Some(flash.clone()),
                core: snapshot.clone(),
                operations: vec![
                    operation(1, "session.attach"),
                    operation(2, "flash.erase_affected_sectors"),
                    operation(3, "flash.program"),
                    operation(4, "flash.verify"),
                    operation(5, "core.reset_and_halt"),
                    operation(6, "snapshot.capture"),
                    operation(7, "core.resume"),
                ],
                complete: false,
            };
            Ok((flash, snapshot, evidence))
        })();

        let disconnect_result = self.backend.disconnect(&session);
        match (result, disconnect_result) {
            (Err(error), Err(cleanup_error)) => Err(with_cleanup_failure(error, cleanup_error)),
            (Err(error), Ok(())) => Err(error),
            (Ok(_), Err(error)) => Err(error),
            (Ok((flash, snapshot, mut evidence)), Ok(())) => {
                evidence.operations.push(operation(8, "session.disconnect"));
                evidence.complete = true;
                let artifact = evidence_reservation.publish(&evidence)?;
                Ok(FlashExecution {
                    plan,
                    session,
                    flash,
                    snapshot,
                    evidence: artifact,
                })
            }
        }
    }
}

pub fn inspect_evidence(path: &Path) -> Result<EvidenceBundle> {
    let bytes =
        fs::read(path).map_err(|error| DebugError::io("read evidence", path.to_str(), &error))?;
    let bundle: EvidenceBundle = serde_json::from_slice(&bytes).map_err(|error| {
        DebugError::evidence(
            "evidence is not valid JSON",
            json!({"path": path, "parser_message": error.to_string()}),
        )
    })?;
    if bundle.schema_version != SCHEMA_VERSION || !bundle.complete {
        return Err(DebugError::evidence(
            "evidence is incomplete or uses an unsupported schema",
            json!({
                "path": path,
                "schema_version": bundle.schema_version,
                "complete": bundle.complete,
            }),
        ));
    }
    Ok(bundle)
}

fn select_probe(probes: &[ProbeInfo], requested: Option<&str>) -> Result<ProbeInfo> {
    if let Some(id) = requested {
        let matches = probes
            .iter()
            .filter(|probe| probe.id == id)
            .cloned()
            .collect::<Vec<_>>();
        return match matches.as_slice() {
            [probe] => ensure_probe_accessible(probe.clone()),
            [] => Err(DebugError::unavailable(
                ErrorCode::ProbeUnavailable,
                "requested probe is not available",
                json!({"requested": id, "available": probes}),
            )),
            many => Err(DebugError::unavailable(
                ErrorCode::ProbeAmbiguous,
                "requested selector matches multiple probes; a unique serial or interface is required",
                json!({"requested": id, "matches": many}),
            )),
        };
    }
    match probes {
        [only] => ensure_probe_accessible(only.clone()),
        [] => Err(DebugError::unavailable(
            ErrorCode::ProbeUnavailable,
            "no debug probe is available",
            json!({}),
        )),
        many => Err(DebugError::unavailable(
            ErrorCode::ProbeAmbiguous,
            "multiple debug probes are available; select one explicitly",
            json!({"available": many}),
        )),
    }
}

fn ensure_probe_accessible(probe: ProbeInfo) -> Result<ProbeInfo> {
    if probe.accessible {
        Ok(probe)
    } else {
        Err(DebugError::new(
            ErrorCode::PermissionDenied,
            "the selected debug probe is visible but not accessible",
            8,
            json!({"probe": probe}),
        ))
    }
}

fn read_firmware(path: &Path) -> Result<(Vec<u8>, FirmwareInfo)> {
    let canonical = path
        .canonicalize()
        .map_err(|error| DebugError::io("resolve firmware path", path.to_str(), &error))?;
    let metadata = canonical
        .metadata()
        .map_err(|error| DebugError::io("read firmware metadata", canonical.to_str(), &error))?;
    if !metadata.is_file() {
        return Err(DebugError::config(
            "firmware path must identify a regular file",
            json!({"path": canonical}),
        ));
    }
    if metadata.len() == 0 || metadata.len() > MAX_FIRMWARE_BYTES {
        return Err(DebugError::config(
            "firmware size is outside the allowed range",
            json!({
                "path": canonical,
                "size": metadata.len(),
                "maximum": MAX_FIRMWARE_BYTES,
            }),
        ));
    }
    let bytes = fs::read(&canonical)
        .map_err(|error| DebugError::io("read firmware", canonical.to_str(), &error))?;
    if bytes.is_empty() || bytes.len() as u64 > MAX_FIRMWARE_BYTES {
        return Err(DebugError::config(
            "firmware size changed while reading or is outside the allowed range",
            json!({
                "path": canonical,
                "size": bytes.len(),
                "maximum": MAX_FIRMWARE_BYTES,
            }),
        ));
    }
    let info = FirmwareInfo {
        path: canonical.display().to_string(),
        format: firmware_format(&canonical)?,
        base_address: None,
        size: bytes.len() as u64,
        sha256: sha256_bytes(&bytes),
    };
    Ok((bytes, info))
}

fn firmware_format(path: &Path) -> Result<String> {
    let extension = path
        .extension()
        .and_then(|value| value.to_str())
        .map(str::to_ascii_lowercase);
    match extension.as_deref() {
        Some("bin") => Ok("bin".to_string()),
        other => Err(DebugError::config(
            "this milestone supports raw BIN firmware only",
            json!({"path": path, "extension": other}),
        )),
    }
}

struct EvidenceReservation {
    target_path: PathBuf,
    temp_path: PathBuf,
    file: Option<fs::File>,
    preserve_temp: bool,
}

impl EvidenceReservation {
    fn new(path: &Path) -> Result<Self> {
        if path.exists() {
            return Err(DebugError::output_exists(&path.display().to_string()));
        }
        let parent = output_parent(path);
        fs::create_dir_all(parent).map_err(|error| {
            DebugError::io("create evidence directory", parent.to_str(), &error)
        })?;
        let temp_path = temporary_sibling(path);
        let file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&temp_path)
            .map_err(|error| {
                DebugError::io("reserve temporary evidence", temp_path.to_str(), &error)
            })?;
        Ok(Self {
            target_path: path.to_path_buf(),
            temp_path,
            file: Some(file),
            preserve_temp: false,
        })
    }

    fn publish(&mut self, bundle: &EvidenceBundle) -> Result<ArtifactReference> {
        let serialized = serde_json::to_vec_pretty(bundle).expect("evidence always serializes");
        let mut file = self
            .file
            .take()
            .expect("evidence reservation is unpublished");
        if let Err(error) = (|| -> std::io::Result<()> {
            file.write_all(&serialized)?;
            file.write_all(b"\n")?;
            file.sync_all()?;
            Ok(())
        })() {
            return Err(DebugError::io(
                "write temporary evidence",
                self.temp_path.to_str(),
                &error,
            ));
        }
        drop(file);

        if let Err(error) = fs::hard_link(&self.temp_path, &self.target_path) {
            self.preserve_temp = true;
            return if error.kind() == std::io::ErrorKind::AlreadyExists {
                Err(DebugError::new(
                    ErrorCode::OutputExists,
                    "refusing to overwrite an evidence file created during execution; complete evidence remains at the recovery path",
                    2,
                    json!({
                        "path": self.target_path,
                        "recovery_path": self.temp_path,
                    }),
                ))
            } else {
                Err(DebugError::new(
                    if error.kind() == std::io::ErrorKind::PermissionDenied {
                        ErrorCode::PermissionDenied
                    } else {
                        ErrorCode::Internal
                    },
                    format!(
                        "commit evidence failed: {error}; complete evidence remains at the recovery path"
                    ),
                    if error.kind() == std::io::ErrorKind::PermissionDenied {
                        8
                    } else {
                        10
                    },
                    json!({
                        "path": self.target_path,
                        "recovery_path": self.temp_path,
                    }),
                ))
            };
        }
        let _ = fs::remove_file(&self.temp_path);
        let size = (serialized.len() + 1) as u64;
        let mut persisted = serialized;
        persisted.push(b'\n');
        Ok(ArtifactReference {
            kind: "debug_snapshot".to_string(),
            path: self.target_path.display().to_string(),
            size,
            sha256: sha256_bytes(&persisted),
        })
    }
}

impl Drop for EvidenceReservation {
    fn drop(&mut self) {
        self.file.take();
        if !self.preserve_temp && self.temp_path.exists() {
            let _ = fs::remove_file(&self.temp_path);
        }
    }
}

fn output_parent(path: &Path) -> &Path {
    path.parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."))
}

fn temporary_sibling(path: &Path) -> PathBuf {
    let mut name = path
        .file_name()
        .map(|value| value.to_os_string())
        .unwrap_or_else(|| "evidence".into());
    name.push(format!(".{}.tmp", Uuid::new_v4().simple()));
    path.with_file_name(name)
}

fn operation(sequence: u32, name: &str) -> OperationRecord {
    OperationRecord {
        sequence,
        operation: name.to_string(),
        ok: true,
    }
}

fn with_cleanup_failure(mut primary: DebugError, cleanup: DebugError) -> DebugError {
    primary.message = format!("{}; session cleanup also failed", primary.message);
    primary.details = json!({
        "primary": primary.details,
        "cleanup": {
            "code": cleanup.code,
            "message": cleanup.message,
            "details": cleanup.details,
        },
    });
    primary
}

fn sha256_bytes(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

#[cfg(test)]
mod tests {
    use std::fs;

    use tempfile::tempdir;

    use super::*;
    use crate::backend::replay::{ReplayBackend, ReplayFixture};

    fn fixture() -> ReplayFixture {
        serde_json::from_str(include_str!("../examples/replay/stm32g4.json")).unwrap()
    }

    #[test]
    fn changing_firmware_changes_confirmation_digest() {
        let directory = tempdir().unwrap();
        let first = directory.path().join("first.bin");
        let second = directory.path().join("second.bin");
        fs::write(&first, b"firmware-a").unwrap();
        fs::write(&second, b"firmware-b").unwrap();
        let service = DebugService::new(ReplayBackend::new(fixture()));

        let first_plan = service.plan_flash(&first, None, None, None).unwrap();
        let second_plan = service.plan_flash(&second, None, None, None).unwrap();

        assert_ne!(first_plan.confirm_digest, second_plan.confirm_digest);
    }

    #[test]
    fn probe_test_disconnects_and_can_be_repeated() {
        let replay = fixture();
        let probe_id = replay.probe.id.clone();
        let target = replay.target.name.clone();
        let mut service = DebugService::new(ReplayBackend::new(replay));

        let first = service.test_probe_connection(&probe_id, &target).unwrap();
        let second = service.test_probe_connection(&probe_id, &target).unwrap();

        assert!(first.complete);
        assert!(second.complete);
        assert_eq!(first.operations[1].operation, "session.disconnect");
    }

    #[test]
    fn changing_flash_address_changes_confirmation_digest() {
        let directory = tempdir().unwrap();
        let firmware = directory.path().join("demo.bin");
        fs::write(&firmware, b"same firmware").unwrap();
        let first_fixture = fixture();
        let mut second_fixture = fixture();
        second_fixture.flash.base_address = crate::model::Address(0x0801_0000);
        second_fixture.flash.erase_ranges[0].start = crate::model::Address(0x0801_0000);

        let first = DebugService::new(ReplayBackend::new(first_fixture))
            .plan_flash(&firmware, None, None, None)
            .unwrap();
        let second = DebugService::new(ReplayBackend::new(second_fixture))
            .plan_flash(&firmware, None, None, None)
            .unwrap();

        assert_eq!(first.ranges[0].start, crate::model::Address(0x0800_0000));
        assert_eq!(first.ranges[0].length, 13);
        assert_ne!(first.confirm_digest, second.confirm_digest);
    }

    #[test]
    fn plan_rejects_incomplete_guarded_workflow_before_writing() {
        let directory = tempdir().unwrap();
        let firmware = directory.path().join("demo.bin");
        fs::write(&firmware, b"firmware").unwrap();
        let mut replay = fixture();
        replay.capabilities.verify = false;
        let service = DebugService::new(ReplayBackend::new(replay));

        let error = service.plan_flash(&firmware, None, None, None).unwrap_err();

        assert_eq!(error.code, ErrorCode::CapabilityUnavailable);
        assert_eq!(error.details["capability"], "verify");
    }

    #[test]
    fn relative_evidence_path_uses_current_directory() {
        assert_eq!(
            output_parent(Path::new("run.evidence.json")),
            Path::new(".")
        );
    }

    #[test]
    fn duplicate_probe_identity_is_rejected() {
        let first = fixture().probe;
        let mut second = first.clone();
        second.product = Some("second physical probe".to_string());

        let error = select_probe(&[first.clone(), second], Some(&first.id)).unwrap_err();

        assert_eq!(error.code, ErrorCode::ProbeAmbiguous);
    }

    #[test]
    fn failed_execution_does_not_leave_evidence_or_reservation() {
        let directory = tempdir().unwrap();
        let firmware = directory.path().join("demo.bin");
        let evidence = directory.path().join("run.evidence.json");
        fs::write(&firmware, b"replay demo firmware\n").unwrap();
        let mut replay = fixture();
        replay.flash.verify_success = false;
        let mut service = DebugService::new(ReplayBackend::new(replay));
        let plan = service.plan_flash(&firmware, None, None, None).unwrap();

        let error = service
            .execute_flash(&firmware, None, None, None, &plan.confirm_digest, &evidence)
            .unwrap_err();

        assert_eq!(error.code, ErrorCode::VerificationFailed);
        assert!(!evidence.exists());
        assert_eq!(fs::read_dir(directory.path()).unwrap().count(), 1);
    }

    #[test]
    fn execution_requires_exact_confirmation_and_writes_evidence() {
        let directory = tempdir().unwrap();
        let firmware = directory.path().join("demo.bin");
        let evidence = directory.path().join("run.evidence.json");
        fs::write(&firmware, b"replay demo firmware\n").unwrap();
        let mut service = DebugService::new(ReplayBackend::new(fixture()));
        let plan = service.plan_flash(&firmware, None, None, None).unwrap();

        let rejected = service
            .execute_flash(&firmware, None, None, None, "wrong", &evidence)
            .unwrap_err();
        assert_eq!(rejected.code, ErrorCode::ConfirmationMismatch);
        assert!(!evidence.exists());

        let result = service
            .execute_flash(&firmware, None, None, None, &plan.confirm_digest, &evidence)
            .unwrap();
        assert!(result.flash.verified);
        assert_eq!(
            result.snapshot.captured_state,
            crate::model::CoreState::Halted
        );
        assert_eq!(result.snapshot.state, crate::model::CoreState::Running);
        assert!(evidence.exists());
        assert!(inspect_evidence(&evidence).unwrap().complete);
    }

    #[test]
    fn evidence_is_never_overwritten() {
        let directory = tempdir().unwrap();
        let firmware = directory.path().join("demo.bin");
        let evidence = directory.path().join("run.evidence.json");
        fs::write(&firmware, b"replay demo firmware\n").unwrap();
        fs::write(&evidence, b"keep me").unwrap();
        let mut service = DebugService::new(ReplayBackend::new(fixture()));
        let plan = service.plan_flash(&firmware, None, None, None).unwrap();

        let error = service
            .execute_flash(&firmware, None, None, None, &plan.confirm_digest, &evidence)
            .unwrap_err();
        assert_eq!(error.code, ErrorCode::OutputExists);
        assert_eq!(fs::read(&evidence).unwrap(), b"keep me");
    }

    #[test]
    fn publish_race_preserves_complete_recovery_evidence() {
        let directory = tempdir().unwrap();
        let target = directory.path().join("run.evidence.json");
        let mut reservation = EvidenceReservation::new(&target).unwrap();
        fs::write(&target, b"other writer").unwrap();
        let mut fixture = fixture();
        let bundle = EvidenceBundle {
            schema_version: SCHEMA_VERSION.to_string(),
            capture_id: "cap_test".to_string(),
            captured_at: "2026-08-13T00:00:00.000Z".to_string(),
            backend: "replay".to_string(),
            probe: fixture.probe,
            target: fixture.target,
            firmware: FirmwareInfo {
                path: "firmware.bin".to_string(),
                format: "bin".to_string(),
                base_address: Some(fixture.flash.base_address),
                size: 1,
                sha256: "00".repeat(32),
            },
            plan_id: Some("plan_test".to_string()),
            confirm_digest: Some("11".repeat(32)),
            ranges: vec![FlashRange {
                start: fixture.flash.base_address,
                length: 1,
            }],
            erase_ranges: std::mem::take(&mut fixture.flash.erase_ranges),
            policy: Some(FlashPolicy::default()),
            flash: Some(crate::model::FlashReport {
                bytes_programmed: 1,
                firmware_sha256: "00".repeat(32),
                verified: true,
            }),
            core: fixture.after_reset_core,
            operations: vec![operation(1, "session.disconnect")],
            complete: true,
        };

        let error = reservation.publish(&bundle).unwrap_err();
        let recovery = PathBuf::from(error.details["recovery_path"].as_str().unwrap());

        assert_eq!(error.code, ErrorCode::OutputExists);
        assert_eq!(fs::read(&target).unwrap(), b"other writer");
        assert!(inspect_evidence(&recovery).unwrap().complete);
        fs::remove_file(recovery).unwrap();
    }
}
