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
        ArtifactReference, EvidenceBundle, FirmwareInfo, FlashExecution, FlashPlan, FlashRange,
        OperationRecord, PlannedAction, ProbeInfo,
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
    verify: bool,
    reset: bool,
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

    pub fn plan_flash(
        &self,
        firmware_path: &Path,
        probe_id: Option<&str>,
        target: Option<&str>,
    ) -> Result<FlashPlan> {
        let probes = self.backend.list_probes()?;
        let probe = select_probe(&probes, probe_id)?;
        let target_info = self.backend.target().clone();
        if let Some(requested) = target
            && !requested.eq_ignore_ascii_case(&target_info.name)
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
        let (_, firmware) = read_firmware(firmware_path)?;
        let ranges = self.backend.plan_flash_ranges(firmware.size)?;
        let confirmation = ConfirmationInput {
            schema_version: SCHEMA_VERSION,
            operation: "flash.execute",
            backend: self.backend.name(),
            probe_id: &probe.id,
            target: &target_info.name,
            firmware_format: &firmware.format,
            firmware_sha256: &firmware.sha256,
            firmware_size: firmware.size,
            ranges: &ranges,
            verify: true,
            reset: true,
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
            ranges,
            actions: vec![
                PlannedAction {
                    action: "program_firmware".to_string(),
                    risk: "R2_DEVICE_WRITE".to_string(),
                },
                PlannedAction {
                    action: "verify_firmware".to_string(),
                    risk: "R0_READ_ONLY".to_string(),
                },
                PlannedAction {
                    action: "reset_target".to_string(),
                    risk: "R1_REVERSIBLE_CONTROL".to_string(),
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
        confirm_digest: &str,
        evidence_path: &Path,
    ) -> Result<FlashExecution> {
        let plan = self.plan_flash(firmware_path, probe_id, target)?;
        if plan.confirm_digest != confirm_digest {
            return Err(DebugError::confirmation(
                &plan.confirm_digest,
                confirm_digest,
            ));
        }
        if evidence_path.exists() {
            return Err(DebugError::output_exists(
                &evidence_path.display().to_string(),
            ));
        }

        let (firmware_bytes, current_firmware) = read_firmware(firmware_path)?;
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
            let mut flash =
                self.backend
                    .program(&session, &firmware_bytes, &current_firmware.sha256)?;
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
                core: snapshot.clone(),
                operations: vec![
                    operation(1, "session.attach"),
                    operation(2, "flash.program"),
                    operation(3, "flash.verify"),
                    operation(4, "core.reset"),
                    operation(5, "snapshot.capture"),
                ],
                complete: true,
            };
            let artifact = write_evidence(evidence_path, &evidence)?;
            Ok(FlashExecution {
                plan: plan.clone(),
                session: session.clone(),
                flash,
                snapshot,
                evidence: artifact,
            })
        })();

        let disconnect_result = self.backend.disconnect(&session);
        match (result, disconnect_result) {
            (Err(error), _) => Err(error),
            (Ok(_), Err(error)) => Err(error),
            (Ok(execution), Ok(())) => Ok(execution),
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
        let probe = probes
            .iter()
            .find(|probe| probe.id == id)
            .cloned()
            .ok_or_else(|| {
                DebugError::unavailable(
                    ErrorCode::ProbeUnavailable,
                    "requested probe is not available",
                    json!({"requested": id, "available": probes}),
                )
            })?;
        return ensure_probe_accessible(probe);
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
    let info = FirmwareInfo {
        path: canonical.display().to_string(),
        format: firmware_format(&canonical)?,
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

fn write_evidence(path: &Path, bundle: &EvidenceBundle) -> Result<ArtifactReference> {
    let parent = output_parent(path);
    fs::create_dir_all(parent)
        .map_err(|error| DebugError::io("create evidence directory", parent.to_str(), &error))?;
    let serialized = serde_json::to_vec_pretty(bundle).expect("evidence always serializes");
    let temp_path = temporary_sibling(path);
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&temp_path)
        .map_err(|error| DebugError::io("create temporary evidence", temp_path.to_str(), &error))?;
    let write_result = (|| -> std::io::Result<()> {
        file.write_all(&serialized)?;
        file.write_all(b"\n")?;
        file.sync_all()?;
        Ok(())
    })();
    if let Err(error) = write_result {
        let _ = fs::remove_file(&temp_path);
        return Err(DebugError::io(
            "write temporary evidence",
            temp_path.to_str(),
            &error,
        ));
    }
    if let Err(error) = fs::hard_link(&temp_path, path) {
        let _ = fs::remove_file(&temp_path);
        return if error.kind() == std::io::ErrorKind::AlreadyExists {
            Err(DebugError::output_exists(&path.display().to_string()))
        } else {
            Err(DebugError::io("commit evidence", path.to_str(), &error))
        };
    }
    let _ = fs::remove_file(&temp_path);
    let size = fs::metadata(path)
        .map_err(|error| DebugError::io("read evidence metadata", path.to_str(), &error))?
        .len();
    let persisted =
        fs::read(path).map_err(|error| DebugError::io("hash evidence", path.to_str(), &error))?;
    Ok(ArtifactReference {
        kind: "debug_snapshot".to_string(),
        path: path.display().to_string(),
        size,
        sha256: sha256_bytes(&persisted),
    })
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

        let first_plan = service.plan_flash(&first, None, None).unwrap();
        let second_plan = service.plan_flash(&second, None, None).unwrap();

        assert_ne!(first_plan.confirm_digest, second_plan.confirm_digest);
    }

    #[test]
    fn changing_flash_address_changes_confirmation_digest() {
        let directory = tempdir().unwrap();
        let firmware = directory.path().join("demo.bin");
        fs::write(&firmware, b"same firmware").unwrap();
        let first_fixture = fixture();
        let mut second_fixture = fixture();
        second_fixture.flash.base_address = crate::model::Address(0x0801_0000);

        let first = DebugService::new(ReplayBackend::new(first_fixture))
            .plan_flash(&firmware, None, None)
            .unwrap();
        let second = DebugService::new(ReplayBackend::new(second_fixture))
            .plan_flash(&firmware, None, None)
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

        let error = service.plan_flash(&firmware, None, None).unwrap_err();

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
    fn execution_requires_exact_confirmation_and_writes_evidence() {
        let directory = tempdir().unwrap();
        let firmware = directory.path().join("demo.bin");
        let evidence = directory.path().join("run.evidence.json");
        fs::write(&firmware, b"replay demo firmware\n").unwrap();
        let mut service = DebugService::new(ReplayBackend::new(fixture()));
        let plan = service.plan_flash(&firmware, None, None).unwrap();

        let rejected = service
            .execute_flash(&firmware, None, None, "wrong", &evidence)
            .unwrap_err();
        assert_eq!(rejected.code, ErrorCode::ConfirmationMismatch);
        assert!(!evidence.exists());

        let result = service
            .execute_flash(&firmware, None, None, &plan.confirm_digest, &evidence)
            .unwrap();
        assert!(result.flash.verified);
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
        let plan = service.plan_flash(&firmware, None, None).unwrap();

        let error = service
            .execute_flash(&firmware, None, None, &plan.confirm_digest, &evidence)
            .unwrap_err();
        assert_eq!(error.code, ErrorCode::OutputExists);
        assert_eq!(fs::read(&evidence).unwrap(), b"keep me");
    }
}
