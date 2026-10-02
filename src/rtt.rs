//! Bounded, target-to-host RTT capture. RTT consumption writes only the read cursor.
use std::{
    fs::OpenOptions,
    io::Write,
    path::Path,
    thread,
    time::{Duration, Instant},
};

use chrono::{SecondsFormat, Utc};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use uuid::Uuid;

use crate::{
    backend::DebugBackend,
    error::{DebugError, ErrorCode, Result},
    model::{Address, ArtifactReference, SessionInfo, TargetInfo},
    service::select_probe,
};

pub const MAX_CAPTURE_BYTES: u64 = 1024 * 1024;
pub const MAX_CHUNK_BYTES: usize = 4096;
pub const MAX_CAPTURE_CHUNKS: u64 = 4096;
pub const MAX_CHANNELS: u32 = 16;
pub const MAX_RING_BYTES: u32 = 1024 * 1024;
pub const HEADER_BYTES: u64 = 24;
pub const DESCRIPTOR_BYTES: u64 = 24;
pub const RTT_MAGIC: &[u8; 16] = b"SEGGER RTT\0\0\0\0\0\0";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RttSelection {
    pub core: u32,
    pub control_block: Address,
    pub channel: u32,
}

impl RttSelection {
    pub fn validate(&self) -> Result<()> {
        if self.control_block.0 == 0
            || !self.control_block.0.is_multiple_of(4)
            || self.control_block.0 > u32::MAX as u64
            || self.channel >= MAX_CHANNELS
        {
            return Err(DebugError::config(
                "RTT requires an aligned 32-bit control-block address and channel 0..15",
                json!({"selection": self}),
            ));
        }
        Ok(())
    }

    pub fn descriptor_address(&self) -> Address {
        Address(self.control_block.0 + HEADER_BYTES + u64::from(self.channel) * DESCRIPTOR_BYTES)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RttCaptureLimits {
    pub duration_ms: u64,
    pub maximum_bytes: u64,
    pub poll_interval_ms: u64,
}

impl RttCaptureLimits {
    pub fn validate(self) -> Result<()> {
        if !(10..=60000).contains(&self.duration_ms)
            || !(1..=MAX_CAPTURE_BYTES).contains(&self.maximum_bytes)
            || !(1..=1000).contains(&self.poll_interval_ms)
            || self.poll_interval_ms > self.duration_ms
        {
            return Err(DebugError::config(
                "RTT limits require duration 10..60000 ms, 1..1048576 bytes and poll interval 1..1000 ms no greater than duration",
                json!({"limits": self}),
            ));
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RttMemoryScope {
    pub start: Address,
    pub length: u64,
}

impl RttMemoryScope {
    pub fn contains(&self, start: Address, length: u64) -> bool {
        length > 0
            && self
                .start
                .0
                .checked_add(self.length)
                .zip(start.0.checked_add(length))
                .is_some_and(|(scope_end, end)| {
                    self.start.0 <= start.0 && end <= scope_end && end <= 0x1_0000_0000
                })
    }

    pub fn validate_selection(&self, selection: &RttSelection) -> Result<()> {
        selection.validate()?;
        if !self.contains(selection.control_block, HEADER_BYTES)
            || !self.contains(selection.descriptor_address(), DESCRIPTOR_BYTES)
        {
            return Err(DebugError::config(
                "RTT header and selected descriptor must fit in one verified RAM region",
                json!({"selection": selection, "memory_scope": self}),
            ));
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RttChannelInfo {
    pub selection: RttSelection,
    pub memory_scope: RttMemoryScope,
    pub buffer_start: Address,
    pub buffer_size: u32,
    pub read_cursor_address: Address,
    pub flags: u32,
    pub name_pointer: Address,
    pub control_block_bytes: u32,
}

pub fn validate_channel(
    info: &RttChannelInfo,
    selection: &RttSelection,
    scope: &RttMemoryScope,
) -> Result<()> {
    scope.validate_selection(selection)?;
    let minimum_metadata = HEADER_BYTES + (u64::from(selection.channel) + 1) * DESCRIPTOR_BYTES;
    let maximum_metadata = HEADER_BYTES + u64::from(MAX_CHANNELS) * 2 * DESCRIPTOR_BYTES;
    if &info.selection != selection
        || &info.memory_scope != scope
        || info.read_cursor_address != Address(selection.descriptor_address().0 + 16)
        || !(2..=MAX_RING_BYTES).contains(&info.buffer_size)
        || !scope.contains(info.buffer_start, u64::from(info.buffer_size))
        || info.flags & 3 > 2
        || !(minimum_metadata..=maximum_metadata).contains(&u64::from(info.control_block_bytes))
        || !scope.contains(selection.control_block, u64::from(info.control_block_bytes))
    {
        return Err(protocol_error(
            "RTT channel metadata is outside the planned RAM/protocol scope",
            json!({"channel": info}),
        ));
    }
    let ring_end = info.buffer_start.0 + u64::from(info.buffer_size);
    let metadata_end = selection.control_block.0 + u64::from(info.control_block_bytes);
    if info.buffer_start.0 < metadata_end && ring_end > selection.control_block.0 {
        return Err(protocol_error(
            "RTT data ring overlaps its control block",
            json!({"channel": info}),
        ));
    }
    Ok(())
}

pub fn validate_header(header: &[u8; 24], selection: &RttSelection) -> Result<u32> {
    let up = u32::from_le_bytes(header[16..20].try_into().unwrap());
    let down = u32::from_le_bytes(header[20..24].try_into().unwrap());
    if &header[..16] != RTT_MAGIC
        || up == 0
        || up > MAX_CHANNELS
        || down > MAX_CHANNELS
        || selection.channel >= up
    {
        return Err(protocol_error(
            "RTT header is missing, corrupted or does not contain the selected up channel",
            json!({"up_channels": up, "down_channels": down, "channel": selection.channel}),
        ));
    }
    Ok(HEADER_BYTES as u32 + (up + down) * DESCRIPTOR_BYTES as u32)
}

pub fn parse_descriptor(
    selection: &RttSelection,
    scope: &RttMemoryScope,
    control_block_bytes: u32,
    words: [u32; 6],
) -> Result<(RttChannelInfo, u32, u32)> {
    let info = RttChannelInfo {
        selection: selection.clone(),
        memory_scope: scope.clone(),
        name_pointer: Address(u64::from(words[0])),
        buffer_start: Address(u64::from(words[1])),
        buffer_size: words[2],
        read_cursor_address: Address(selection.descriptor_address().0 + 16),
        flags: words[5],
        control_block_bytes,
    };
    validate_channel(&info, selection, scope)?;
    ring_read_spans(&info, words[3], words[4], 1)?;
    Ok((info, words[3], words[4]))
}

/// The writer owns write_offset; the consumer owns read_offset. Leave one byte unused.
pub fn ring_read_spans(
    info: &RttChannelInfo,
    write_offset: u32,
    read_offset: u32,
    maximum_bytes: usize,
) -> Result<(Vec<(Address, usize)>, u32)> {
    let size = info.buffer_size;
    if !(2..=MAX_RING_BYTES).contains(&size)
        || write_offset >= size
        || read_offset >= size
        || maximum_bytes == 0
        || maximum_bytes > MAX_CHUNK_BYTES
    {
        return Err(protocol_error(
            "RTT cursor or read size is invalid",
            json!({"write_offset": write_offset, "read_offset": read_offset, "buffer_size": size, "maximum_bytes": maximum_bytes}),
        ));
    }
    let available =
        (u64::from(write_offset) + u64::from(size) - u64::from(read_offset)) % u64::from(size);
    let count = usize::try_from(available).unwrap().min(maximum_bytes);
    if count == 0 {
        return Ok((Vec::new(), read_offset));
    }
    let first = count.min((size - read_offset) as usize);
    let mut spans = vec![(Address(info.buffer_start.0 + u64::from(read_offset)), first)];
    if first < count {
        spans.push((info.buffer_start, count - first));
    }
    let next = ((u64::from(read_offset) + count as u64) % u64::from(size)) as u32;
    Ok((spans, next))
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct RttEffects {
    pub target_ram_read: bool,
    pub target_rtt_read_cursor_write: bool,
    pub down_channel_write: bool,
    pub channel_mode_write: bool,
    pub reset_requested: bool,
    pub halt_requested: bool,
    pub resume_requested: bool,
    pub attach_may_affect_target: bool,
    pub post_disconnect_core_state_verified: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct RttPlan {
    pub schema_version: &'static str,
    pub tool_version: &'static str,
    pub protocol: &'static str,
    pub maximum_channel_count: u32,
    pub maximum_ring_bytes: u32,
    pub operation: &'static str,
    pub scope: &'static str,
    pub risk: &'static str,
    pub backend: String,
    pub probe_id: String,
    pub target: TargetInfo,
    pub selection: RttSelection,
    pub memory_scope: RttMemoryScope,
    pub limits: RttCaptureLimits,
    pub chunk_bytes_limit: usize,
    pub chunk_count_limit: u64,
    pub effects: RttEffects,
    pub hardware_access: bool,
    pub hardware_acceptance_verified: bool,
    pub confirm_digest: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct RttCaptureReport {
    pub schema_version: &'static str,
    pub scope: &'static str,
    pub capture_id: String,
    pub plan: RttPlan,
    pub session: SessionInfo,
    pub channel: RttChannelInfo,
    pub started_at: String,
    pub finished_at: String,
    pub elapsed_ms: u64,
    pub stop_reason: &'static str,
    pub bytes_captured: u64,
    pub chunk_count: u64,
    pub next_cursor: u64,
    pub payload_sha256: String,
    pub channel_stopped: bool,
    pub disconnected: bool,
    pub complete: bool,
    pub hardware_access: bool,
    pub evidence: ArtifactReference,
}

pub struct RttService<B: DebugBackend> {
    backend: B,
}

impl<B: DebugBackend> RttService<B> {
    pub fn new(backend: B) -> Self {
        Self { backend }
    }

    /// Pure host planning. Does not enumerate probes or attach to a target.
    pub fn plan(
        &self,
        probe_id: &str,
        target: &str,
        selection: &RttSelection,
        limits: RttCaptureLimits,
    ) -> Result<RttPlan> {
        selection.validate()?;
        limits.validate()?;
        if probe_id.trim().is_empty()
            || !self.backend.matches_target(target)
            || selection.core >= self.backend.target().core_count
        {
            return Err(DebugError::config(
                "RTT requires an exact probe/target and an available core",
                json!({"probe_id": probe_id, "target": target, "selection": selection}),
            ));
        }
        if !self.backend.capabilities().rtt {
            return Err(unsupported(self.backend.name()));
        }
        let scope = self.backend.plan_rtt_channel(selection)?;
        scope.validate_selection(selection)?;
        let native = self.backend.name() != "replay";
        let mut plan = RttPlan {
            schema_version: "embedded-debugger.rtt-plan.v1",
            tool_version: env!("CARGO_PKG_VERSION"),
            protocol: "segger_rtt_32bit_little_endian",
            maximum_channel_count: MAX_CHANNELS,
            maximum_ring_bytes: MAX_RING_BYTES,
            operation: "rtt.capture",
            scope: "host_only_rtt_planning",
            risk: "R1_REVERSIBLE_CONTROL",
            backend: self.backend.name().into(),
            probe_id: probe_id.into(),
            target: self.backend.target().clone(),
            selection: selection.clone(),
            memory_scope: scope,
            limits,
            chunk_bytes_limit: MAX_CHUNK_BYTES,
            chunk_count_limit: MAX_CAPTURE_CHUNKS,
            effects: RttEffects {
                target_ram_read: true,
                target_rtt_read_cursor_write: true,
                down_channel_write: false,
                channel_mode_write: false,
                reset_requested: false,
                halt_requested: false,
                resume_requested: false,
                attach_may_affect_target: native,
                post_disconnect_core_state_verified: false,
            },
            hardware_access: false,
            hardware_acceptance_verified: false,
            confirm_digest: String::new(),
        };
        plan.confirm_digest = hex::encode(Sha256::digest(
            serde_json::to_vec(&plan).expect("RTT plan serializes"),
        ));
        Ok(plan)
    }

    pub fn capture(
        &mut self,
        plan: &RttPlan,
        confirm_digest: &str,
        evidence_path: &Path,
    ) -> Result<RttCaptureReport> {
        let current = self.plan(
            &plan.probe_id,
            &plan.target.name,
            &plan.selection,
            plan.limits,
        )?;
        if current != *plan || current.confirm_digest != confirm_digest {
            return Err(DebugError::new(
                ErrorCode::ConfirmationMismatch,
                "RTT confirmation does not match the exact current plan",
                2,
                json!({"expected_confirm_digest": current.confirm_digest, "received_confirm_digest": confirm_digest}),
            ));
        }
        // Reserve evidence before enumeration/attach: never consume target data without a sink.
        let mut evidence = EvidenceWriter::create(evidence_path)?;
        let capture_id = format!("rtt_{}", Uuid::new_v4().simple());
        let clock = Instant::now();
        let started_at = timestamp();
        evidence.record(&json!({"schema_version": "embedded-debugger.rtt-evidence.v1", "event": "capture.started", "capture_id": capture_id, "timestamp": started_at, "elapsed_ms": 0, "plan": plan}))?;
        let attach_result = (|| {
            let probe = select_probe(&self.backend.list_probes()?, Some(&plan.probe_id))?;
            if !self.backend.probe_identity_is_stable(&probe) {
                return Err(DebugError::config(
                    "RTT requires a stable exact probe identity",
                    json!({"probe": probe}),
                ));
            }
            self.backend.attach(&probe.id, &plan.target.name)
        })();
        let session = match attach_result {
            Ok(session) => session,
            Err(mut error) => {
                let record_result = evidence.record(&json!({"event": "capture.finished", "capture_id": capture_id, "timestamp": timestamp(), "elapsed_ms": elapsed_ms(clock), "ok": false, "stage": "attach", "error": error_json(&error), "attach_completed": false}));
                error.details = json!({"cause": error.details, "evidence_path": evidence_path, "failure_record_error": record_result.err().as_ref().map(error_json)});
                return Err(error);
            }
        };
        let deadline = Instant::now() + Duration::from_millis(plan.limits.duration_ms);
        let result = (|| -> Result<_> {
            if session.backend != plan.backend
                || session.probe.id != plan.probe_id
                || session.target != plan.target
            {
                return Err(protocol_error(
                    "backend attached an unexpected RTT probe/target",
                    json!({"session": session}),
                ));
            }
            let channel = self.backend.start_rtt(&session, &plan.selection)?;
            validate_channel(&channel, &plan.selection, &plan.memory_scope)?;
            evidence.record(&json!({"event": "rtt.channel", "capture_id": capture_id, "timestamp": timestamp(), "elapsed_ms": elapsed_ms(clock), "channel": channel}))?;
            let mut bytes = 0_u64;
            let mut chunks = 0_u64;
            let mut payload_hash = Sha256::new();
            let stop_reason = loop {
                if bytes == plan.limits.maximum_bytes {
                    break "byte_limit";
                }
                if chunks == MAX_CAPTURE_CHUNKS {
                    break "chunk_limit";
                }
                if Instant::now() >= deadline {
                    break "duration_limit";
                }
                let maximum =
                    (plan.limits.maximum_bytes - bytes).min(MAX_CHUNK_BYTES as u64) as usize;
                let data = self.backend.read_rtt(&session, maximum)?;
                if data.len() > maximum {
                    return Err(protocol_error(
                        "backend exceeded the RTT chunk limit",
                        json!({"maximum": maximum, "returned": data.len()}),
                    ));
                }
                if !data.is_empty() {
                    evidence.record(&json!({"event": "rtt.chunk", "capture_id": capture_id, "sequence": chunks, "cursor": bytes, "next_cursor": bytes + data.len() as u64, "timestamp": timestamp(), "elapsed_ms": elapsed_ms(clock), "encoding": "hex", "data": hex::encode(&data), "length": data.len()}))?;
                    payload_hash.update(&data);
                    bytes += data.len() as u64;
                    chunks += 1;
                }
                if bytes < plan.limits.maximum_bytes
                    && let Some(remaining) = deadline.checked_duration_since(Instant::now())
                {
                    thread::sleep(
                        Duration::from_millis(plan.limits.poll_interval_ms).min(remaining),
                    );
                }
            };
            Ok((
                channel,
                bytes,
                chunks,
                hex::encode(payload_hash.finalize()),
                stop_reason,
            ))
        })();
        // Both cleanup steps run even after start/read/output failure; no automatic retries.
        let stop_result = self.backend.stop_rtt(&session);
        let disconnect_result = self.backend.disconnect(&session);
        let finished_at = timestamp();
        let elapsed = elapsed_ms(clock);
        let cleanup = json!({"channel_stopped": stop_result.is_ok(), "disconnected": disconnect_result.is_ok(), "stop_error": stop_result.as_ref().err().map(error_json), "disconnect_error": disconnect_result.as_ref().err().map(error_json)});
        let completion = match result {
            Ok((channel, bytes, chunks, payload_sha256, reason))
                if stop_result.is_ok() && disconnect_result.is_ok() =>
            {
                evidence.record(&json!({"event": "capture.finished", "capture_id": capture_id, "timestamp": finished_at, "elapsed_ms": elapsed, "ok": true, "stop_reason": reason, "bytes_captured": bytes, "chunk_count": chunks, "next_cursor": bytes, "payload_sha256": payload_sha256, "cleanup": cleanup}))?;
                Ok((channel, bytes, chunks, payload_sha256, reason))
            }
            outcome => {
                let mut error = match outcome {
                    Err(error) => error,
                    Ok(_) => DebugError::new(
                        ErrorCode::ProtocolError,
                        "RTT capture cleanup failed",
                        6,
                        json!({}),
                    ),
                };
                let failure_record = evidence.record(&json!({"event": "capture.finished", "capture_id": capture_id, "timestamp": finished_at, "elapsed_ms": elapsed, "ok": false, "error": error_json(&error), "cleanup": cleanup}));
                error.details = json!({"cause": error.details, "cleanup": cleanup, "evidence_path": evidence_path, "failure_record_error": failure_record.err().as_ref().map(error_json)});
                Err(error)
            }
        }?;
        let artifact = evidence.finish()?;
        Ok(RttCaptureReport {
            schema_version: "embedded-debugger.rtt-capture.v1",
            scope: "bounded_rtt_capture",
            capture_id,
            plan: plan.clone(),
            session,
            channel: completion.0,
            started_at,
            finished_at,
            elapsed_ms: elapsed,
            stop_reason: completion.4,
            bytes_captured: completion.1,
            chunk_count: completion.2,
            next_cursor: completion.1,
            payload_sha256: completion.3,
            channel_stopped: true,
            disconnected: true,
            complete: true,
            hardware_access: self.backend.name() != "replay",
            evidence: artifact,
        })
    }
}

struct EvidenceWriter {
    file: std::fs::File,
    path: String,
    bytes: u64,
    hash: Sha256,
}

impl EvidenceWriter {
    fn create(path: &Path) -> Result<Self> {
        let file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(path)
            .map_err(|error| {
                if error.kind() == std::io::ErrorKind::AlreadyExists {
                    DebugError::output_exists(&path.to_string_lossy())
                } else {
                    DebugError::io("create RTT evidence", path.to_str(), &error)
                }
            })?;
        Ok(Self {
            file,
            path: path.to_string_lossy().into_owned(),
            bytes: 0,
            hash: Sha256::new(),
        })
    }
    fn record(&mut self, value: &Value) -> Result<()> {
        let mut record = value.clone();
        record
            .as_object_mut()
            .expect("RTT record is an object")
            .entry("schema_version")
            .or_insert_with(|| json!("embedded-debugger.rtt-evidence.v1"));
        let mut bytes = serde_json::to_vec(&record).expect("RTT evidence serializes");
        bytes.push(b'\n');
        self.file
            .write_all(&bytes)
            .and_then(|_| self.file.flush())
            .map_err(|error| DebugError::io("write RTT evidence", Some(&self.path), &error))?;
        self.bytes += bytes.len() as u64;
        self.hash.update(bytes);
        Ok(())
    }
    fn finish(self) -> Result<ArtifactReference> {
        self.file
            .sync_all()
            .map_err(|error| DebugError::io("sync RTT evidence", Some(&self.path), &error))?;
        Ok(ArtifactReference {
            kind: "rtt_jsonl".into(),
            path: self.path,
            size: self.bytes,
            sha256: hex::encode(self.hash.finalize()),
        })
    }
}

pub fn unsupported(backend: &str) -> DebugError {
    DebugError::new(
        ErrorCode::CapabilityUnavailable,
        "selected backend/target does not support bounded RTT capture",
        6,
        json!({"backend": backend, "capability": "rtt"}),
    )
}

pub(crate) fn protocol_error(message: &str, details: Value) -> DebugError {
    DebugError::new(ErrorCode::ProtocolError, message, 6, details)
}
fn timestamp() -> String {
    Utc::now().to_rfc3339_opts(SecondsFormat::Millis, true)
}

fn error_json(error: &DebugError) -> Value {
    json!({"code": error.code, "message": error.message, "retryable": error.retryable, "exit_code": error.exit_code, "details": error.details})
}
fn elapsed_ms(start: Instant) -> u64 {
    start.elapsed().as_millis().try_into().unwrap_or(u64::MAX)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::backend::{
        probe_rs::ProbeRsBackend,
        replay::{ReplayBackend, ReplayFixture},
    };
    use tempfile::tempdir;

    fn fixture() -> ReplayFixture {
        serde_json::from_str(include_str!("../examples/replay/stm32g4.json")).unwrap()
    }
    fn selection() -> RttSelection {
        RttSelection {
            core: 0,
            control_block: Address(0x20000100),
            channel: 0,
        }
    }
    fn limits(bytes: u64) -> RttCaptureLimits {
        RttCaptureLimits {
            duration_ms: 30,
            maximum_bytes: bytes,
            poll_interval_ms: 1,
        }
    }
    fn plan(service: &RttService<ReplayBackend>, bytes: u64) -> RttPlan {
        let f = fixture();
        service
            .plan(&f.probe.id, &f.target.name, &selection(), limits(bytes))
            .unwrap()
    }
    fn events(path: &Path) -> Vec<Value> {
        std::fs::read_to_string(path)
            .unwrap()
            .lines()
            .map(|line| serde_json::from_str(line).unwrap())
            .collect()
    }

    #[test]
    fn capture_evidence_is_lossless_hashed_ordered_and_cleanup_is_complete() {
        let f = fixture();
        f.validate().unwrap();
        let expected = f.rtt_channels[0]
            .chunks
            .iter()
            .flat_map(|chunk| hex::decode(chunk).unwrap())
            .collect::<Vec<_>>();
        let mut service = RttService::new(ReplayBackend::new(f));
        let plan = plan(&service, expected.len() as u64);
        let dir = tempdir().unwrap();
        let path = dir.path().join("rtt.jsonl");
        let report = service.capture(&plan, &plan.confirm_digest, &path).unwrap();
        assert_eq!(report.stop_reason, "byte_limit");
        assert_eq!(report.bytes_captured, expected.len() as u64);
        assert!(report.complete && report.channel_stopped && report.disconnected);
        assert!(!report.hardware_access);
        assert_eq!(
            report.payload_sha256,
            hex::encode(Sha256::digest(&expected))
        );
        let bytes = std::fs::read(&path).unwrap();
        assert_eq!(report.evidence.sha256, hex::encode(Sha256::digest(&bytes)));
        assert_eq!(report.evidence.size, bytes.len() as u64);
        let records = events(&path);
        assert_eq!(records.first().unwrap()["event"], "capture.started");
        assert_eq!(records.last().unwrap()["event"], "capture.finished");
        let mut restored = Vec::new();
        let mut last_ms = 0;
        let mut sequence = 0;
        for event in records.iter().filter(|event| event["event"] == "rtt.chunk") {
            assert_eq!(event["sequence"], sequence);
            assert_eq!(event["cursor"], restored.len() as u64);
            let current_ms = event["elapsed_ms"].as_u64().unwrap();
            assert!(current_ms >= last_ms);
            last_ms = current_ms;
            assert!(
                chrono::DateTime::parse_from_rfc3339(event["timestamp"].as_str().unwrap()).is_ok()
            );
            restored.extend(hex::decode(event["data"].as_str().unwrap()).unwrap());
            assert_eq!(event["next_cursor"], restored.len() as u64);
            sequence += 1;
        }
        assert_eq!(restored, expected);
        assert_eq!(sequence, report.chunk_count);
        service
            .capture(&plan, &plan.confirm_digest, &dir.path().join("next.jsonl"))
            .unwrap();
    }

    #[test]
    fn exact_byte_limit_clips_a_chunk_and_does_not_read_beyond_budget() {
        let mut service = RttService::new(ReplayBackend::new(fixture()));
        let plan = plan(&service, 3);
        let dir = tempdir().unwrap();
        let path = dir.path().join("clip.jsonl");
        let report = service.capture(&plan, &plan.confirm_digest, &path).unwrap();
        assert_eq!(report.bytes_captured, 3);
        assert_eq!(report.chunk_count, 1);
        let records = events(&path);
        assert_eq!(
            records
                .iter()
                .find(|event| event["event"] == "rtt.chunk")
                .unwrap()["data"],
            hex::encode(b"EAT")
        );
    }

    #[test]
    fn empty_channel_finishes_by_duration_without_writes_or_fabricated_data() {
        let mut f = fixture();
        f.rtt_channels[0].chunks.clear();
        let mut service = RttService::new(ReplayBackend::new(f));
        let plan = plan(&service, 100);
        let dir = tempdir().unwrap();
        let path = dir.path().join("empty.jsonl");
        let report = service.capture(&plan, &plan.confirm_digest, &path).unwrap();
        assert_eq!(report.stop_reason, "duration_limit");
        assert_eq!(report.bytes_captured, 0);
        assert_eq!(report.chunk_count, 0);
        assert!(report.elapsed_ms >= 30);
        assert!(
            !events(&path)
                .iter()
                .any(|event| event["event"] == "rtt.chunk")
        );
    }

    #[test]
    fn read_failure_keeps_partial_evidence_and_attempts_both_cleanup_steps() {
        let mut f = fixture();
        f.rtt_channels[0].fail_read_at = Some(1);
        let mut service = RttService::new(ReplayBackend::new(f));
        let plan = plan(&service, 100);
        let dir = tempdir().unwrap();
        let path = dir.path().join("failed.jsonl");
        let error = service
            .capture(&plan, &plan.confirm_digest, &path)
            .unwrap_err();
        assert_eq!(error.code, ErrorCode::ProtocolError);
        assert!(!error.retryable);
        assert_eq!(error.details["cause"]["read_index"], 1);
        assert_eq!(error.details["cleanup"]["channel_stopped"], true);
        assert_eq!(error.details["cleanup"]["disconnected"], true);
        let records = events(&path);
        assert_eq!(
            records
                .iter()
                .filter(|event| event["event"] == "rtt.chunk")
                .count(),
            1
        );
        assert_eq!(records.last().unwrap()["ok"], false);
        let later = service
            .capture(&plan, &plan.confirm_digest, &dir.path().join("later.jsonl"))
            .unwrap_err();
        assert_eq!(later.details["cause"]["read_index"], 1);
    }

    #[test]
    fn failed_channel_stop_still_disconnects_and_does_not_claim_complete_success() {
        let mut f = fixture();
        f.rtt_channels[0].fail_stop = true;
        let mut service = RttService::new(ReplayBackend::new(f));
        let plan = plan(&service, 3);
        let dir = tempdir().unwrap();
        let path = dir.path().join("stop-failed.jsonl");
        let error = service
            .capture(&plan, &plan.confirm_digest, &path)
            .unwrap_err();
        assert_eq!(error.details["cleanup"]["channel_stopped"], false);
        assert_eq!(error.details["cleanup"]["disconnected"], true);
        assert_eq!(events(&path).last().unwrap()["ok"], false);
    }

    #[test]
    fn wrong_probe_preserves_attach_failure_evidence_without_consuming_a_channel() {
        let mut service = RttService::new(ReplayBackend::new(fixture()));
        let plan = service
            .plan(
                "replay:missing-probe",
                &fixture().target.name,
                &selection(),
                limits(10),
            )
            .unwrap();
        let dir = tempdir().unwrap();
        let path = dir.path().join("attach-failed.jsonl");
        let error = service
            .capture(&plan, &plan.confirm_digest, &path)
            .unwrap_err();
        assert_eq!(error.code, ErrorCode::ProbeUnavailable);
        let records = events(&path);
        assert_eq!(records.len(), 2);
        assert_eq!(records[1]["stage"], "attach");
        assert_eq!(records[1]["attach_completed"], false);
    }

    #[test]
    fn altered_confirmation_and_existing_evidence_fail_before_consumption() {
        let mut service = RttService::new(ReplayBackend::new(fixture()));
        let plan = plan(&service, 5);
        let dir = tempdir().unwrap();
        let path = dir.path().join("keep.jsonl");
        assert_eq!(
            service.capture(&plan, "wrong", &path).unwrap_err().code,
            ErrorCode::ConfirmationMismatch
        );
        assert!(!path.exists());
        let mut changed = plan.clone();
        changed.limits.maximum_bytes = 6;
        assert_eq!(
            service
                .capture(&changed, &plan.confirm_digest, &path)
                .unwrap_err()
                .code,
            ErrorCode::ConfirmationMismatch
        );
        assert!(!path.exists());
        std::fs::write(&path, b"preserve").unwrap();
        assert_eq!(
            service
                .capture(&plan, &plan.confirm_digest, &path)
                .unwrap_err()
                .code,
            ErrorCode::OutputExists
        );
        assert_eq!(std::fs::read(&path).unwrap(), b"preserve");
    }

    #[test]
    fn planning_binds_every_identity_and_limit_without_requiring_connected_hardware() {
        let service = RttService::new(ProbeRsBackend::new("nRF52840_xxAA").unwrap());
        let target = "nRF52840_xxAA";
        let base = service
            .plan(
                "1366:1061:explicit-serial",
                target,
                &selection(),
                limits(20),
            )
            .unwrap();
        assert!(!base.hardware_access && !base.hardware_acceptance_verified);
        assert!(base.effects.target_rtt_read_cursor_write);
        assert!(!base.effects.post_disconnect_core_state_verified);
        for (probe, core, address, channel, duration, bytes, poll) in [
            ("other", 0, 0x20000100, 0, 30, 20, 1),
            ("1366:1061:explicit-serial", 0, 0x20000104, 0, 30, 20, 1),
            ("1366:1061:explicit-serial", 0, 0x20000100, 1, 30, 20, 1),
            ("1366:1061:explicit-serial", 0, 0x20000100, 0, 31, 20, 1),
            ("1366:1061:explicit-serial", 0, 0x20000100, 0, 30, 21, 1),
            ("1366:1061:explicit-serial", 0, 0x20000100, 0, 30, 20, 2),
        ] {
            let next = service
                .plan(
                    probe,
                    target,
                    &RttSelection {
                        core,
                        control_block: Address(address),
                        channel,
                    },
                    RttCaptureLimits {
                        duration_ms: duration,
                        maximum_bytes: bytes,
                        poll_interval_ms: poll,
                    },
                )
                .unwrap();
            assert_ne!(next.confirm_digest, base.confirm_digest);
        }
        assert!(
            service
                .plan(
                    "probe",
                    target,
                    &RttSelection {
                        core: 1,
                        ..selection()
                    },
                    limits(20)
                )
                .is_err()
        );
        assert!(
            service
                .plan("probe", "esp32s3", &selection(), limits(20))
                .is_err()
        );
        assert!(
            service
                .plan(
                    "probe",
                    target,
                    &RttSelection {
                        control_block: Address(0x40000000),
                        ..selection()
                    },
                    limits(20)
                )
                .is_err()
        );
        assert!(
            RttService::new(ProbeRsBackend::new("esp32s3").unwrap())
                .plan("probe", "esp32s3", &selection(), limits(20))
                .is_err()
        );
    }

    #[test]
    fn invalid_limits_and_channel_layout_are_rejected() {
        for bounds in [
            limits(0),
            limits(MAX_CAPTURE_BYTES + 1),
            RttCaptureLimits {
                duration_ms: 60001,
                ..limits(1)
            },
            RttCaptureLimits {
                poll_interval_ms: 31,
                ..limits(1)
            },
        ] {
            assert!(bounds.validate().is_err());
        }
        for select in [
            RttSelection {
                channel: 16,
                ..selection()
            },
            RttSelection {
                control_block: Address(0x20000101),
                ..selection()
            },
            RttSelection {
                control_block: Address(0),
                ..selection()
            },
        ] {
            assert!(select.validate().is_err());
        }
        let mut f = fixture();
        f.rtt_channels[0].buffer_start = Address(0x40000000);
        assert!(f.validate().is_err());
        let mut f = fixture();
        f.rtt_channels[0].chunks = vec!["not-hex".into()];
        assert!(f.validate().is_err());
        let mut f = fixture();
        f.rtt_channels.push(f.rtt_channels[0].clone());
        assert!(f.validate().is_err());
    }

    #[test]
    fn chunk_limit_prevents_tiny_chunks_from_expanding_evidence_without_bound() {
        let mut f = fixture();
        f.rtt_channels[0].chunks = vec!["61".into(); MAX_CAPTURE_CHUNKS as usize + 1];
        let mut service = RttService::new(ReplayBackend::new(f));
        let plan = service
            .plan(
                &fixture().probe.id,
                &fixture().target.name,
                &selection(),
                RttCaptureLimits {
                    duration_ms: 60000,
                    maximum_bytes: MAX_CAPTURE_BYTES,
                    poll_interval_ms: 1,
                },
            )
            .unwrap();
        let dir = tempdir().unwrap();
        let report = service
            .capture(
                &plan,
                &plan.confirm_digest,
                &dir.path().join("chunks.jsonl"),
            )
            .unwrap();
        assert_eq!(report.stop_reason, "chunk_limit");
        assert_eq!(report.chunk_count, MAX_CAPTURE_CHUNKS);
        assert_eq!(report.bytes_captured, MAX_CAPTURE_CHUNKS);
    }
}
