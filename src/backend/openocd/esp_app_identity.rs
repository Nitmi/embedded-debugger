use std::{
    fs::{self, File},
    io::Read,
    path::{Path, PathBuf},
};

use object::{
    Architecture, BinaryFormat, Endianness, Object, ObjectKind, ObjectSection, SectionFlags, elf,
    read::File as ObjectFile,
};
use serde::Serialize;
use serde_json::json;
use sha2::{Digest, Sha256};

use super::{
    OpenOcdGdbSessionOptions, OpenOcdMemorySnapshotOptions, OpenOcdMemorySnapshotPlan,
    OpenOcdMemorySnapshotTestReport, plan_memory_snapshot, test_memory_snapshot,
};
use crate::{
    SCHEMA_VERSION,
    error::{DebugError, ErrorCode, Result, SuggestedAction},
    model::{Address, MemoryRegionKind},
};

pub const ESP_APP_DESCRIPTOR_BYTES: usize = 256;
pub const ESP_APP_DESCRIPTOR_ELF_SHA256_OFFSET: usize = 0x90;
pub const ESP_APP_DESCRIPTOR_ELF_SHA256_LENGTH: usize = 32;
const ESP_APP_DESCRIPTOR_MAGIC: u32 = 0xabcd_5432;
const MAX_ESP_APP_IDENTITY_ELF_BYTES: u64 = 64 * 1024 * 1024;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OpenOcdEspAppIdentityOptions {
    pub session: OpenOcdGdbSessionOptions,
    pub elf: PathBuf,
    pub region_start: Address,
    pub region_length_bytes: u64,
    pub region_kind: MemoryRegionKind,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct OpenOcdEspAppIdentityPlan {
    pub backend: String,
    pub operation: String,
    pub risk: String,
    pub complete: bool,
    pub memory: OpenOcdMemorySnapshotPlan,
    pub elf: OpenOcdEspAppIdentityElfInspection,
    pub identity_policy: OpenOcdEspAppIdentityPolicy,
    pub effects: OpenOcdEspAppIdentityEffects,
    pub confirmation_boundary: OpenOcdEspAppIdentityConfirmationBoundary,
    pub confirm_digest: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct OpenOcdEspAppIdentityElfInspection {
    pub resolved: String,
    pub bytes: u64,
    pub maximum_bytes: u64,
    pub sha256: String,
    pub format: String,
    pub kind: String,
    pub architecture: String,
    pub endianness: String,
    pub section_name: String,
    pub section_address: Address,
    pub section_length_bytes: u64,
    pub section_alignment_bytes: u64,
    pub section_allocated: bool,
    pub section_writable: bool,
    pub source_descriptor_sha256: String,
    pub source_descriptor: OpenOcdEspAppDescriptor,
    pub expected_descriptor_sha256: String,
    pub expected_descriptor_hex: String,
    pub expected_descriptor: OpenOcdEspAppDescriptor,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct OpenOcdEspAppDescriptor {
    pub magic: String,
    pub secure_version: u32,
    pub version: String,
    pub project_name: String,
    pub build_time: String,
    pub build_date: String,
    pub idf_version: String,
    pub app_elf_sha256: String,
    pub minimum_efuse_revision: u16,
    pub maximum_efuse_revision: u16,
    pub mmu_page_size: u8,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct OpenOcdEspAppIdentityPolicy {
    pub object_parser: String,
    pub descriptor_layout: String,
    pub image_generation_rule: String,
    pub required_file_format: String,
    pub required_object_kind: String,
    pub allowed_architectures: Vec<String>,
    pub required_endianness: String,
    pub required_section_name: String,
    pub required_section_count: u64,
    pub descriptor_length_bytes: u64,
    pub descriptor_magic: String,
    pub elf_sha256_offset_bytes: u64,
    pub elf_sha256_length_bytes: u64,
    pub source_elf_sha256_slot_required_zero: bool,
    pub expected_descriptor_derivation: String,
    pub target_comparison: String,
    pub declared_region_kind_required: MemoryRegionKind,
    pub runtime_firmware_identity_semantics: String,
    pub cryptographic_authenticity_claimed: bool,
    pub secure_boot_verification_claimed: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct OpenOcdEspAppIdentityEffects {
    pub base_memory_snapshot_effects_apply: bool,
    pub exact_host_elf_read_requested: bool,
    pub in_process_elf_and_descriptor_parsing_requested: bool,
    pub exact_target_descriptor_read_requested: bool,
    pub gdb_symbol_or_executable_loading_requested: bool,
    pub memory_write_requested: bool,
    pub breakpoint_or_watchpoint_requested: bool,
    pub flash_command_requested: bool,
    pub source_file_read_requested: bool,
    pub network_access_requested: bool,
    pub notes: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct OpenOcdEspAppIdentityConfirmationBoundary {
    pub base_memory_confirm_digest_bound: bool,
    pub canonical_elf_path_bound: bool,
    pub exact_elf_bytes_and_hash_bound: bool,
    pub descriptor_section_address_and_layout_bound: bool,
    pub source_and_expected_descriptor_hashes_bound: bool,
    pub expected_descriptor_bytes_bound: bool,
    pub declared_nvm_region_bound: bool,
    pub parser_versions_and_derivation_rule_bound: bool,
    pub runtime_firmware_identity_bound: bool,
    pub target_memory_map_semantics_bound: bool,
    pub runtime_adapter_identity_bound: bool,
    pub cryptographic_authenticity_bound: bool,
    pub secure_boot_state_bound: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct OpenOcdEspAppIdentityTestReport {
    pub backend: String,
    pub scope: String,
    pub risk: String,
    pub complete: bool,
    pub confirm_digest: String,
    pub memory: OpenOcdMemorySnapshotTestReport,
    pub elf: OpenOcdEspAppIdentityElfInspection,
    pub identity_policy: OpenOcdEspAppIdentityPolicy,
    pub comparison: OpenOcdEspAppIdentityComparison,
    pub effects: OpenOcdEspAppIdentityEffects,
    pub confirmation_boundary: OpenOcdEspAppIdentityConfirmationBoundary,
    pub capabilities: OpenOcdEspAppIdentityCapabilities,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct OpenOcdEspAppIdentityComparison {
    pub target_descriptor_sha256: String,
    pub target_descriptor_hex: String,
    pub target_descriptor: Option<OpenOcdEspAppDescriptor>,
    pub target_descriptor_parse_error: Option<String>,
    pub exact_expected_descriptor_match: bool,
    pub source_bytes_outside_elf_sha256_slot_match: bool,
    pub embedded_elf_sha256_match: bool,
    pub runtime_firmware_identity_verified: bool,
    pub cryptographic_authenticity_verified: bool,
    pub secure_boot_verified: bool,
    pub target_memory_map_semantics_verified: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct OpenOcdEspAppIdentityCapabilities {
    pub bounded_memory_read: bool,
    pub esp_app_descriptor_parsing: bool,
    pub runtime_firmware_identity_verification: bool,
    pub cryptographic_authenticity_verification: bool,
    pub secure_boot_verification: bool,
    pub memory_write: bool,
    pub symbol_loading: bool,
    pub breakpoints: bool,
    pub watchpoints: bool,
    pub general_execution_control: bool,
    pub flash: bool,
    pub arbitrary_commands: bool,
}

#[derive(Debug, Serialize)]
struct IdentityConfirmationInput<'a> {
    schema_version: &'static str,
    operation: &'static str,
    backend: &'static str,
    base_memory_confirm_digest: &'a str,
    elf: &'a OpenOcdEspAppIdentityElfInspection,
    identity_policy: &'a OpenOcdEspAppIdentityPolicy,
    effects: &'a OpenOcdEspAppIdentityEffects,
    confirmation_boundary: &'a OpenOcdEspAppIdentityConfirmationBoundary,
}

struct PreparedIdentity {
    plan: OpenOcdEspAppIdentityPlan,
    memory_options: OpenOcdMemorySnapshotOptions,
    expected_descriptor: [u8; ESP_APP_DESCRIPTOR_BYTES],
}

pub fn plan_esp_app_identity(
    options: &OpenOcdEspAppIdentityOptions,
) -> Result<OpenOcdEspAppIdentityPlan> {
    prepare_identity(options).map(|prepared| prepared.plan)
}

pub fn test_esp_app_identity(
    options: &OpenOcdEspAppIdentityOptions,
    confirm_digest: &str,
) -> Result<OpenOcdEspAppIdentityTestReport> {
    let prepared = prepare_identity(options)?;
    if prepared.plan.confirm_digest != confirm_digest {
        return Err(identity_confirmation_error(
            &prepared.plan.confirm_digest,
            confirm_digest,
        ));
    }

    let base_digest = prepared.plan.memory.confirm_digest.clone();
    let memory = test_memory_snapshot(&prepared.memory_options, &base_digest)?;
    let target_bytes = hex::decode(&memory.exchange.snapshot.data).map_err(|error| {
        DebugError::new(
            ErrorCode::ProtocolError,
            "decode confirmed ESP app descriptor snapshot failed",
            6,
            json!({
                "encoding": memory.exchange.snapshot.encoding,
                "error": bounded_text(&error.to_string()),
                "memory": memory,
            }),
        )
    })?;
    let comparison = compare_descriptor(&prepared.expected_descriptor, &target_bytes);
    if !comparison.runtime_firmware_identity_verified {
        return Err(DebugError::verification(
            "target ESP app descriptor does not match the descriptor derived from the confirmed ELF",
            json!({
                "comparison": comparison,
                "memory": memory,
                "retry_attempted": false,
            }),
        ));
    }

    Ok(OpenOcdEspAppIdentityTestReport {
        backend: prepared.plan.backend,
        scope: "confirmed_esp_app_descriptor_runtime_firmware_identity".to_string(),
        risk: prepared.plan.risk,
        complete: true,
        confirm_digest: prepared.plan.confirm_digest,
        memory,
        elf: prepared.plan.elf,
        identity_policy: prepared.plan.identity_policy,
        comparison,
        effects: prepared.plan.effects,
        confirmation_boundary: prepared.plan.confirmation_boundary,
        capabilities: identity_capabilities(),
    })
}

fn prepare_identity(options: &OpenOcdEspAppIdentityOptions) -> Result<PreparedIdentity> {
    validate_declared_region(options)?;
    super::session::validate_session_options(&options.session)?;
    let (resolved, bytes) = read_bounded_elf(&options.elf)?;
    let (elf, expected_descriptor) = inspect_elf(&resolved, &bytes)?;
    validate_descriptor_containment(options, elf.section_address)?;

    let memory_options = OpenOcdMemorySnapshotOptions {
        session: options.session.clone(),
        address: elf.section_address,
        length_bytes: ESP_APP_DESCRIPTOR_BYTES as u64,
        region_start: options.region_start,
        region_length_bytes: options.region_length_bytes,
        region_kind: options.region_kind,
    };
    let memory = plan_memory_snapshot(&memory_options)?;
    let identity_policy = identity_policy();
    let effects = identity_effects();
    let confirmation_boundary = identity_confirmation_boundary();
    let confirmation = IdentityConfirmationInput {
        schema_version: SCHEMA_VERSION,
        operation: "openocd.esp_app_identity.test",
        backend: "openocd",
        base_memory_confirm_digest: &memory.confirm_digest,
        elf: &elf,
        identity_policy: &identity_policy,
        effects: &effects,
        confirmation_boundary: &confirmation_boundary,
    };
    let confirm_digest = hex::encode(Sha256::digest(
        serde_json::to_vec(&confirmation).expect("ESP app identity confirmation input serializes"),
    ));

    Ok(PreparedIdentity {
        plan: OpenOcdEspAppIdentityPlan {
            backend: "openocd".to_string(),
            operation: "openocd.esp_app_identity.test".to_string(),
            risk: memory.risk.clone(),
            complete: true,
            memory,
            elf,
            identity_policy,
            effects,
            confirmation_boundary,
            confirm_digest,
        },
        memory_options,
        expected_descriptor,
    })
}

fn validate_declared_region(options: &OpenOcdEspAppIdentityOptions) -> Result<()> {
    if options.region_kind != MemoryRegionKind::Nvm {
        return Err(DebugError::config(
            "ESP app identity requires an explicitly declared NVM region",
            json!({
                "region_kind": options.region_kind,
                "required_region_kind": MemoryRegionKind::Nvm,
            }),
        ));
    }
    if options.region_length_bytes == 0 {
        return Err(DebugError::config(
            "declared ESP app identity NVM region must be non-empty",
            json!({"region_length_bytes": options.region_length_bytes}),
        ));
    }
    options
        .region_start
        .0
        .checked_add(options.region_length_bytes)
        .ok_or_else(|| {
            DebugError::config(
                "declared ESP app identity NVM region overflows the address space",
                json!({
                    "region_start": options.region_start,
                    "region_length_bytes": options.region_length_bytes,
                }),
            )
        })?;
    Ok(())
}

fn validate_descriptor_containment(
    options: &OpenOcdEspAppIdentityOptions,
    address: Address,
) -> Result<()> {
    let descriptor_end = address
        .0
        .checked_add(ESP_APP_DESCRIPTOR_BYTES as u64)
        .expect("a four-byte-aligned ELF section cannot overflow by 256 bytes");
    let region_end = options
        .region_start
        .0
        .checked_add(options.region_length_bytes)
        .expect("declared region overflow is rejected first");
    if address.0 < options.region_start.0 || descriptor_end > region_end {
        return Err(DebugError::config(
            "ESP app descriptor is not contained in the declared NVM region",
            json!({
                "descriptor_address": address,
                "descriptor_length_bytes": ESP_APP_DESCRIPTOR_BYTES,
                "descriptor_end_exclusive": Address(descriptor_end),
                "region_start": options.region_start,
                "region_length_bytes": options.region_length_bytes,
                "region_end_exclusive": Address(region_end),
            }),
        ));
    }
    Ok(())
}

fn read_bounded_elf(requested: &Path) -> Result<(PathBuf, Vec<u8>)> {
    let requested_display = stable_path(requested, "requested")?;
    let resolved = fs::canonicalize(requested).map_err(|source| {
        DebugError::config(
            "resolve ESP app identity ELF failed",
            json!({"path": requested_display, "cause": source.to_string()}),
        )
    })?;
    let resolved_display = stable_path(&resolved, "resolved")?;
    let file = File::open(&resolved).map_err(|source| {
        DebugError::config(
            "open ESP app identity ELF failed",
            json!({"path": resolved_display, "cause": source.to_string()}),
        )
    })?;
    let metadata = file.metadata().map_err(|source| {
        DebugError::config(
            "inspect ESP app identity ELF failed",
            json!({"path": resolved_display, "cause": source.to_string()}),
        )
    })?;
    if !metadata.is_file() {
        return Err(DebugError::config(
            "ESP app identity ELF is not a regular file",
            json!({"path": resolved_display}),
        ));
    }
    if metadata.len() == 0 || metadata.len() > MAX_ESP_APP_IDENTITY_ELF_BYTES {
        return Err(DebugError::config(
            "ESP app identity ELF size is outside the supported range",
            json!({
                "path": resolved_display,
                "bytes": metadata.len(),
                "minimum_bytes": 1,
                "maximum_bytes": MAX_ESP_APP_IDENTITY_ELF_BYTES,
            }),
        ));
    }
    let mut bytes = Vec::with_capacity(usize::try_from(metadata.len()).unwrap_or(0));
    file.take(MAX_ESP_APP_IDENTITY_ELF_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(|source| {
            DebugError::config(
                "read ESP app identity ELF failed",
                json!({"path": resolved_display, "cause": source.to_string()}),
            )
        })?;
    if bytes.len() as u64 != metadata.len() {
        return Err(DebugError::config(
            "ESP app identity ELF changed while it was being read",
            json!({
                "path": resolved_display,
                "metadata_bytes": metadata.len(),
                "read_bytes": bytes.len(),
            }),
        ));
    }
    Ok((resolved, bytes))
}

fn inspect_elf(
    resolved: &Path,
    bytes: &[u8],
) -> Result<(
    OpenOcdEspAppIdentityElfInspection,
    [u8; ESP_APP_DESCRIPTOR_BYTES],
)> {
    let object = ObjectFile::parse(bytes)
        .map_err(|error| object_error("parse ESP app identity ELF", error))?;
    if object.format() != BinaryFormat::Elf {
        return Err(DebugError::config(
            "ESP app identity input is not an ELF file",
            json!({"observed_format": format!("{:?}", object.format())}),
        ));
    }
    if object.kind() != ObjectKind::Executable {
        return Err(DebugError::config(
            "ESP app identity ELF is not an executable image",
            json!({"observed_kind": format!("{:?}", object.kind())}),
        ));
    }
    if object.endianness() != Endianness::Little {
        return Err(DebugError::config(
            "ESP app identity ELF must be little-endian",
            json!({"observed_endianness": format!("{:?}", object.endianness())}),
        ));
    }
    if !matches!(
        object.architecture(),
        Architecture::Xtensa | Architecture::Riscv32
    ) {
        return Err(DebugError::config(
            "ESP app identity ELF architecture is not supported",
            json!({"observed_architecture": architecture_name(object.architecture())}),
        ));
    }

    let mut matches = object
        .sections()
        .filter_map(|section| match section.name() {
            Ok(".flash.appdesc") => Some(Ok(section)),
            Ok(_) => None,
            Err(error) => Some(Err(object_error("read ELF section name", error))),
        })
        .collect::<Result<Vec<_>>>()?;
    if matches.len() != 1 {
        return Err(DebugError::config(
            "ESP app identity ELF must contain exactly one .flash.appdesc section",
            json!({"observed_section_count": matches.len(), "required_section_count": 1}),
        ));
    }
    let section = matches.pop().expect("one section was required");
    if section.size() != ESP_APP_DESCRIPTOR_BYTES as u64 {
        return Err(DebugError::config(
            "ESP app descriptor section has the wrong size",
            json!({
                "observed_length_bytes": section.size(),
                "required_length_bytes": ESP_APP_DESCRIPTOR_BYTES,
            }),
        ));
    }
    if section.address() == 0 || section.address() % 4 != 0 {
        return Err(DebugError::config(
            "ESP app descriptor section address must be non-zero and four-byte aligned",
            json!({"section_address": Address(section.address())}),
        ));
    }
    let (section_allocated, section_writable) = match section.flags() {
        SectionFlags::Elf { sh_flags } => (
            sh_flags & u64::from(elf::SHF_ALLOC) != 0,
            sh_flags & u64::from(elf::SHF_WRITE) != 0,
        ),
        _ => (false, false),
    };
    if !section_allocated || section_writable {
        return Err(DebugError::config(
            "ESP app descriptor section must be allocated and read-only",
            json!({
                "section_allocated": section_allocated,
                "section_writable": section_writable,
            }),
        ));
    }
    let source = section
        .data()
        .map_err(|error| object_error("read ESP app descriptor section", error))?;
    let mut source_descriptor = [0_u8; ESP_APP_DESCRIPTOR_BYTES];
    source_descriptor.copy_from_slice(source);
    let source_parsed = parse_descriptor(&source_descriptor).map_err(|message| {
        DebugError::config(
            "parse source ESP app descriptor failed",
            json!({"error": message}),
        )
    })?;
    let source_hash = &source_descriptor[ESP_APP_DESCRIPTOR_ELF_SHA256_OFFSET
        ..ESP_APP_DESCRIPTOR_ELF_SHA256_OFFSET + ESP_APP_DESCRIPTOR_ELF_SHA256_LENGTH];
    if source_hash.iter().any(|byte| *byte != 0) {
        return Err(DebugError::config(
            "source ESP app descriptor ELF SHA-256 slot must be zero before image generation",
            json!({"observed_app_elf_sha256": hex::encode(source_hash)}),
        ));
    }

    let elf_sha256 = Sha256::digest(bytes);
    let mut expected_descriptor = source_descriptor;
    expected_descriptor[ESP_APP_DESCRIPTOR_ELF_SHA256_OFFSET
        ..ESP_APP_DESCRIPTOR_ELF_SHA256_OFFSET + ESP_APP_DESCRIPTOR_ELF_SHA256_LENGTH]
        .copy_from_slice(&elf_sha256);
    let expected_parsed = parse_descriptor(&expected_descriptor).map_err(|message| {
        DebugError::config(
            "parse derived ESP app descriptor failed",
            json!({"error": message}),
        )
    })?;

    Ok((
        OpenOcdEspAppIdentityElfInspection {
            resolved: stable_path(resolved, "resolved")?,
            bytes: bytes.len() as u64,
            maximum_bytes: MAX_ESP_APP_IDENTITY_ELF_BYTES,
            sha256: hex::encode(elf_sha256),
            format: "elf".to_string(),
            kind: "executable".to_string(),
            architecture: architecture_name(object.architecture()),
            endianness: "little".to_string(),
            section_name: ".flash.appdesc".to_string(),
            section_address: Address(section.address()),
            section_length_bytes: section.size(),
            section_alignment_bytes: section.align(),
            section_allocated,
            section_writable,
            source_descriptor_sha256: hex::encode(Sha256::digest(source_descriptor)),
            source_descriptor: source_parsed,
            expected_descriptor_sha256: hex::encode(Sha256::digest(expected_descriptor)),
            expected_descriptor_hex: hex::encode(expected_descriptor),
            expected_descriptor: expected_parsed,
        },
        expected_descriptor,
    ))
}

fn parse_descriptor(
    bytes: &[u8; ESP_APP_DESCRIPTOR_BYTES],
) -> std::result::Result<OpenOcdEspAppDescriptor, String> {
    let magic = read_u32(bytes, 0);
    if magic != ESP_APP_DESCRIPTOR_MAGIC {
        return Err(format!(
            "descriptor magic 0x{magic:08X} does not match 0x{ESP_APP_DESCRIPTOR_MAGIC:08X}"
        ));
    }
    Ok(OpenOcdEspAppDescriptor {
        magic: format!("0x{magic:08X}"),
        secure_version: read_u32(bytes, 4),
        version: fixed_ascii(bytes, 16, 32, "version")?,
        project_name: fixed_ascii(bytes, 48, 32, "project_name")?,
        build_time: fixed_ascii(bytes, 80, 16, "build_time")?,
        build_date: fixed_ascii(bytes, 96, 16, "build_date")?,
        idf_version: fixed_ascii(bytes, 112, 32, "idf_version")?,
        app_elf_sha256: hex::encode(
            &bytes[ESP_APP_DESCRIPTOR_ELF_SHA256_OFFSET
                ..ESP_APP_DESCRIPTOR_ELF_SHA256_OFFSET + ESP_APP_DESCRIPTOR_ELF_SHA256_LENGTH],
        ),
        minimum_efuse_revision: read_u16(bytes, 176),
        maximum_efuse_revision: read_u16(bytes, 178),
        mmu_page_size: bytes[180],
    })
}

fn fixed_ascii(
    bytes: &[u8; ESP_APP_DESCRIPTOR_BYTES],
    offset: usize,
    length: usize,
    field: &str,
) -> std::result::Result<String, String> {
    let raw = &bytes[offset..offset + length];
    let end = raw.iter().position(|byte| *byte == 0).unwrap_or(raw.len());
    if end < raw.len() && raw[end..].iter().any(|byte| *byte != 0) {
        return Err(format!(
            "descriptor field {field} has non-zero bytes after NUL"
        ));
    }
    if raw[..end].iter().any(|byte| !(0x20..=0x7e).contains(byte)) {
        return Err(format!("descriptor field {field} is not printable ASCII"));
    }
    Ok(String::from_utf8(raw[..end].to_vec()).expect("printable ASCII is always valid UTF-8"))
}

fn compare_descriptor(
    expected: &[u8; ESP_APP_DESCRIPTOR_BYTES],
    target: &[u8],
) -> OpenOcdEspAppIdentityComparison {
    let target_descriptor = <[u8; ESP_APP_DESCRIPTOR_BYTES]>::try_from(target).ok();
    let parsed = target_descriptor.as_ref().map(parse_descriptor).transpose();
    let (target_descriptor, target_descriptor_parse_error) = match parsed {
        Ok(descriptor) => (descriptor, None),
        Err(error) => (None, Some(error)),
    };
    let exact_expected_descriptor_match = target == expected;
    let source_bytes_outside_elf_sha256_slot_match = target.len() == expected.len()
        && target[..ESP_APP_DESCRIPTOR_ELF_SHA256_OFFSET]
            == expected[..ESP_APP_DESCRIPTOR_ELF_SHA256_OFFSET]
        && target[ESP_APP_DESCRIPTOR_ELF_SHA256_OFFSET + ESP_APP_DESCRIPTOR_ELF_SHA256_LENGTH..]
            == expected
                [ESP_APP_DESCRIPTOR_ELF_SHA256_OFFSET + ESP_APP_DESCRIPTOR_ELF_SHA256_LENGTH..];
    let embedded_elf_sha256_match = target.len() == expected.len()
        && target[ESP_APP_DESCRIPTOR_ELF_SHA256_OFFSET
            ..ESP_APP_DESCRIPTOR_ELF_SHA256_OFFSET + ESP_APP_DESCRIPTOR_ELF_SHA256_LENGTH]
            == expected[ESP_APP_DESCRIPTOR_ELF_SHA256_OFFSET
                ..ESP_APP_DESCRIPTOR_ELF_SHA256_OFFSET + ESP_APP_DESCRIPTOR_ELF_SHA256_LENGTH];
    let runtime_firmware_identity_verified =
        exact_expected_descriptor_match && target_descriptor.is_some();

    OpenOcdEspAppIdentityComparison {
        target_descriptor_sha256: hex::encode(Sha256::digest(target)),
        target_descriptor_hex: hex::encode(target),
        target_descriptor,
        target_descriptor_parse_error,
        exact_expected_descriptor_match,
        source_bytes_outside_elf_sha256_slot_match,
        embedded_elf_sha256_match,
        runtime_firmware_identity_verified,
        cryptographic_authenticity_verified: false,
        secure_boot_verified: false,
        target_memory_map_semantics_verified: false,
    }
}

fn identity_policy() -> OpenOcdEspAppIdentityPolicy {
    OpenOcdEspAppIdentityPolicy {
        object_parser: "object 0.39.1".to_string(),
        descriptor_layout: "ESP-IDF esp_app_desc_t v1, 256 bytes".to_string(),
        image_generation_rule:
            "espflash 4.5.0 IDF image rule: SHA-256 the complete input ELF and copy the 32-byte digest into app_elf_sha256"
                .to_string(),
        required_file_format: "elf".to_string(),
        required_object_kind: "executable".to_string(),
        allowed_architectures: vec!["xtensa".to_string(), "riscv32".to_string()],
        required_endianness: "little".to_string(),
        required_section_name: ".flash.appdesc".to_string(),
        required_section_count: 1,
        descriptor_length_bytes: ESP_APP_DESCRIPTOR_BYTES as u64,
        descriptor_magic: format!("0x{ESP_APP_DESCRIPTOR_MAGIC:08X}"),
        elf_sha256_offset_bytes: ESP_APP_DESCRIPTOR_ELF_SHA256_OFFSET as u64,
        elf_sha256_length_bytes: ESP_APP_DESCRIPTOR_ELF_SHA256_LENGTH as u64,
        source_elf_sha256_slot_required_zero: true,
        expected_descriptor_derivation:
            "copy the exact source section, replacing only bytes 0x90..0xB0 with the complete ELF SHA-256"
                .to_string(),
        target_comparison: "require an exact byte-for-byte match of all 256 target bytes"
            .to_string(),
        declared_region_kind_required: MemoryRegionKind::Nvm,
        runtime_firmware_identity_semantics:
            "non-adversarial build identity evidence from the target-mapped ESP app descriptor; not signed attestation"
                .to_string(),
        cryptographic_authenticity_claimed: false,
        secure_boot_verification_claimed: false,
    }
}

fn identity_effects() -> OpenOcdEspAppIdentityEffects {
    OpenOcdEspAppIdentityEffects {
        base_memory_snapshot_effects_apply: true,
        exact_host_elf_read_requested: true,
        in_process_elf_and_descriptor_parsing_requested: true,
        exact_target_descriptor_read_requested: true,
        gdb_symbol_or_executable_loading_requested: false,
        memory_write_requested: false,
        breakpoint_or_watchpoint_requested: false,
        flash_command_requested: false,
        source_file_read_requested: false,
        network_access_requested: false,
        notes: vec![
            "The nested memory plan retains all confirmed OpenOCD, GDB, attach, restoration, and configuration effects."
                .to_string(),
            "The only explicit target payload operation is one 256-byte read at the ELF-declared .flash.appdesc address."
                .to_string(),
            "A mismatch is reported after detach, target-running restoration, and OpenOCD shutdown; no retry is attempted."
                .to_string(),
            "Descriptor equality distinguishes ordinary builds but cannot prevent a malicious target from spoofing self-reported bytes."
                .to_string(),
        ],
    }
}

fn identity_confirmation_boundary() -> OpenOcdEspAppIdentityConfirmationBoundary {
    OpenOcdEspAppIdentityConfirmationBoundary {
        base_memory_confirm_digest_bound: true,
        canonical_elf_path_bound: true,
        exact_elf_bytes_and_hash_bound: true,
        descriptor_section_address_and_layout_bound: true,
        source_and_expected_descriptor_hashes_bound: true,
        expected_descriptor_bytes_bound: true,
        declared_nvm_region_bound: true,
        parser_versions_and_derivation_rule_bound: true,
        runtime_firmware_identity_bound: true,
        target_memory_map_semantics_bound: false,
        runtime_adapter_identity_bound: false,
        cryptographic_authenticity_bound: false,
        secure_boot_state_bound: false,
    }
}

fn identity_capabilities() -> OpenOcdEspAppIdentityCapabilities {
    OpenOcdEspAppIdentityCapabilities {
        bounded_memory_read: true,
        esp_app_descriptor_parsing: true,
        runtime_firmware_identity_verification: true,
        cryptographic_authenticity_verification: false,
        secure_boot_verification: false,
        memory_write: false,
        symbol_loading: false,
        breakpoints: false,
        watchpoints: false,
        general_execution_control: false,
        flash: false,
        arbitrary_commands: false,
    }
}

fn stable_path(path: &Path, kind: &str) -> Result<String> {
    path.to_str().map(str::to_string).ok_or_else(|| {
        DebugError::config(
            "ESP app identity ELF path is not valid Unicode",
            json!({"path_kind": kind}),
        )
    })
}

fn architecture_name(architecture: Architecture) -> String {
    format!("{architecture:?}").to_ascii_lowercase()
}

fn object_error(operation: &str, error: object::Error) -> DebugError {
    DebugError::config(
        format!("{operation} failed"),
        json!({"parser": "object 0.39.1", "error": bounded_text(&error.to_string())}),
    )
}

fn bounded_text(value: &str) -> String {
    value
        .chars()
        .map(|character| {
            if character.is_control() {
                '?'
            } else {
                character
            }
        })
        .take(4 * 1024)
        .collect()
}

fn read_u16(bytes: &[u8; ESP_APP_DESCRIPTOR_BYTES], offset: usize) -> u16 {
    u16::from_le_bytes([bytes[offset], bytes[offset + 1]])
}

fn read_u32(bytes: &[u8; ESP_APP_DESCRIPTOR_BYTES], offset: usize) -> u32 {
    u32::from_le_bytes([
        bytes[offset],
        bytes[offset + 1],
        bytes[offset + 2],
        bytes[offset + 3],
    ])
}

fn identity_confirmation_error(expected: &str, received: &str) -> DebugError {
    let mut error = DebugError::new(
        ErrorCode::ConfirmationMismatch,
        "OpenOCD ESP app identity confirmation digest does not match the current plan",
        2,
        json!({
            "expected_confirm_digest": expected,
            "received_confirm_digest": received,
        }),
    );
    error.suggested_actions.push(SuggestedAction::new(
        "review_openocd_esp_app_identity_plan",
        json!({"command": "openocd esp-app-identity plan --elf <FILE>"}),
    ));
    error
}

#[cfg(test)]
mod tests {
    use std::{fs, path::Path};

    use tempfile::tempdir;

    use super::*;

    #[test]
    fn plan_binds_complete_elf_and_derived_descriptor() {
        let directory = tempdir().unwrap();
        let options = test_options(directory.path());
        let first = plan_esp_app_identity(&options).unwrap();
        let second = plan_esp_app_identity(&options).unwrap();

        assert_eq!(first.confirm_digest, second.confirm_digest);
        assert_eq!(first.elf.section_address, Address(0x3c00_0020));
        assert_eq!(first.elf.section_length_bytes, 256);
        assert_eq!(
            first.elf.expected_descriptor.app_elf_sha256,
            first.elf.sha256
        );
        assert_eq!(first.elf.expected_descriptor_hex.len(), 512);
        assert_eq!(
            first.memory.memory_policy.read_command,
            "3-data-read-memory-bytes 0x3c000020 256"
        );
        assert_eq!(
            first.memory.memory_policy.declared_region.kind,
            MemoryRegionKind::Nvm
        );
        assert!(!first.identity_policy.cryptographic_authenticity_claimed);
    }

    #[test]
    fn plan_rejects_ram_before_filesystem_access() {
        let directory = tempdir().unwrap();
        let mut options = test_options(directory.path());
        options.region_kind = MemoryRegionKind::Ram;
        options.elf = PathBuf::from("missing.elf");
        let error = plan_esp_app_identity(&options).unwrap_err();
        assert_eq!(error.code, ErrorCode::ConfigInvalid);
        assert!(error.message.contains("NVM"));
    }

    #[test]
    fn stale_outer_digest_is_rejected_before_openocd_execution() {
        let directory = tempdir().unwrap();
        let options = test_options(directory.path());
        let error = test_esp_app_identity(&options, &"00".repeat(32)).unwrap_err();
        assert_eq!(error.code, ErrorCode::ConfirmationMismatch);
        assert_eq!(
            error.suggested_actions[0].action,
            "review_openocd_esp_app_identity_plan"
        );
        assert!(error.details.get("openocd_readiness").is_none());
    }

    #[test]
    fn descriptor_comparison_requires_all_256_bytes() {
        let source = test_descriptor();
        let mut expected = source;
        expected[ESP_APP_DESCRIPTOR_ELF_SHA256_OFFSET
            ..ESP_APP_DESCRIPTOR_ELF_SHA256_OFFSET + ESP_APP_DESCRIPTOR_ELF_SHA256_LENGTH]
            .fill(0x5a);
        let matched = compare_descriptor(&expected, &expected);
        assert!(matched.runtime_firmware_identity_verified);
        assert!(!matched.cryptographic_authenticity_verified);

        let mut wrong_metadata = expected;
        wrong_metadata[48] = b'X';
        let mismatch = compare_descriptor(&expected, &wrong_metadata);
        assert!(!mismatch.runtime_firmware_identity_verified);
        assert!(!mismatch.source_bytes_outside_elf_sha256_slot_match);
        assert!(mismatch.embedded_elf_sha256_match);
    }

    #[test]
    fn controlled_identity_test_matches_exact_descriptor_and_restores_running() {
        let directory = tempdir().unwrap();
        let options = test_options(directory.path());
        let expected = expected_test_descriptor(&options.elf);
        rewrite_fake_gdb(&options.session.gdb_executable, &expected);
        let plan = plan_esp_app_identity(&options).unwrap();
        let report = test_esp_app_identity(&options, &plan.confirm_digest).unwrap();

        assert!(report.complete);
        assert!(report.comparison.runtime_firmware_identity_verified);
        assert_eq!(
            report.comparison.target_descriptor.unwrap().project_name,
            "identity-test"
        );
        assert_eq!(report.memory.exchange.snapshot.length_bytes, 256);
        assert_eq!(report.memory.target_restoration.initial.state, "running");
        assert_eq!(
            report
                .memory
                .target_restoration
                .final_observation
                .unwrap()
                .state,
            "running"
        );
        assert!(report.memory.openocd_shutdown.graceful);
    }

    #[test]
    fn mismatch_reports_cleanup_evidence_and_does_not_retry() {
        let directory = tempdir().unwrap();
        let options = test_options(directory.path());
        let mut target = expected_test_descriptor(&options.elf);
        target[48] = b'X';
        rewrite_fake_gdb(&options.session.gdb_executable, &target);
        let plan = plan_esp_app_identity(&options).unwrap();
        let error = test_esp_app_identity(&options, &plan.confirm_digest).unwrap_err();

        assert_eq!(error.code, ErrorCode::VerificationFailed);
        assert_eq!(
            error.details["comparison"]["runtime_firmware_identity_verified"],
            false
        );
        assert_eq!(error.details["retry_attempted"], false);
        assert_eq!(
            error.details["memory"]["target_restoration"]["complete"],
            true
        );
        assert_eq!(
            error.details["memory"]["target_restoration"]["final_observation"]["state"],
            "running"
        );
        assert_eq!(
            error.details["memory"]["openocd_shutdown"]["graceful"],
            true
        );
    }

    fn test_options(directory: &Path) -> OpenOcdEspAppIdentityOptions {
        let memory = super::super::memory::tests::test_options(directory);
        let elf = directory.join("app.elf");
        fs::write(&elf, test_elf()).unwrap();
        OpenOcdEspAppIdentityOptions {
            session: memory.session,
            elf,
            region_start: Address(0x3c00_0000),
            region_length_bytes: 0x1_0000,
            region_kind: MemoryRegionKind::Nvm,
        }
    }

    fn test_elf() -> Vec<u8> {
        const ELF_HEADER_SIZE: usize = 52;
        const APP_OFFSET: usize = 0x100;
        const NAMES_OFFSET: usize = 0x200;
        const SECTION_HEADERS_OFFSET: usize = 0x220;
        const SECTION_HEADER_SIZE: usize = 40;
        const SECTION_COUNT: usize = 3;

        let names = b"\0.flash.appdesc\0.shstrtab\0";
        let mut bytes = vec![0_u8; SECTION_HEADERS_OFFSET + SECTION_HEADER_SIZE * SECTION_COUNT];
        bytes[0..16].copy_from_slice(&[0x7f, b'E', b'L', b'F', 1, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0]);
        put_u16(&mut bytes, 16, 2);
        put_u16(&mut bytes, 18, 94);
        put_u32(&mut bytes, 20, 1);
        put_u32(&mut bytes, 24, 0x4037_0000);
        put_u32(&mut bytes, 32, SECTION_HEADERS_OFFSET as u32);
        put_u16(&mut bytes, 40, ELF_HEADER_SIZE as u16);
        put_u16(&mut bytes, 46, SECTION_HEADER_SIZE as u16);
        put_u16(&mut bytes, 48, SECTION_COUNT as u16);
        put_u16(&mut bytes, 50, 2);
        bytes[APP_OFFSET..APP_OFFSET + ESP_APP_DESCRIPTOR_BYTES]
            .copy_from_slice(&test_descriptor());
        bytes[NAMES_OFFSET..NAMES_OFFSET + names.len()].copy_from_slice(names);

        let app = SECTION_HEADERS_OFFSET + SECTION_HEADER_SIZE;
        put_u32(&mut bytes, app, 1);
        put_u32(&mut bytes, app + 4, 1);
        put_u32(&mut bytes, app + 8, elf::SHF_ALLOC);
        put_u32(&mut bytes, app + 12, 0x3c00_0020);
        put_u32(&mut bytes, app + 16, APP_OFFSET as u32);
        put_u32(&mut bytes, app + 20, ESP_APP_DESCRIPTOR_BYTES as u32);
        put_u32(&mut bytes, app + 32, 4);

        let strings = SECTION_HEADERS_OFFSET + SECTION_HEADER_SIZE * 2;
        put_u32(&mut bytes, strings, 16);
        put_u32(&mut bytes, strings + 4, 3);
        put_u32(&mut bytes, strings + 16, NAMES_OFFSET as u32);
        put_u32(&mut bytes, strings + 20, names.len() as u32);
        put_u32(&mut bytes, strings + 32, 1);
        bytes
    }

    fn expected_test_descriptor(elf: &Path) -> [u8; ESP_APP_DESCRIPTOR_BYTES] {
        let bytes = fs::read(elf).unwrap();
        let mut descriptor = test_descriptor();
        descriptor[ESP_APP_DESCRIPTOR_ELF_SHA256_OFFSET
            ..ESP_APP_DESCRIPTOR_ELF_SHA256_OFFSET + ESP_APP_DESCRIPTOR_ELF_SHA256_LENGTH]
            .copy_from_slice(&Sha256::digest(bytes));
        descriptor
    }

    fn rewrite_fake_gdb(path: &Path, descriptor: &[u8; ESP_APP_DESCRIPTOR_BYTES]) {
        let script = fs::read_to_string(path).unwrap();
        let script = script.replace(
            "3-data-read-memory-bytes 0x20000004 8",
            "3-data-read-memory-bytes 0x3c000020 256",
        );
        let contents = hex::encode(descriptor);
        #[cfg(windows)]
        let response = format!(
            "echo 3^^done,memory=[{{begin=\"0x3c000020\",offset=\"0x0\",end=\"0x3c000120\",contents=\"{contents}\"}}]"
        );
        #[cfg(unix)]
        let response = format!(
            "printf '%s\\n' '3^done,memory=[{{begin=\"0x3c000020\",offset=\"0x0\",end=\"0x3c000120\",contents=\"{contents}\"}}]' '(gdb)'"
        );
        let newline = if cfg!(windows) { "\r\n" } else { "\n" };
        let rewritten = script
            .lines()
            .map(|line| {
                if line.contains("done,memory=[") {
                    response.as_str()
                } else {
                    line
                }
            })
            .collect::<Vec<_>>()
            .join(newline)
            + newline;
        fs::write(path, rewritten).unwrap();
    }

    fn test_descriptor() -> [u8; ESP_APP_DESCRIPTOR_BYTES] {
        let mut descriptor = [0_u8; ESP_APP_DESCRIPTOR_BYTES];
        descriptor[0..4].copy_from_slice(&ESP_APP_DESCRIPTOR_MAGIC.to_le_bytes());
        put_fixed(&mut descriptor, 16, 32, b"0.1.0");
        put_fixed(&mut descriptor, 48, 32, b"identity-test");
        put_fixed(&mut descriptor, 80, 16, b"12:34:56");
        put_fixed(&mut descriptor, 96, 16, b"2026-08-31");
        put_fixed(&mut descriptor, 112, 32, b"0.0.0");
        descriptor
    }

    fn put_fixed(bytes: &mut [u8], offset: usize, length: usize, value: &[u8]) {
        assert!(value.len() < length);
        bytes[offset..offset + value.len()].copy_from_slice(value);
    }

    fn put_u16(bytes: &mut [u8], offset: usize, value: u16) {
        bytes[offset..offset + 2].copy_from_slice(&value.to_le_bytes());
    }

    fn put_u32(bytes: &mut [u8], offset: usize, value: u32) {
        bytes[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
    }
}
