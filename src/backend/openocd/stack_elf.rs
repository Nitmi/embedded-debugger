use std::{
    borrow::Cow,
    fs::{self, File},
    io::Read,
    path::{Path, PathBuf},
};

use addr2line::{
    Context, LookupContinuation, LookupResult,
    gimli::{self, Dwarf, EndianSlice, RunTimeEndian, SectionId},
};
use object::{
    Architecture, BinaryFormat, CompressionFormat, Endianness, Object, ObjectKind, ObjectSection,
    ObjectSegment, ObjectSymbol, SymbolKind, read::File as ObjectFile,
};
use serde::Serialize;
use serde_json::json;
use sha2::{Digest, Sha256};

use super::{
    GdbMiStackFrame, MAX_OPENOCD_STACK_SNAPSHOT_FRAMES, OpenOcdStackSnapshotOptions,
    OpenOcdStackSnapshotPlan, OpenOcdStackSnapshotTestReport, plan_stack_snapshot,
    test_stack_snapshot,
};
use crate::{
    SCHEMA_VERSION,
    error::{DebugError, ErrorCode, Result, SuggestedAction},
    model::Address,
};

pub const MAX_OPENOCD_STACK_ELF_BYTES: u64 = 64 * 1024 * 1024;
pub const MAX_OPENOCD_STACK_ELF_INLINE_ANNOTATIONS: u64 = 8;
const MAX_OPENOCD_STACK_ELF_SECTIONS: u64 = 65_536;
const MAX_OPENOCD_STACK_ELF_SYMBOLS: u64 = 262_144;
const MAX_OPENOCD_STACK_ELF_TEXT_BYTES: usize = 4 * 1024;
const MAX_OPENOCD_STACK_ELF_BUILD_ID_BYTES: usize = 64;
const MAX_OPENOCD_STACK_ELF_SPLIT_DWARF_REQUESTS_PER_FRAME: u64 = 8;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OpenOcdStackElfOptions {
    pub stack: OpenOcdStackSnapshotOptions,
    pub elf: PathBuf,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct OpenOcdStackElfPlan {
    pub backend: String,
    pub operation: String,
    pub risk: String,
    pub complete: bool,
    pub stack: OpenOcdStackSnapshotPlan,
    pub elf: OpenOcdStackElfInspection,
    pub annotation_policy: OpenOcdStackElfPolicy,
    pub effects: OpenOcdStackElfEffects,
    pub confirmation_boundary: OpenOcdStackElfConfirmationBoundary,
    pub confirm_digest: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct OpenOcdStackElfInspection {
    pub resolved: String,
    pub bytes: u64,
    pub maximum_bytes: u64,
    pub sha256: String,
    pub format: String,
    pub kind: String,
    pub architecture: String,
    pub address_size_bits: u64,
    pub endianness: String,
    pub entry: Address,
    pub build_id: Option<String>,
    pub section_count: u64,
    pub symbol_count: u64,
    pub text_symbol_count: u64,
    pub has_debug_symbols: bool,
    pub has_debug_info: bool,
    pub has_debug_line: bool,
    pub gnu_debuglink_present: bool,
    pub gnu_debugaltlink_present: bool,
    pub compressed_debug_sections_detected: bool,
    pub external_files_loaded: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct OpenOcdStackElfPolicy {
    pub object_parser: String,
    pub address_resolver: String,
    pub required_file_format: String,
    pub required_object_kind: String,
    pub maximum_elf_bytes: u64,
    pub maximum_sections: u64,
    pub maximum_symbols: u64,
    pub maximum_build_id_bytes: u64,
    pub address_interpretation: String,
    pub load_bias: i64,
    pub top_frame_lookup: String,
    pub non_top_frame_lookup: String,
    pub maximum_dwarf_frames_examined_per_frame: u64,
    pub maximum_inline_annotations_per_frame: u64,
    pub maximum_split_dwarf_requests_per_frame: u64,
    pub text_field_maximum_bytes: u64,
    pub symbol_table_fallback: String,
    pub compressed_debug_sections: String,
    pub split_or_external_debug_data: String,
    pub source_file_contents_read: bool,
    pub gdb_symbol_or_executable_loading: bool,
    pub unresolved_frames_allowed: bool,
    pub runtime_firmware_identity_verified: bool,
    pub physical_call_stack_completeness_claimed: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct OpenOcdStackElfEffects {
    pub base_stack_snapshot_effects_apply: bool,
    pub exact_host_elf_read_requested: bool,
    pub in_process_elf_and_dwarf_parsing_requested: bool,
    pub gdb_symbol_or_executable_loading_requested: bool,
    pub elf_embedded_script_execution_requested: bool,
    pub source_file_read_requested: bool,
    pub external_debug_file_read_requested: bool,
    pub network_access_requested: bool,
    pub notes: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct OpenOcdStackElfConfirmationBoundary {
    pub base_stack_confirm_digest_bound: bool,
    pub canonical_elf_path_bound: bool,
    pub exact_elf_bytes_and_hash_bound: bool,
    pub elf_format_kind_architecture_and_entry_bound: bool,
    pub elf_build_id_bound_when_present: bool,
    pub parser_versions_bound: bool,
    pub parser_resource_limits_bound: bool,
    pub address_adjustment_policy_bound: bool,
    pub inline_annotation_limit_bound: bool,
    pub external_debug_loading_policy_bound: bool,
    pub runtime_firmware_identity_bound: bool,
    pub runtime_adapter_identity_bound: bool,
    pub implicit_unwinder_target_access_addresses_bound: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct OpenOcdStackElfTestReport {
    pub backend: String,
    pub scope: String,
    pub risk: String,
    pub complete: bool,
    pub confirm_digest: String,
    pub stack: OpenOcdStackSnapshotTestReport,
    pub elf: OpenOcdStackElfInspection,
    pub annotation_policy: OpenOcdStackElfPolicy,
    pub annotations: OpenOcdStackElfAnnotations,
    pub effects: OpenOcdStackElfEffects,
    pub confirmation_boundary: OpenOcdStackElfConfirmationBoundary,
    pub capabilities: OpenOcdStackElfCapabilities,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct OpenOcdStackElfAnnotations {
    pub frames: Vec<OpenOcdStackElfFrame>,
    pub resolved_frames: u64,
    pub unresolved_frames: u64,
    pub runtime_firmware_identity_verified: bool,
    pub physical_call_stack_completeness_proven: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct OpenOcdStackElfFrame {
    pub frame: GdbMiStackFrame,
    pub lookup_address: Address,
    pub return_address_adjusted: bool,
    pub within_loadable_segment: bool,
    pub resolution: OpenOcdStackElfResolution,
    pub external_debug_data_required: bool,
    pub external_debug_load_requests: u64,
    pub lookup_error: Option<String>,
    pub inline_annotations: Vec<OpenOcdStackElfAnnotation>,
    pub inline_annotations_truncated: bool,
    pub metadata_rejected: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct OpenOcdStackElfAnnotation {
    pub depth: u64,
    pub function: Option<String>,
    pub file: Option<String>,
    pub line: Option<u64>,
    pub column: Option<u64>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum OpenOcdStackElfResolution {
    Dwarf,
    SymbolTable,
    Unresolved,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct OpenOcdStackElfCapabilities {
    pub bounded_stack_snapshot: bool,
    pub offline_elf_annotation: bool,
    pub dwarf_inline_annotations: bool,
    pub in_file_symbol_table_fallback: bool,
    pub gdb_symbol_loading: bool,
    pub external_debug_loading: bool,
    pub source_file_read: bool,
    pub runtime_firmware_identity_verification: bool,
    pub breakpoints: bool,
    pub watchpoints: bool,
    pub general_execution_control: bool,
    pub flash: bool,
    pub arbitrary_commands: bool,
}

#[derive(Debug, Serialize)]
struct StackElfConfirmationInput<'a> {
    schema_version: &'static str,
    operation: &'static str,
    backend: &'static str,
    base_stack_confirm_digest: &'a str,
    elf: &'a OpenOcdStackElfInspection,
    annotation_policy: &'a OpenOcdStackElfPolicy,
    effects: &'a OpenOcdStackElfEffects,
    confirmation_boundary: &'a OpenOcdStackElfConfirmationBoundary,
}

struct PreparedStackElf {
    plan: OpenOcdStackElfPlan,
    bytes: Vec<u8>,
}

struct OfflineSymbols<'data> {
    object: ObjectFile<'data, &'data [u8]>,
    context: Context<EndianSlice<'data, RunTimeEndian>>,
    text_symbols: Vec<TextSymbol>,
}

struct TextSymbol {
    address: u64,
    size: u64,
    name: String,
}

pub fn plan_stack_elf(options: &OpenOcdStackElfOptions) -> Result<OpenOcdStackElfPlan> {
    prepare_stack_elf(options).map(|prepared| prepared.plan)
}

pub fn test_stack_elf(
    options: &OpenOcdStackElfOptions,
    confirm_digest: &str,
) -> Result<OpenOcdStackElfTestReport> {
    let prepared = prepare_stack_elf(options)?;
    if prepared.plan.confirm_digest != confirm_digest {
        return Err(stack_elf_confirmation_error(
            &prepared.plan.confirm_digest,
            confirm_digest,
        ));
    }

    let base_digest = prepared.plan.stack.confirm_digest.clone();
    let stack = test_stack_snapshot(&options.stack, &base_digest)?;
    let annotations = annotate_frames(&prepared.bytes, &stack.exchange.snapshot.frames)?;

    Ok(OpenOcdStackElfTestReport {
        backend: prepared.plan.backend,
        scope: "confirmed_bounded_stack_snapshot_with_offline_elf_annotation".to_string(),
        risk: prepared.plan.risk,
        complete: true,
        confirm_digest: prepared.plan.confirm_digest,
        stack,
        elf: prepared.plan.elf,
        annotation_policy: prepared.plan.annotation_policy,
        annotations,
        effects: prepared.plan.effects,
        confirmation_boundary: prepared.plan.confirmation_boundary,
        capabilities: stack_elf_capabilities(),
    })
}

fn prepare_stack_elf(options: &OpenOcdStackElfOptions) -> Result<PreparedStackElf> {
    validate_frame_limit(options.stack.maximum_frames)?;
    super::session::validate_session_options(&options.stack.session)?;
    let (resolved, bytes) = read_bounded_elf(&options.elf)?;
    let elf = inspect_elf(&resolved, &bytes)?;

    // Constructing the context here rejects structurally unusable in-file DWARF before hardware.
    let _ = OfflineSymbols::new(&bytes)?;
    let stack = plan_stack_snapshot(&options.stack)?;
    let annotation_policy = stack_elf_policy();
    let effects = stack_elf_effects();
    let confirmation_boundary = stack_elf_confirmation_boundary();
    let confirmation = StackElfConfirmationInput {
        schema_version: SCHEMA_VERSION,
        operation: "openocd.stack.annotated.test",
        backend: "openocd",
        base_stack_confirm_digest: &stack.confirm_digest,
        elf: &elf,
        annotation_policy: &annotation_policy,
        effects: &effects,
        confirmation_boundary: &confirmation_boundary,
    };
    let confirm_digest = hex::encode(Sha256::digest(
        serde_json::to_vec(&confirmation).expect("stack ELF confirmation input serializes"),
    ));

    Ok(PreparedStackElf {
        plan: OpenOcdStackElfPlan {
            backend: "openocd".to_string(),
            operation: "openocd.stack.annotated.test".to_string(),
            risk: stack.risk.clone(),
            complete: true,
            stack,
            elf,
            annotation_policy,
            effects,
            confirmation_boundary,
            confirm_digest,
        },
        bytes,
    })
}

fn validate_frame_limit(maximum_frames: u64) -> Result<()> {
    if !(1..=MAX_OPENOCD_STACK_SNAPSHOT_FRAMES).contains(&maximum_frames) {
        return Err(DebugError::config(
            "OpenOCD stack snapshot frame limit is outside the supported range",
            json!({
                "maximum_frames": maximum_frames,
                "minimum": 1,
                "maximum": MAX_OPENOCD_STACK_SNAPSHOT_FRAMES,
            }),
        ));
    }
    Ok(())
}

fn read_bounded_elf(requested: &Path) -> Result<(PathBuf, Vec<u8>)> {
    let requested_display = stable_elf_path(requested, "requested")?;
    let resolved = fs::canonicalize(requested).map_err(|source| {
        DebugError::config(
            "resolve stack annotation ELF failed",
            json!({"path": requested_display, "cause": source.to_string()}),
        )
    })?;
    let resolved_display = stable_elf_path(&resolved, "resolved")?;
    let file = File::open(&resolved).map_err(|source| {
        DebugError::config(
            "open stack annotation ELF failed",
            json!({"path": resolved_display, "cause": source.to_string()}),
        )
    })?;
    let metadata = file.metadata().map_err(|source| {
        DebugError::config(
            "inspect stack annotation ELF failed",
            json!({"path": resolved_display, "cause": source.to_string()}),
        )
    })?;
    if !metadata.is_file() {
        return Err(DebugError::config(
            "stack annotation ELF is not a regular file",
            json!({"path": resolved_display}),
        ));
    }
    if metadata.len() == 0 || metadata.len() > MAX_OPENOCD_STACK_ELF_BYTES {
        return Err(DebugError::config(
            "stack annotation ELF size is outside the supported range",
            json!({
                "path": resolved_display,
                "bytes": metadata.len(),
                "minimum_bytes": 1,
                "maximum_bytes": MAX_OPENOCD_STACK_ELF_BYTES,
            }),
        ));
    }

    let mut bytes = Vec::with_capacity(usize::try_from(metadata.len()).unwrap_or(0));
    file.take(MAX_OPENOCD_STACK_ELF_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(|source| {
            DebugError::config(
                "read stack annotation ELF failed",
                json!({"path": resolved_display, "cause": source.to_string()}),
            )
        })?;
    if bytes.len() as u64 != metadata.len() {
        return Err(DebugError::config(
            "stack annotation ELF changed while it was being read",
            json!({
                "path": resolved_display,
                "metadata_bytes": metadata.len(),
                "read_bytes": bytes.len(),
            }),
        ));
    }
    Ok((resolved, bytes))
}

fn inspect_elf(resolved: &Path, bytes: &[u8]) -> Result<OpenOcdStackElfInspection> {
    let object = parse_executable_elf(bytes)?;
    let architecture = object.architecture();
    let address_size_bits = architecture
        .address_size()
        .map(|size| u64::from(size.bytes()) * 8)
        .ok_or_else(|| {
            DebugError::config(
                "stack annotation ELF architecture has no known address size",
                json!({"architecture": architecture_name(architecture)}),
            )
        })?;

    let mut section_count = 0_u64;
    let mut has_debug_info = false;
    let mut has_debug_line = false;
    for section in object.sections() {
        section_count += 1;
        if section_count > MAX_OPENOCD_STACK_ELF_SECTIONS {
            return Err(DebugError::config(
                "stack annotation ELF contains too many sections",
                json!({"maximum_sections": MAX_OPENOCD_STACK_ELF_SECTIONS}),
            ));
        }
        let name = section
            .name()
            .map_err(|error| object_error("read ELF section name", error))?;
        has_debug_info |= name == ".debug_info";
        has_debug_line |= name == ".debug_line";
        if is_debug_section(name) {
            if name.starts_with(".zdebug_") {
                return Err(DebugError::config(
                    "compressed ELF debug sections are not accepted for stack annotation",
                    json!({"section": bounded_text(name)}),
                ));
            }
            let compression = section
                .compressed_file_range()
                .map_err(|error| object_error("inspect ELF debug-section compression", error))?;
            if compression.format != CompressionFormat::None {
                return Err(DebugError::config(
                    "compressed ELF debug sections are not accepted for stack annotation",
                    json!({"section": bounded_text(name)}),
                ));
            }
            section
                .data()
                .map_err(|error| object_error("read ELF debug section", error))?;
        }
    }

    let mut symbol_count = 0_u64;
    let mut text_symbol_count = 0_u64;
    for symbol in object.symbols() {
        symbol_count += 1;
        if symbol_count > MAX_OPENOCD_STACK_ELF_SYMBOLS {
            return Err(DebugError::config(
                "stack annotation ELF contains too many symbols",
                json!({"maximum_symbols": MAX_OPENOCD_STACK_ELF_SYMBOLS}),
            ));
        }
        if symbol.kind() == SymbolKind::Text && symbol.is_definition() && symbol.size() != 0 {
            text_symbol_count += 1;
        }
    }

    let build_id = object
        .build_id()
        .map_err(|error| object_error("read ELF build ID", error))?
        .map(|build_id| {
            if build_id.len() > MAX_OPENOCD_STACK_ELF_BUILD_ID_BYTES {
                return Err(DebugError::config(
                    "stack annotation ELF build ID exceeds the supported size",
                    json!({
                        "bytes": build_id.len(),
                        "maximum_bytes": MAX_OPENOCD_STACK_ELF_BUILD_ID_BYTES,
                    }),
                ));
            }
            Ok(hex::encode(build_id))
        })
        .transpose()?;
    let gnu_debuglink_present = object
        .gnu_debuglink()
        .map_err(|error| object_error("inspect ELF GNU debug link", error))?
        .is_some();
    let gnu_debugaltlink_present = object
        .gnu_debugaltlink()
        .map_err(|error| object_error("inspect ELF GNU alternate debug link", error))?
        .is_some();

    Ok(OpenOcdStackElfInspection {
        resolved: stable_elf_path(resolved, "resolved")?,
        bytes: bytes.len() as u64,
        maximum_bytes: MAX_OPENOCD_STACK_ELF_BYTES,
        sha256: hex::encode(Sha256::digest(bytes)),
        format: "elf".to_string(),
        kind: "executable".to_string(),
        architecture: architecture_name(architecture),
        address_size_bits,
        endianness: endianness_name(object.endianness()).to_string(),
        entry: Address(object.entry()),
        build_id,
        section_count,
        symbol_count,
        text_symbol_count,
        has_debug_symbols: object.has_debug_symbols(),
        has_debug_info,
        has_debug_line,
        gnu_debuglink_present,
        gnu_debugaltlink_present,
        compressed_debug_sections_detected: false,
        external_files_loaded: false,
    })
}

fn parse_executable_elf<'data>(bytes: &'data [u8]) -> Result<ObjectFile<'data, &'data [u8]>> {
    let object = ObjectFile::parse(bytes)
        .map_err(|error| object_error("parse stack annotation ELF", error))?;
    if object.format() != BinaryFormat::Elf {
        return Err(DebugError::config(
            "stack annotation input is not an ELF file",
            json!({"observed_format": format!("{:?}", object.format())}),
        ));
    }
    if object.kind() != ObjectKind::Executable {
        return Err(DebugError::config(
            "stack annotation ELF is not an executable image",
            json!({"observed_kind": format!("{:?}", object.kind())}),
        ));
    }
    Ok(object)
}

impl<'data> OfflineSymbols<'data> {
    fn new(bytes: &'data [u8]) -> Result<Self> {
        let object = parse_executable_elf(bytes)?;
        let endian = match object.endianness() {
            Endianness::Little => RunTimeEndian::Little,
            Endianness::Big => RunTimeEndian::Big,
        };
        let dwarf = Dwarf::load(
            |id: SectionId| -> std::result::Result<EndianSlice<'data, RunTimeEndian>, gimli::Error> {
                let data = object
                    .section_by_name(id.name())
                    .and_then(|section| section.data().ok())
                    .unwrap_or(&[]);
                Ok(EndianSlice::new(data, endian))
            },
        )
        .map_err(|error| dwarf_error("load in-file DWARF sections", error))?;
        let context = Context::from_dwarf(dwarf)
            .map_err(|error| dwarf_error("construct offline address resolver", error))?;

        let mut text_symbols = Vec::new();
        for symbol in object.symbols() {
            if symbol.kind() != SymbolKind::Text || !symbol.is_definition() || symbol.size() == 0 {
                continue;
            }
            let Ok(name) = symbol.name() else {
                continue;
            };
            let (Some(name), _) = sanitize_text(name) else {
                continue;
            };
            let demangled = addr2line::demangle_auto(Cow::Owned(name), None);
            let Some(name) = sanitize_text(&demangled).0 else {
                continue;
            };
            text_symbols.push(TextSymbol {
                address: symbol.address(),
                size: symbol.size(),
                name,
            });
        }
        text_symbols.sort_by(|left, right| {
            left.address
                .cmp(&right.address)
                .then(left.size.cmp(&right.size))
                .then(left.name.cmp(&right.name))
        });
        Ok(Self {
            object,
            context,
            text_symbols,
        })
    }

    fn annotate(&self, frame: &GdbMiStackFrame) -> OpenOcdStackElfFrame {
        let return_address_adjusted = frame.level != 0 && frame.address.0 != 0;
        let lookup_address = if return_address_adjusted {
            frame.address.0 - 1
        } else {
            frame.address.0
        };
        let within_loadable_segment = self.object.segments().any(|segment| {
            segment
                .address()
                .checked_add(segment.size())
                .is_some_and(|end| segment.address() <= lookup_address && lookup_address < end)
        });
        let mut result = OpenOcdStackElfFrame {
            frame: frame.clone(),
            lookup_address: Address(lookup_address),
            return_address_adjusted,
            within_loadable_segment,
            resolution: OpenOcdStackElfResolution::Unresolved,
            external_debug_data_required: false,
            external_debug_load_requests: 0,
            lookup_error: None,
            inline_annotations: Vec::new(),
            inline_annotations_truncated: false,
            metadata_rejected: false,
        };
        if !within_loadable_segment {
            return result;
        }

        let mut lookup = self.context.find_frames(lookup_address);
        let frames = loop {
            match lookup {
                LookupResult::Output(frames) => break Some(frames),
                LookupResult::Load { continuation, .. } => {
                    result.external_debug_data_required = true;
                    result.external_debug_load_requests += 1;
                    if result.external_debug_load_requests
                        > MAX_OPENOCD_STACK_ELF_SPLIT_DWARF_REQUESTS_PER_FRAME
                    {
                        result.lookup_error = Some(
                            "split DWARF request limit exceeded; external data was not loaded"
                                .to_string(),
                        );
                        break None;
                    }
                    lookup = continuation.resume(None);
                }
            }
        };
        if let Some(frames) = frames {
            match frames {
                Ok(mut frames) => {
                    let mut examined_frames = 0_u64;
                    loop {
                        match frames.next() {
                            Ok(Some(dwarf_frame)) => {
                                examined_frames += 1;
                                if examined_frames > MAX_OPENOCD_STACK_ELF_INLINE_ANNOTATIONS {
                                    result.inline_annotations_truncated = true;
                                    break;
                                }
                                let (function, function_rejected) = match dwarf_frame.function {
                                    Some(name) => sanitize_function_name(name),
                                    None => (None, false),
                                };
                                let location = dwarf_frame.location;
                                let (file, file_rejected) = location
                                    .as_ref()
                                    .and_then(|value| value.file)
                                    .map_or((None, false), sanitize_text);
                                let annotation = OpenOcdStackElfAnnotation {
                                    depth: result.inline_annotations.len() as u64,
                                    function,
                                    file,
                                    line: location
                                        .as_ref()
                                        .and_then(|value| value.line)
                                        .map(u64::from),
                                    column: location
                                        .as_ref()
                                        .and_then(|value| value.column)
                                        .map(u64::from),
                                };
                                result.metadata_rejected |= function_rejected || file_rejected;
                                if annotation.function.is_some()
                                    || annotation.file.is_some()
                                    || annotation.line.is_some()
                                {
                                    result.inline_annotations.push(annotation);
                                }
                            }
                            Ok(None) => break,
                            Err(error) => {
                                result.lookup_error = Some(bounded_text(&error.to_string()));
                                break;
                            }
                        }
                    }
                }
                Err(error) => result.lookup_error = Some(bounded_text(&error.to_string())),
            }
        }

        if !result.inline_annotations.is_empty() {
            result.resolution = OpenOcdStackElfResolution::Dwarf;
            return result;
        }
        if let Some(symbol) = self
            .text_symbols
            .iter()
            .filter(|symbol| {
                symbol
                    .address
                    .checked_add(symbol.size)
                    .is_some_and(|end| symbol.address <= lookup_address && lookup_address < end)
            })
            .min_by(|left, right| {
                left.size
                    .cmp(&right.size)
                    .then(right.address.cmp(&left.address))
                    .then(left.name.cmp(&right.name))
            })
        {
            result.inline_annotations.push(OpenOcdStackElfAnnotation {
                depth: 0,
                function: Some(symbol.name.clone()),
                file: None,
                line: None,
                column: None,
            });
            result.resolution = OpenOcdStackElfResolution::SymbolTable;
        }
        result
    }
}

fn annotate_frames(bytes: &[u8], frames: &[GdbMiStackFrame]) -> Result<OpenOcdStackElfAnnotations> {
    let symbols = OfflineSymbols::new(bytes)?;
    let frames = frames
        .iter()
        .map(|frame| symbols.annotate(frame))
        .collect::<Vec<_>>();
    let resolved_frames = frames
        .iter()
        .filter(|frame| frame.resolution != OpenOcdStackElfResolution::Unresolved)
        .count() as u64;
    Ok(OpenOcdStackElfAnnotations {
        unresolved_frames: frames.len() as u64 - resolved_frames,
        resolved_frames,
        frames,
        runtime_firmware_identity_verified: false,
        physical_call_stack_completeness_proven: false,
    })
}

fn stack_elf_policy() -> OpenOcdStackElfPolicy {
    OpenOcdStackElfPolicy {
        object_parser: "object 0.39.1".to_string(),
        address_resolver: "addr2line 0.25.1".to_string(),
        required_file_format: "elf".to_string(),
        required_object_kind: "executable".to_string(),
        maximum_elf_bytes: MAX_OPENOCD_STACK_ELF_BYTES,
        maximum_sections: MAX_OPENOCD_STACK_ELF_SECTIONS,
        maximum_symbols: MAX_OPENOCD_STACK_ELF_SYMBOLS,
        maximum_build_id_bytes: MAX_OPENOCD_STACK_ELF_BUILD_ID_BYTES as u64,
        address_interpretation: "exact ELF virtual memory addresses with no relocation".to_string(),
        load_bias: 0,
        top_frame_lookup: "exact GDB frame address".to_string(),
        non_top_frame_lookup: "GDB return address minus one when nonzero".to_string(),
        maximum_dwarf_frames_examined_per_frame: MAX_OPENOCD_STACK_ELF_INLINE_ANNOTATIONS,
        maximum_inline_annotations_per_frame: MAX_OPENOCD_STACK_ELF_INLINE_ANNOTATIONS,
        maximum_split_dwarf_requests_per_frame:
            MAX_OPENOCD_STACK_ELF_SPLIT_DWARF_REQUESTS_PER_FRAME,
        text_field_maximum_bytes: MAX_OPENOCD_STACK_ELF_TEXT_BYTES as u64,
        symbol_table_fallback: "smallest containing defined nonzero-sized in-file text symbol"
            .to_string(),
        compressed_debug_sections: "rejected before hardware access".to_string(),
        split_or_external_debug_data: "never loaded; unresolved output is allowed".to_string(),
        source_file_contents_read: false,
        gdb_symbol_or_executable_loading: false,
        unresolved_frames_allowed: true,
        runtime_firmware_identity_verified: false,
        physical_call_stack_completeness_claimed: false,
    }
}

fn stack_elf_effects() -> OpenOcdStackElfEffects {
    OpenOcdStackElfEffects {
        base_stack_snapshot_effects_apply: true,
        exact_host_elf_read_requested: true,
        in_process_elf_and_dwarf_parsing_requested: true,
        gdb_symbol_or_executable_loading_requested: false,
        elf_embedded_script_execution_requested: false,
        source_file_read_requested: false,
        external_debug_file_read_requested: false,
        network_access_requested: false,
        notes: vec![
            "The confirmed base stack protocol remains version, remote attach, bounded unwind, detach, and exit; GDB never receives the ELF path."
                .to_string(),
            "Annotation parses only the exact SHA-256-bound ELF bytes retained in memory and does not invoke an external addr2line process."
                .to_string(),
            "ELF identity does not prove that the connected target is running those bytes."
                .to_string(),
        ],
    }
}

fn stack_elf_confirmation_boundary() -> OpenOcdStackElfConfirmationBoundary {
    OpenOcdStackElfConfirmationBoundary {
        base_stack_confirm_digest_bound: true,
        canonical_elf_path_bound: true,
        exact_elf_bytes_and_hash_bound: true,
        elf_format_kind_architecture_and_entry_bound: true,
        elf_build_id_bound_when_present: true,
        parser_versions_bound: true,
        parser_resource_limits_bound: true,
        address_adjustment_policy_bound: true,
        inline_annotation_limit_bound: true,
        external_debug_loading_policy_bound: true,
        runtime_firmware_identity_bound: false,
        runtime_adapter_identity_bound: false,
        implicit_unwinder_target_access_addresses_bound: false,
    }
}

fn stack_elf_capabilities() -> OpenOcdStackElfCapabilities {
    OpenOcdStackElfCapabilities {
        bounded_stack_snapshot: true,
        offline_elf_annotation: true,
        dwarf_inline_annotations: true,
        in_file_symbol_table_fallback: true,
        gdb_symbol_loading: false,
        external_debug_loading: false,
        source_file_read: false,
        runtime_firmware_identity_verification: false,
        breakpoints: false,
        watchpoints: false,
        general_execution_control: false,
        flash: false,
        arbitrary_commands: false,
    }
}

fn is_debug_section(name: &str) -> bool {
    name.starts_with(".debug_")
        || name.starts_with(".zdebug_")
        || matches!(name, ".eh_frame" | ".eh_frame_hdr")
}

fn architecture_name(architecture: Architecture) -> String {
    format!("{architecture:?}").to_ascii_lowercase()
}

fn endianness_name(endianness: Endianness) -> &'static str {
    match endianness {
        Endianness::Little => "little",
        Endianness::Big => "big",
    }
}

fn sanitize_text(value: &str) -> (Option<String>, bool) {
    if value.is_empty()
        || value.len() > MAX_OPENOCD_STACK_ELF_TEXT_BYTES
        || value.chars().any(char::is_control)
    {
        return (None, true);
    }
    (Some(value.to_string()), false)
}

fn sanitize_function_name<R: gimli::Reader>(
    name: addr2line::FunctionName<R>,
) -> (Option<String>, bool) {
    let Ok(raw) = name.name.to_slice() else {
        return (None, true);
    };
    if raw.len() > MAX_OPENOCD_STACK_ELF_TEXT_BYTES {
        return (None, true);
    }
    let Ok(raw) = std::str::from_utf8(raw.as_ref()) else {
        return (None, true);
    };
    let (Some(raw), _) = sanitize_text(raw) else {
        return (None, true);
    };
    let demangled = addr2line::demangle_auto(Cow::Owned(raw), name.language);
    sanitize_text(&demangled)
}

fn bounded_text(value: &str) -> String {
    let value = value
        .chars()
        .map(|character| {
            if character.is_control() {
                '?'
            } else {
                character
            }
        })
        .collect::<String>();
    if value.len() <= MAX_OPENOCD_STACK_ELF_TEXT_BYTES {
        return value;
    }
    let mut end = MAX_OPENOCD_STACK_ELF_TEXT_BYTES;
    while !value.is_char_boundary(end) {
        end -= 1;
    }
    value[..end].to_string()
}

fn stable_elf_path(path: &Path, kind: &str) -> Result<String> {
    path.to_str().map(str::to_string).ok_or_else(|| {
        DebugError::config(
            "stack annotation ELF path is not valid Unicode",
            json!({"path_kind": kind}),
        )
    })
}

fn object_error(operation: &str, error: object::Error) -> DebugError {
    DebugError::config(
        format!("{operation} failed"),
        json!({"parser": "object 0.39.1", "error": bounded_text(&error.to_string())}),
    )
}

fn dwarf_error(operation: &str, error: gimli::Error) -> DebugError {
    DebugError::config(
        format!("{operation} failed"),
        json!({"resolver": "addr2line 0.25.1", "error": bounded_text(&error.to_string())}),
    )
}

fn stack_elf_confirmation_error(expected: &str, received: &str) -> DebugError {
    let mut error = DebugError::new(
        ErrorCode::ConfirmationMismatch,
        "OpenOCD ELF-annotated stack confirmation digest does not match the current plan",
        2,
        json!({
            "expected_confirm_digest": expected,
            "received_confirm_digest": received,
        }),
    );
    error.suggested_actions.push(SuggestedAction::new(
        "review_openocd_annotated_stack_plan",
        json!({"command": "openocd stack plan --elf <FILE>"}),
    ));
    error
}

#[cfg(test)]
pub(crate) fn test_executable_elf(compressed_debug_section: bool) -> Vec<u8> {
    test_executable_elf_options(compressed_debug_section, None)
}

#[cfg(test)]
fn test_executable_elf_options(
    compressed_debug_section: bool,
    build_id_bytes: Option<usize>,
) -> Vec<u8> {
    use addr2line::gimli::{
        Encoding, Format, LittleEndian,
        write::{Address as WriteAddress, AttributeValue, DwarfUnit, EndianVec, Sections},
    };
    use object::{build, elf};

    let mut builder = build::elf::Builder::new(Endianness::Little, false);
    builder.header.e_type = elf::ET_EXEC;
    builder.header.e_machine = elf::EM_XTENSA;
    builder.header.e_entry = 0x4037_0000;
    builder.header.e_phoff = 0x34;

    let section = builder.sections.add();
    section.name = b".shstrtab"[..].into();
    section.sh_type = elf::SHT_STRTAB;
    section.data = build::elf::SectionData::SectionString;

    let section = builder.sections.add();
    section.name = b".text"[..].into();
    section.sh_type = elf::SHT_PROGBITS;
    section.sh_flags = u64::from(elf::SHF_ALLOC | elf::SHF_EXECINSTR);
    section.sh_addr = 0x4037_0000;
    section.sh_offset = 0x1000;
    section.sh_addralign = 4;
    section.data = build::elf::SectionData::Data(vec![0_u8; 0x40].into());
    let text_id = section.id();

    let section = builder.sections.add();
    section.name = b".symtab"[..].into();
    section.sh_type = elf::SHT_SYMTAB;
    section.sh_addralign = 4;
    section.data = build::elf::SectionData::Symbol;

    let section = builder.sections.add();
    section.name = b".strtab"[..].into();
    section.sh_type = elf::SHT_STRTAB;
    section.sh_addralign = 1;
    section.data = build::elf::SectionData::String;

    if let Some(build_id_bytes) = build_id_bytes {
        let mut note = Vec::new();
        note.extend_from_slice(&4_u32.to_le_bytes());
        note.extend_from_slice(&(build_id_bytes as u32).to_le_bytes());
        note.extend_from_slice(&elf::NT_GNU_BUILD_ID.to_le_bytes());
        note.extend_from_slice(b"GNU\0");
        note.resize(note.len() + build_id_bytes, 0xA5);
        while note.len() % 4 != 0 {
            note.push(0);
        }
        let section = builder.sections.add();
        section.name = b".note.gnu.build-id"[..].into();
        section.sh_type = elf::SHT_NOTE;
        section.sh_addralign = 4;
        section.data = build::elf::SectionData::Note(note.into());
    }

    if compressed_debug_section {
        let section = builder.sections.add();
        section.name = b".zdebug_info"[..].into();
        section.sh_type = elf::SHT_PROGBITS;
        section.sh_addralign = 1;
        section.data = build::elf::SectionData::Data(b"not-loaded"[..].into());
    }

    let symbol = builder.symbols.add();
    symbol.name = b"fixture_symbol_app_main"[..].into();
    symbol.section = Some(text_id);
    symbol.set_st_info(elf::STB_GLOBAL, elf::STT_FUNC);
    symbol.st_value = 0x4037_0000;
    symbol.st_size = 0x20;

    let encoding = Encoding {
        format: Format::Dwarf32,
        version: 5,
        address_size: 4,
    };
    let mut dwarf = DwarfUnit::new(encoding);
    let root = dwarf.unit.root();
    dwarf.unit.get_mut(root).set(
        gimli::DW_AT_low_pc,
        AttributeValue::Address(WriteAddress::Constant(0x4037_0000)),
    );
    dwarf
        .unit
        .get_mut(root)
        .set(gimli::DW_AT_high_pc, AttributeValue::Udata(0x18));
    let function = dwarf.unit.add(root, gimli::DW_TAG_subprogram);
    let function_entry = dwarf.unit.get_mut(function);
    function_entry.set(
        gimli::DW_AT_name,
        AttributeValue::String(b"fixture_dwarf_app_main"[..].into()),
    );
    function_entry.set(
        gimli::DW_AT_low_pc,
        AttributeValue::Address(WriteAddress::Constant(0x4037_0000)),
    );
    function_entry.set(gimli::DW_AT_high_pc, AttributeValue::Udata(0x18));
    let mut dwarf_sections = Sections::new(EndianVec::new(LittleEndian));
    dwarf.write(&mut dwarf_sections).unwrap();
    dwarf_sections
        .for_each(|id, data| -> std::result::Result<(), ()> {
            if !data.slice().is_empty() {
                let section = builder.sections.add();
                section.name = id.name().as_bytes().to_vec().into();
                section.sh_type = elf::SHT_PROGBITS;
                section.sh_addralign = 1;
                section.data = build::elf::SectionData::Data(data.slice().to_vec().into());
            }
            Ok(())
        })
        .unwrap();

    builder.set_section_sizes();
    let segment = builder.segments.add();
    segment.p_type = elf::PT_LOAD;
    segment.p_flags = elf::PF_R | elf::PF_X;
    segment.p_offset = 0x1000;
    segment.p_vaddr = 0x4037_0000;
    segment.p_paddr = 0x4037_0000;
    segment.p_filesz = 0x40;
    segment.p_memsz = 0x40;
    segment.p_align = 0x1000;
    segment.sections.push(text_id);

    let mut bytes = Vec::new();
    builder.write(&mut bytes).unwrap();
    bytes
}

#[cfg(test)]
mod tests {
    use tempfile::tempdir;

    use super::*;

    fn frame(level: u64, address: u64) -> GdbMiStackFrame {
        GdbMiStackFrame {
            level,
            address: Address(address),
            function: None,
            file: None,
            fullname: None,
            line: None,
            module: None,
            architecture: Some("xtensa".to_string()),
            address_flags: None,
        }
    }

    #[test]
    fn executable_elf_is_inspected_and_symbolized_offline() {
        let bytes = test_executable_elf(false);
        let inspection = inspect_elf(Path::new("fixture.elf"), &bytes).unwrap();
        assert_eq!(inspection.format, "elf");
        assert_eq!(inspection.kind, "executable");
        assert_eq!(inspection.architecture, "xtensa");
        assert_eq!(inspection.address_size_bits, 32);
        assert_eq!(inspection.entry, Address(0x4037_0000));
        assert_eq!(inspection.text_symbol_count, 1);
        assert!(inspection.has_debug_info);
        assert!(!inspection.external_files_loaded);

        let annotations =
            annotate_frames(&bytes, &[frame(0, 0x4037_0010), frame(1, 0x4037_0020)]).unwrap();
        assert_eq!(annotations.resolved_frames, 2);
        assert_eq!(annotations.unresolved_frames, 0);
        assert_eq!(
            annotations.frames[0].resolution,
            OpenOcdStackElfResolution::Dwarf
        );
        assert!(!annotations.frames[0].return_address_adjusted);
        assert_eq!(annotations.frames[0].lookup_address, Address(0x4037_0010));
        assert_eq!(annotations.frames[0].external_debug_load_requests, 0);
        assert!(annotations.frames[1].return_address_adjusted);
        assert_eq!(annotations.frames[1].lookup_address, Address(0x4037_001f));
        assert_eq!(
            annotations.frames[0].inline_annotations[0]
                .function
                .as_deref(),
            Some("fixture_dwarf_app_main")
        );
        assert_eq!(
            annotations.frames[1].inline_annotations[0]
                .function
                .as_deref(),
            Some("fixture_symbol_app_main")
        );
        assert!(!annotations.runtime_firmware_identity_verified);
    }

    #[test]
    fn compressed_debug_sections_are_rejected() {
        let error =
            inspect_elf(Path::new("compressed.elf"), &test_executable_elf(true)).unwrap_err();
        assert_eq!(error.code, ErrorCode::ConfigInvalid);
        assert_eq!(error.details["section"], ".zdebug_info");
    }

    #[test]
    fn non_elf_and_non_executable_inputs_are_rejected() {
        let error = inspect_elf(Path::new("not-elf"), b"not an ELF").unwrap_err();
        assert_eq!(error.code, ErrorCode::ConfigInvalid);

        let mut object =
            object::write::Object::new(BinaryFormat::Elf, Architecture::Xtensa, Endianness::Little);
        object.add_section(Vec::new(), b".text".to_vec(), object::SectionKind::Text);
        let bytes = object.write().unwrap();
        let error = inspect_elf(Path::new("relocatable.elf"), &bytes).unwrap_err();
        assert_eq!(error.code, ErrorCode::ConfigInvalid);
        assert_eq!(error.details["observed_kind"], "Relocatable");
    }

    #[test]
    fn missing_empty_and_oversized_elf_inputs_fail_as_configuration() {
        let directory = tempdir().unwrap();
        let missing = directory.path().join("missing.elf");
        let error = read_bounded_elf(&missing).unwrap_err();
        assert_eq!(error.code, ErrorCode::ConfigInvalid);

        let empty = directory.path().join("empty.elf");
        File::create(&empty).unwrap();
        let error = read_bounded_elf(&empty).unwrap_err();
        assert_eq!(error.code, ErrorCode::ConfigInvalid);
        assert_eq!(error.details["bytes"], 0);

        let oversized = directory.path().join("oversized.elf");
        File::create(&oversized)
            .unwrap()
            .set_len(MAX_OPENOCD_STACK_ELF_BYTES + 1)
            .unwrap();
        let error = read_bounded_elf(&oversized).unwrap_err();
        assert_eq!(error.code, ErrorCode::ConfigInvalid);
        assert_eq!(error.details["maximum_bytes"], MAX_OPENOCD_STACK_ELF_BYTES);
    }

    #[test]
    fn oversized_build_id_is_rejected_before_annotation() {
        let bytes =
            test_executable_elf_options(false, Some(MAX_OPENOCD_STACK_ELF_BUILD_ID_BYTES + 1));
        let error = inspect_elf(Path::new("long-build-id.elf"), &bytes).unwrap_err();
        assert_eq!(error.code, ErrorCode::ConfigInvalid);
        assert_eq!(
            error.details["maximum_bytes"],
            MAX_OPENOCD_STACK_ELF_BUILD_ID_BYTES
        );
    }
}
