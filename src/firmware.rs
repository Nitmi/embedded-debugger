use std::{
    fs,
    path::{Path, PathBuf},
    str::FromStr,
};

use espflash::{
    flasher::{FlashData, FlashSettings, FlashSize},
    image_format::{Metadata, idf::IdfBootloaderFormat, idf::check_idf_bootloader},
    target::Chip,
};
use serde_json::json;
use sha2::{Digest, Sha256};

use crate::{
    error::{DebugError, ErrorCode, Result},
    model::{Address, FirmwareImageOptions, FirmwareInfo, FirmwareSegmentInfo, FlashRange},
};

const MAX_FIRMWARE_BYTES: u64 = 64 * 1024 * 1024;
const MAX_INTEL_HEX_RECORDS: usize = 262_144;
const ESP_IDF_GENERATOR: &str = "espflash-4.5.0";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FirmwareFormat {
    Bin,
    IntelHex,
    EspIdf,
}

impl FirmwareFormat {
    pub const fn name(self) -> &'static str {
        match self {
            Self::Bin => "bin",
            Self::IntelHex => "hex",
            Self::EspIdf => "idf",
        }
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct FirmwareInputOptions {
    pub format: Option<FirmwareFormat>,
    pub base_address: Option<Address>,
    pub flash_size: Option<u64>,
    pub chip_revision: Option<u16>,
}

#[derive(Debug, Clone)]
pub struct FirmwareSegment {
    pub info: FirmwareSegmentInfo,
    pub data: Vec<u8>,
}

#[derive(Debug, Clone)]
pub struct LoadedFirmware {
    pub info: FirmwareInfo,
    pub segments: Vec<FirmwareSegment>,
    pending_raw_bytes: Option<Vec<u8>>,
}

impl LoadedFirmware {
    pub fn write_ranges(&self) -> Vec<FlashRange> {
        self.segments
            .iter()
            .map(|segment| FlashRange {
                start: segment.info.start,
                length: segment.info.length,
            })
            .collect()
    }

    pub fn bind_raw_segment(&mut self, start: Address) -> Result<()> {
        if self.info.format != FirmwareFormat::Bin.name() {
            return Err(DebugError::new(
                ErrorCode::Internal,
                "only raw BIN firmware can be bound to an explicit address",
                10,
                json!({"format": self.info.format}),
            ));
        }
        let data = self.pending_raw_bytes.take().ok_or_else(|| {
            DebugError::new(
                ErrorCode::Internal,
                "raw firmware bytes were already bound to an address",
                10,
                json!({"base_address": self.info.base_address}),
            )
        })?;
        let info = FirmwareSegmentInfo {
            kind: "application".to_string(),
            start,
            length: data.len() as u64,
            sha256: sha256_bytes(&data),
        };
        self.info.base_address = Some(start);
        self.info.program_size = info.length;
        self.info.segments = vec![info.clone()];
        self.segments = vec![FirmwareSegment { info, data }];
        Ok(())
    }
}

pub fn resolve_format(path: &Path, requested: Option<FirmwareFormat>) -> Result<FirmwareFormat> {
    if let Some(format) = requested {
        return Ok(format);
    }

    let extension = path
        .extension()
        .and_then(|value| value.to_str())
        .map(str::to_ascii_lowercase);
    match extension.as_deref() {
        Some("bin") => Ok(FirmwareFormat::Bin),
        Some("hex" | "ihex") => Ok(FirmwareFormat::IntelHex),
        Some("elf") => Err(DebugError::config(
            "ELF firmware is ambiguous; select --format idf for an ESP-IDF application",
            json!({"path": path, "extension": extension}),
        )),
        other => Err(DebugError::config(
            "firmware format cannot be inferred from the file extension",
            json!({
                "path": path,
                "extension": other,
                "supported_formats": ["bin", "hex", "idf"],
            }),
        )),
    }
}

pub fn load(
    path: &Path,
    target_name: &str,
    options: &FirmwareInputOptions,
) -> Result<LoadedFirmware> {
    let format = resolve_format(path, options.format)?;
    validate_options(format, options)?;
    let (canonical, source_bytes) = read_source(path)?;
    let source_sha256 = sha256_bytes(&source_bytes);
    let mut loaded = LoadedFirmware {
        info: FirmwareInfo {
            path: canonical.display().to_string(),
            format: format.name().to_string(),
            base_address: None,
            size: source_bytes.len() as u64,
            sha256: source_sha256,
            program_size: 0,
            segments: Vec::new(),
            image_options: None,
        },
        segments: Vec::new(),
        pending_raw_bytes: Some(source_bytes),
    };

    match format {
        FirmwareFormat::Bin => {}
        FirmwareFormat::IntelHex => load_intel_hex(&mut loaded, target_name)?,
        FirmwareFormat::EspIdf => load_esp_idf(&mut loaded, target_name, options)?,
    }

    Ok(loaded)
}

fn validate_options(format: FirmwareFormat, options: &FirmwareInputOptions) -> Result<()> {
    match format {
        FirmwareFormat::Bin => {
            if options.flash_size.is_some() || options.chip_revision.is_some() {
                return Err(DebugError::config(
                    "--flash-size and --chip-revision apply only to --format idf",
                    json!({"format": format.name()}),
                ));
            }
        }
        FirmwareFormat::IntelHex => {
            if options.base_address.is_some()
                || options.flash_size.is_some()
                || options.chip_revision.is_some()
            {
                return Err(DebugError::config(
                    "Intel HEX records define their physical addresses; omit --base-address, --flash-size, and --chip-revision",
                    json!({"format": format.name()}),
                ));
            }
        }
        FirmwareFormat::EspIdf => {
            if options.base_address.is_some() {
                return Err(DebugError::config(
                    "ESP-IDF images define their physical flash addresses; omit --base-address",
                    json!({"format": format.name()}),
                ));
            }
            if options.flash_size.is_none() {
                return Err(DebugError::config(
                    "ESP-IDF planning requires an explicit --flash-size",
                    json!({
                        "format": format.name(),
                        "accepted_values": supported_esp_flash_sizes(),
                    }),
                ));
            }
        }
    }
    Ok(())
}

fn read_source(path: &Path) -> Result<(PathBuf, Vec<u8>)> {
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
    Ok((canonical, bytes))
}

#[derive(Debug)]
struct IntelHexChunk {
    start: u64,
    data: Vec<u8>,
    first_line: usize,
    last_line: usize,
}

fn load_intel_hex(loaded: &mut LoadedFirmware, target_name: &str) -> Result<()> {
    let source_bytes = loaded
        .pending_raw_bytes
        .take()
        .expect("firmware source is available during Intel HEX parsing");
    let source = std::str::from_utf8(&source_bytes).map_err(|error| {
        DebugError::config(
            "Intel HEX firmware must be UTF-8 compatible ASCII text",
            json!({
                "path": loaded.info.path,
                "valid_up_to": error.valid_up_to(),
            }),
        )
    })?;

    let mut address_base = 0_u64;
    let mut chunks = Vec::new();
    let mut record_count = 0_usize;
    let mut saw_eof = false;

    for (line_index, line) in source.lines().enumerate() {
        let line_number = line_index + 1;
        if line.is_empty() {
            continue;
        }
        if saw_eof {
            return Err(DebugError::config(
                "Intel HEX contains a record after the EOF record",
                json!({"path": loaded.info.path, "line": line_number}),
            ));
        }
        record_count += 1;
        if record_count > MAX_INTEL_HEX_RECORDS {
            return Err(DebugError::config(
                "Intel HEX contains too many records",
                json!({
                    "path": loaded.info.path,
                    "line": line_number,
                    "maximum": MAX_INTEL_HEX_RECORDS,
                }),
            ));
        }
        if !line.starts_with(':') {
            return Err(DebugError::config(
                "Intel HEX record must begin with ':'",
                json!({"path": loaded.info.path, "line": line_number}),
            ));
        }
        if line.len() > 521 {
            return Err(DebugError::config(
                "Intel HEX record exceeds the maximum encoded length",
                json!({"path": loaded.info.path, "line": line_number, "length": line.len()}),
            ));
        }

        let encoded = &line[1..];
        if encoded.len() % 2 != 0 {
            return Err(DebugError::config(
                "Intel HEX record has an odd number of hexadecimal digits",
                json!({"path": loaded.info.path, "line": line_number}),
            ));
        }
        let record = hex::decode(encoded).map_err(|error| {
            DebugError::config(
                "Intel HEX record contains invalid hexadecimal data",
                json!({
                    "path": loaded.info.path,
                    "line": line_number,
                    "cause": error.to_string(),
                }),
            )
        })?;
        if record.len() < 5 {
            return Err(DebugError::config(
                "Intel HEX record is shorter than its required header and checksum",
                json!({"path": loaded.info.path, "line": line_number}),
            ));
        }

        let declared_length = usize::from(record[0]);
        if record.len() != declared_length + 5 {
            return Err(DebugError::config(
                "Intel HEX byte count does not match the record length",
                json!({
                    "path": loaded.info.path,
                    "line": line_number,
                    "declared_data_length": declared_length,
                    "actual_record_length": record.len(),
                }),
            ));
        }
        if record.iter().copied().fold(0_u8, u8::wrapping_add) != 0 {
            return Err(DebugError::config(
                "Intel HEX record checksum is invalid",
                json!({"path": loaded.info.path, "line": line_number}),
            ));
        }

        let record_address = u64::from(u16::from_be_bytes([record[1], record[2]]));
        let record_type = record[3];
        let data = &record[4..4 + declared_length];
        match record_type {
            0x00 => {
                if data.is_empty() {
                    continue;
                }
                let start = address_base.checked_add(record_address).ok_or_else(|| {
                    DebugError::config(
                        "Intel HEX data address overflowed",
                        json!({"path": loaded.info.path, "line": line_number}),
                    )
                })?;
                let end = start.checked_add(data.len() as u64).ok_or_else(|| {
                    DebugError::config(
                        "Intel HEX data range overflowed",
                        json!({"path": loaded.info.path, "line": line_number, "start": Address(start)}),
                    )
                })?;
                if end > u64::from(u32::MAX) + 1 {
                    return Err(DebugError::config(
                        "Intel HEX data range exceeds the 32-bit address space",
                        json!({
                            "path": loaded.info.path,
                            "line": line_number,
                            "start": Address(start),
                            "length": data.len(),
                        }),
                    ));
                }
                chunks.push(IntelHexChunk {
                    start,
                    data: data.to_vec(),
                    first_line: line_number,
                    last_line: line_number,
                });
            }
            0x01 => {
                require_intel_hex_record_shape(loaded, line_number, record_address, data, 0)?;
                saw_eof = true;
            }
            0x02 => {
                require_intel_hex_record_shape(loaded, line_number, record_address, data, 2)?;
                address_base = u64::from(u16::from_be_bytes([data[0], data[1]])) << 4;
            }
            0x03 => {
                require_intel_hex_record_shape(loaded, line_number, record_address, data, 4)?;
            }
            0x04 => {
                require_intel_hex_record_shape(loaded, line_number, record_address, data, 2)?;
                address_base = u64::from(u16::from_be_bytes([data[0], data[1]])) << 16;
            }
            0x05 => {
                require_intel_hex_record_shape(loaded, line_number, record_address, data, 4)?;
            }
            _ => {
                return Err(DebugError::config(
                    "Intel HEX contains an unsupported record type",
                    json!({
                        "path": loaded.info.path,
                        "line": line_number,
                        "record_type": format!("0x{record_type:02X}"),
                    }),
                ));
            }
        }
    }

    if !saw_eof {
        return Err(DebugError::config(
            "Intel HEX is missing its EOF record",
            json!({"path": loaded.info.path}),
        ));
    }
    if chunks.is_empty() {
        return Err(DebugError::config(
            "Intel HEX does not contain any data bytes",
            json!({"path": loaded.info.path}),
        ));
    }

    chunks.sort_by_key(|chunk| chunk.start);
    let mut merged: Vec<IntelHexChunk> = Vec::new();
    for chunk in chunks {
        if let Some(previous) = merged.last_mut() {
            let previous_end = previous.start + previous.data.len() as u64;
            if chunk.start < previous_end {
                return Err(DebugError::config(
                    "Intel HEX contains overlapping data records",
                    json!({
                        "path": loaded.info.path,
                        "overlap_address": Address(chunk.start),
                        "previous_first_line": previous.first_line,
                        "previous_last_line": previous.last_line,
                        "current_line": chunk.first_line,
                    }),
                ));
            }
            if chunk.start == previous_end {
                previous.data.extend_from_slice(&chunk.data);
                previous.last_line = chunk.last_line;
                continue;
            }
        }
        merged.push(chunk);
    }

    let program_size = merged.iter().try_fold(0_u64, |total, chunk| {
        total
            .checked_add(chunk.data.len() as u64)
            .filter(|size| *size <= MAX_FIRMWARE_BYTES)
            .ok_or_else(|| {
                DebugError::config(
                    "Intel HEX programmed data exceeds the allowed size",
                    json!({"path": loaded.info.path, "maximum": MAX_FIRMWARE_BYTES}),
                )
            })
    })?;
    let segments = merged
        .into_iter()
        .map(|chunk| {
            let end = chunk.start + chunk.data.len() as u64;
            let kind = if target_name.eq_ignore_ascii_case("nRF52840_xxAA")
                && chunk.start >= 0x1000_1000
                && end <= 0x1000_2000
            {
                "uicr"
            } else {
                "data"
            };
            FirmwareSegment {
                info: FirmwareSegmentInfo {
                    kind: kind.to_string(),
                    start: Address(chunk.start),
                    length: chunk.data.len() as u64,
                    sha256: sha256_bytes(&chunk.data),
                },
                data: chunk.data,
            }
        })
        .collect::<Vec<_>>();

    loaded.info.base_address = segments.first().map(|segment| segment.info.start);
    loaded.info.program_size = program_size;
    loaded.info.segments = segments
        .iter()
        .map(|segment| segment.info.clone())
        .collect();
    loaded.segments = segments;
    Ok(())
}

fn require_intel_hex_record_shape(
    loaded: &LoadedFirmware,
    line: usize,
    address: u64,
    data: &[u8],
    expected_length: usize,
) -> Result<()> {
    if address != 0 || data.len() != expected_length {
        return Err(DebugError::config(
            "Intel HEX control record has an invalid address or byte count",
            json!({
                "path": loaded.info.path,
                "line": line,
                "address": Address(address),
                "expected_data_length": expected_length,
                "actual_data_length": data.len(),
            }),
        ));
    }
    Ok(())
}

fn load_esp_idf(
    loaded: &mut LoadedFirmware,
    target_name: &str,
    options: &FirmwareInputOptions,
) -> Result<()> {
    let source_bytes = loaded
        .pending_raw_bytes
        .as_ref()
        .expect("firmware source is available during image generation");
    let target_chip_name = target_name
        .split_once('-')
        .map_or(target_name, |(name, _)| name)
        .to_ascii_lowercase();
    let chip = Chip::from_str(&target_chip_name).map_err(|error| {
        DebugError::new(
            ErrorCode::CapabilityUnavailable,
            "selected target does not support ESP-IDF image generation",
            6,
            json!({
                "target": target_name,
                "format": FirmwareFormat::EspIdf.name(),
                "cause": error.to_string(),
            }),
        )
    })?;
    let flash_size_bytes = options
        .flash_size
        .expect("ESP-IDF options were validated before image generation");
    let flash_size = esp_flash_size(flash_size_bytes)?;
    let chip_revision = options.chip_revision.unwrap_or_default();

    check_idf_bootloader(source_bytes).map_err(|error| {
        DebugError::config(
            "firmware is not a valid ESP-IDF application ELF",
            json!({
                "path": loaded.info.path,
                "target": target_name,
                "cause": error.to_string(),
            }),
        )
    })?;

    let metadata = Metadata::from_bytes(Some(source_bytes));
    if let Some(image_chip) = metadata.chip_name()
        && !image_chip.eq_ignore_ascii_case(&target_chip_name)
    {
        return Err(DebugError::config(
            "ESP-IDF image metadata does not match the selected target",
            json!({
                "target": target_name,
                "image_chip": image_chip,
            }),
        ));
    }

    let flash_data = FlashData::new(
        FlashSettings::new(None, Some(flash_size), None),
        chip_revision,
        None,
        chip,
        chip.default_xtal_frequency(),
    );
    let image = IdfBootloaderFormat::new(source_bytes, &flash_data, None, None, None, None)
        .map_err(|error| {
            DebugError::config(
                "failed to generate the ESP-IDF physical flash image",
                json!({
                    "path": loaded.info.path,
                    "target": target_name,
                    "flash_size": flash_size_bytes,
                    "chip_revision": chip_revision,
                    "cause": error.to_string(),
                }),
            )
        })?;

    let kinds = ["bootloader", "partition_table", "application"];
    let image_segments = image.flash_segments().collect::<Vec<_>>();
    if image_segments.len() != kinds.len() {
        return Err(DebugError::new(
            ErrorCode::Internal,
            "ESP-IDF image generator returned an unexpected segment layout",
            10,
            json!({
                "path": loaded.info.path,
                "target": target_name,
                "expected_segment_count": kinds.len(),
                "actual_segment_count": image_segments.len(),
            }),
        ));
    }
    let mut segments = image_segments
        .into_iter()
        .zip(kinds)
        .map(|(segment, kind)| {
            let data = segment.data.into_owned();
            FirmwareSegment {
                info: FirmwareSegmentInfo {
                    kind: kind.to_string(),
                    start: Address(u64::from(segment.addr)),
                    length: data.len() as u64,
                    sha256: sha256_bytes(&data),
                },
                data,
            }
        })
        .collect::<Vec<_>>();
    segments.sort_by_key(|segment| segment.info.start.0);

    let program_size = segments.iter().try_fold(0_u64, |total, segment| {
        total.checked_add(segment.info.length).ok_or_else(|| {
            DebugError::new(
                ErrorCode::Internal,
                "generated ESP-IDF image size overflowed",
                10,
                json!({"path": loaded.info.path}),
            )
        })
    })?;
    loaded.info.base_address = segments.first().map(|segment| segment.info.start);
    loaded.info.program_size = program_size;
    loaded.info.segments = segments
        .iter()
        .map(|segment| segment.info.clone())
        .collect();
    loaded.info.image_options = Some(FirmwareImageOptions {
        generator: ESP_IDF_GENERATOR.to_string(),
        target_chip: target_chip_name,
        flash_size: flash_size_bytes,
        chip_revision,
    });
    loaded.segments = segments;
    loaded.pending_raw_bytes = None;
    Ok(())
}

pub fn parse_esp_flash_size(value: &str) -> std::result::Result<u64, String> {
    let size = FlashSize::from_str(value).map_err(|_| {
        format!(
            "unsupported flash size {value:?}; expected one of {}",
            supported_esp_flash_sizes().join(", ")
        )
    })?;
    let bytes = u64::from(size.size());
    if esp_flash_size(bytes).is_err() {
        return Err(format!(
            "unsupported ESP-IDF image flash size {value:?}; expected one of {}",
            supported_esp_flash_sizes().join(", ")
        ));
    }
    Ok(bytes)
}

fn esp_flash_size(bytes: u64) -> Result<FlashSize> {
    let size = match bytes {
        0x10_0000 => FlashSize::_1Mb,
        0x20_0000 => FlashSize::_2Mb,
        0x40_0000 => FlashSize::_4Mb,
        0x80_0000 => FlashSize::_8Mb,
        0x100_0000 => FlashSize::_16Mb,
        0x200_0000 => FlashSize::_32Mb,
        0x400_0000 => FlashSize::_64Mb,
        0x800_0000 => FlashSize::_128Mb,
        0x1000_0000 => FlashSize::_256Mb,
        _ => {
            return Err(DebugError::config(
                "unsupported ESP-IDF image flash size",
                json!({
                    "flash_size": bytes,
                    "accepted_values": supported_esp_flash_sizes(),
                }),
            ));
        }
    };
    Ok(size)
}

fn supported_esp_flash_sizes() -> Vec<&'static str> {
    vec![
        "1MB", "2MB", "4MB", "8MB", "16MB", "32MB", "64MB", "128MB", "256MB",
    ]
}

fn sha256_bytes(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn elf_requires_an_explicit_format() {
        let error = resolve_format(Path::new("firmware.elf"), None).unwrap_err();

        assert_eq!(error.code, ErrorCode::ConfigInvalid);
        assert!(error.message.contains("--format idf"));
    }

    #[test]
    fn hex_extension_is_inferred() {
        assert_eq!(
            resolve_format(Path::new("firmware.hex"), None).unwrap(),
            FirmwareFormat::IntelHex
        );
    }

    #[test]
    fn intel_hex_loads_sparse_segments_and_marks_nrf52840_uicr() {
        let directory = tempdir().unwrap();
        let path = directory.path().join("firmware.hex");
        let records = [
            intel_hex_record(0, 0x04, &[0x00, 0x00]),
            intel_hex_record(0x1000, 0x00, &[1, 2, 3, 4]),
            intel_hex_record(0x1004, 0x00, &[5, 6]),
            intel_hex_record(0, 0x04, &[0x10, 0x00]),
            intel_hex_record(0x1014, 0x00, &[0x00, 0x80, 0x0f, 0x00]),
            intel_hex_record(0, 0x01, &[]),
        ];
        fs::write(&path, records.join("\n")).unwrap();

        let loaded = load(&path, "nRF52840_xxAA", &FirmwareInputOptions::default()).unwrap();

        assert_eq!(loaded.info.format, "hex");
        assert_eq!(loaded.info.program_size, 10);
        assert_eq!(loaded.info.segments.len(), 2);
        assert_eq!(loaded.info.segments[0].start, Address(0x1000));
        assert_eq!(loaded.info.segments[0].length, 6);
        assert_eq!(loaded.info.segments[0].kind, "data");
        assert_eq!(loaded.info.segments[1].start, Address(0x1000_1014));
        assert_eq!(loaded.info.segments[1].kind, "uicr");
    }

    #[test]
    fn intel_hex_rejects_bad_checksum() {
        let directory = tempdir().unwrap();
        let path = directory.path().join("bad.hex");
        fs::write(&path, ":0400000001020304F3\n:00000001FF\n").unwrap();

        let error = load(&path, "nRF52840_xxAA", &FirmwareInputOptions::default()).unwrap_err();

        assert_eq!(error.code, ErrorCode::ConfigInvalid);
        assert!(error.message.contains("checksum"));
    }

    #[test]
    fn intel_hex_rejects_overlapping_data_records() {
        let directory = tempdir().unwrap();
        let path = directory.path().join("overlap.hex");
        let records = [
            intel_hex_record(0x1000, 0x00, &[1, 2, 3, 4]),
            intel_hex_record(0x1002, 0x00, &[3, 4, 5, 6]),
            intel_hex_record(0, 0x01, &[]),
        ];
        fs::write(&path, records.join("\n")).unwrap();

        let error = load(&path, "nRF52840_xxAA", &FirmwareInputOptions::default()).unwrap_err();

        assert_eq!(error.code, ErrorCode::ConfigInvalid);
        assert!(error.message.contains("overlapping"));
    }

    #[test]
    fn idf_requires_explicit_flash_size_before_reading_the_file() {
        let error = load(
            Path::new("missing.elf"),
            "esp32s3",
            &FirmwareInputOptions {
                format: Some(FirmwareFormat::EspIdf),
                ..FirmwareInputOptions::default()
            },
        )
        .unwrap_err();

        assert_eq!(error.code, ErrorCode::ConfigInvalid);
        assert!(error.message.contains("--flash-size"));
    }

    #[test]
    fn idf_generation_produces_three_hashed_physical_segments() {
        let directory = tempdir().unwrap();
        let path = directory.path().join("minimal.elf");
        fs::write(&path, minimal_esp32s3_idf_elf()).unwrap();

        let loaded = load(
            &path,
            "esp32s3",
            &FirmwareInputOptions {
                format: Some(FirmwareFormat::EspIdf),
                flash_size: Some(8 * 1024 * 1024),
                chip_revision: Some(0),
                base_address: None,
            },
        )
        .unwrap();

        assert_eq!(loaded.info.format, "idf");
        assert_eq!(loaded.info.segments.len(), 3);
        assert_eq!(loaded.info.segments[0].kind, "bootloader");
        assert_eq!(loaded.info.segments[0].start, Address(0));
        assert_eq!(loaded.info.segments[1].kind, "partition_table");
        assert_eq!(loaded.info.segments[1].start, Address(0x8000));
        assert_eq!(loaded.info.segments[2].kind, "application");
        assert_eq!(loaded.info.segments[2].start, Address(0x1_0000));
        assert_eq!(
            loaded.info.program_size,
            loaded
                .info
                .segments
                .iter()
                .map(|item| item.length)
                .sum::<u64>()
        );
        assert!(
            loaded
                .info
                .segments
                .iter()
                .all(|item| item.sha256.len() == 64)
        );
        assert_eq!(
            loaded.info.image_options.as_ref().unwrap().flash_size,
            8 * 1024 * 1024
        );
    }

    // A minimal ELF32 executable with one allocated ESP32-S3 DROM section.
    // The first 256 bytes form the ESP-IDF app descriptor expected by espflash.
    pub(crate) fn minimal_esp32s3_idf_elf() -> Vec<u8> {
        minimal_idf_elf(94, 0x4037_0000, 0x3c00_0020)
    }

    pub(crate) fn minimal_esp32c3_idf_elf() -> Vec<u8> {
        minimal_idf_elf(243, 0x4038_0000, 0x3c00_0020)
    }

    fn minimal_idf_elf(machine: u16, entry: u32, app_address: u32) -> Vec<u8> {
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
        put_u16(&mut bytes, 18, machine);
        put_u32(&mut bytes, 20, 1);
        put_u32(&mut bytes, 24, entry);
        put_u32(&mut bytes, 32, SECTION_HEADERS_OFFSET as u32);
        put_u16(&mut bytes, 40, ELF_HEADER_SIZE as u16);
        put_u16(&mut bytes, 46, SECTION_HEADER_SIZE as u16);
        put_u16(&mut bytes, 48, SECTION_COUNT as u16);
        put_u16(&mut bytes, 50, 2);

        put_u32(&mut bytes, APP_OFFSET, 0xABCD_5432);
        bytes[NAMES_OFFSET..NAMES_OFFSET + names.len()].copy_from_slice(names);

        let app = SECTION_HEADERS_OFFSET + SECTION_HEADER_SIZE;
        put_u32(&mut bytes, app, 1);
        put_u32(&mut bytes, app + 4, 1);
        put_u32(&mut bytes, app + 8, 2);
        put_u32(&mut bytes, app + 12, app_address);
        put_u32(&mut bytes, app + 16, APP_OFFSET as u32);
        put_u32(&mut bytes, app + 20, 256);
        put_u32(&mut bytes, app + 32, 4);

        let strings = SECTION_HEADERS_OFFSET + SECTION_HEADER_SIZE * 2;
        put_u32(&mut bytes, strings, 16);
        put_u32(&mut bytes, strings + 4, 3);
        put_u32(&mut bytes, strings + 16, NAMES_OFFSET as u32);
        put_u32(&mut bytes, strings + 20, names.len() as u32);
        put_u32(&mut bytes, strings + 32, 1);
        bytes
    }

    fn intel_hex_record(address: u16, record_type: u8, data: &[u8]) -> String {
        let mut bytes = Vec::with_capacity(data.len() + 5);
        bytes.push(data.len() as u8);
        bytes.extend_from_slice(&address.to_be_bytes());
        bytes.push(record_type);
        bytes.extend_from_slice(data);
        let checksum = 0_u8.wrapping_sub(bytes.iter().copied().fold(0_u8, u8::wrapping_add));
        bytes.push(checksum);
        format!(":{}", hex::encode_upper(bytes))
    }

    fn put_u16(bytes: &mut [u8], offset: usize, value: u16) {
        bytes[offset..offset + 2].copy_from_slice(&value.to_le_bytes());
    }

    fn put_u32(bytes: &mut [u8], offset: usize, value: u32) {
        bytes[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
    }
}
