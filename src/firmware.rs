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
const ESP_IDF_GENERATOR: &str = "espflash-4.5.0";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FirmwareFormat {
    Bin,
    EspIdf,
}

impl FirmwareFormat {
    pub const fn name(self) -> &'static str {
        match self {
            Self::Bin => "bin",
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
        Some("elf") => Err(DebugError::config(
            "ELF firmware is ambiguous; select --format idf for an ESP-IDF application",
            json!({"path": path, "extension": extension}),
        )),
        other => Err(DebugError::config(
            "firmware format cannot be inferred from the file extension",
            json!({
                "path": path,
                "extension": other,
                "supported_formats": ["bin", "idf"],
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

    if format == FirmwareFormat::EspIdf {
        load_esp_idf(&mut loaded, target_name, options)?;
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

    fn put_u16(bytes: &mut [u8], offset: usize, value: u16) {
        bytes[offset..offset + 2].copy_from_slice(&value.to_le_bytes());
    }

    fn put_u32(bytes: &mut [u8], offset: usize, value: u32) {
        bytes[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
    }
}
