//! Narrow ARM32 RTT reader: reads one header/descriptor, never follows name pointers,
//! scans RAM, changes mode, writes a down channel, or resets/halts the core.
use probe_rs::{Core, MemoryInterface};
use serde_json::json;

use crate::{
    error::{DebugError, Result},
    rtt::{self, RttChannelInfo, RttMemoryScope, RttSelection},
};

trait RttMemory {
    fn bytes(&mut self, address: u64, output: &mut [u8]) -> Result<()>;
    fn words(&mut self, address: u64, output: &mut [u32]) -> Result<()>;
    fn write_cursor(&mut self, address: u64, cursor: u32) -> Result<()>;
}

impl RttMemory for Core<'_> {
    fn bytes(&mut self, address: u64, output: &mut [u8]) -> Result<()> {
        self.read_8(address, output)
            .map_err(|error| super::map_core_error("read RTT bytes", error))
    }
    fn words(&mut self, address: u64, output: &mut [u32]) -> Result<()> {
        self.read_32(address, output)
            .map_err(|error| super::map_core_error("read RTT descriptor", error))
    }
    fn write_cursor(&mut self, address: u64, cursor: u32) -> Result<()> {
        self.write_word_32(address, cursor)
            .map_err(|error| super::map_core_error("advance RTT read cursor", error))
    }
}

pub(super) struct NativeRttChannel {
    pub(super) info: RttChannelInfo,
    read_offset: u32,
}

impl NativeRttChannel {
    pub(super) fn open(
        core: &mut Core<'_>,
        selection: &RttSelection,
        scope: &RttMemoryScope,
    ) -> Result<Self> {
        Self::initialize(core, selection, scope)
    }

    fn initialize(
        memory: &mut impl RttMemory,
        selection: &RttSelection,
        scope: &RttMemoryScope,
    ) -> Result<Self> {
        scope.validate_selection(selection)?;
        let (info, _, read_offset) = metadata(memory, selection, scope)?;
        Ok(Self { info, read_offset })
    }

    pub(super) fn read(&mut self, core: &mut Core<'_>, maximum: usize) -> Result<Vec<u8>> {
        self.consume(core, maximum)
    }

    fn consume(&mut self, memory: &mut impl RttMemory, maximum: usize) -> Result<Vec<u8>> {
        let (info, write_offset, read_offset) =
            metadata(memory, &self.info.selection, &self.info.memory_scope)?;
        if info != self.info || read_offset != self.read_offset {
            return Err(rtt::protocol_error(
                "RTT metadata changed or another consumer advanced the read cursor",
                json!({"expected_channel": self.info, "current_channel": info, "expected_read_offset": self.read_offset, "current_read_offset": read_offset}),
            ));
        }
        let (spans, next_cursor) = rtt::ring_read_spans(&info, write_offset, read_offset, maximum)?;
        let mut data = Vec::new();
        for (address, size) in spans {
            let start = data.len();
            data.resize(start + size, 0);
            memory.bytes(address.0, &mut data[start..])?;
        }
        if !data.is_empty() {
            memory.write_cursor(info.read_cursor_address.0, next_cursor)?;
            self.read_offset = next_cursor;
        }
        Ok(data)
    }
}

fn metadata(
    memory: &mut impl RttMemory,
    selection: &RttSelection,
    scope: &RttMemoryScope,
) -> Result<(RttChannelInfo, u32, u32)> {
    let mut header = [0; 24];
    memory.bytes(selection.control_block.0, &mut header)?;
    let control_block_bytes = rtt::validate_header(&header, selection)?;
    if !scope.contains(selection.control_block, u64::from(control_block_bytes)) {
        return Err(DebugError::config(
            "RTT descriptor table exceeds the target RAM region",
            json!({"control_block_bytes": control_block_bytes, "scope": scope}),
        ));
    }
    let mut descriptor = [0; 6];
    memory.words(selection.descriptor_address().0, &mut descriptor)?;
    rtt::parse_descriptor(selection, scope, control_block_bytes, descriptor)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::Address;

    struct Memory {
        header: [u8; 24],
        descriptor: [u32; 6],
        ring: Vec<u8>,
        reads: Vec<(u64, usize)>,
        writes: Vec<(u64, u32)>,
        fail_data: bool,
        fail_write: bool,
    }
    impl Memory {
        fn new(write: u32, read: u32) -> Self {
            let mut header = [0; 24];
            header[..16].copy_from_slice(rtt::RTT_MAGIC);
            header[16..20].copy_from_slice(&1u32.to_le_bytes());
            Self {
                header,
                descriptor: [0xfffffff0, 0x20000200, 8, write, read, 0],
                ring: b"abcdefgh".to_vec(),
                reads: Vec::new(),
                writes: Vec::new(),
                fail_data: false,
                fail_write: false,
            }
        }
    }
    impl RttMemory for Memory {
        fn bytes(&mut self, address: u64, output: &mut [u8]) -> Result<()> {
            self.reads.push((address, output.len()));
            if address == 0x20000100 {
                output.copy_from_slice(&self.header);
            } else {
                if self.fail_data {
                    return Err(rtt::protocol_error("injected data failure", json!({})));
                }
                let offset = (address - 0x20000200) as usize;
                output.copy_from_slice(&self.ring[offset..offset + output.len()]);
            }
            Ok(())
        }
        fn words(&mut self, address: u64, output: &mut [u32]) -> Result<()> {
            assert_eq!(address, 0x20000118);
            output.copy_from_slice(&self.descriptor);
            Ok(())
        }
        fn write_cursor(&mut self, address: u64, cursor: u32) -> Result<()> {
            self.writes.push((address, cursor));
            if self.fail_write {
                return Err(rtt::protocol_error("injected cursor failure", json!({})));
            }
            self.descriptor[4] = cursor;
            Ok(())
        }
    }
    fn open(memory: &mut Memory) -> NativeRttChannel {
        NativeRttChannel::initialize(
            memory,
            &RttSelection {
                core: 0,
                control_block: Address(0x20000100),
                channel: 0,
            },
            &RttMemoryScope {
                start: Address(0x20000000),
                length: 0x40000,
            },
        )
        .unwrap()
    }
    #[test]
    fn wrapped_ring_reads_only_selected_bytes_and_writes_one_cursor() {
        let mut memory = Memory::new(3, 6);
        let mut channel = open(&mut memory);
        assert_eq!(channel.consume(&mut memory, 4).unwrap(), b"ghab");
        assert_eq!(memory.writes, [(0x20000128, 2)]);
        assert_eq!(channel.consume(&mut memory, 4).unwrap(), b"c");
        assert_eq!(channel.consume(&mut memory, 4).unwrap(), b"");
        assert_eq!(memory.writes.len(), 2);
        assert!(
            !memory
                .reads
                .iter()
                .any(|(address, _)| *address == 0xfffffff0)
        );
    }
    #[test]
    fn data_failure_does_not_advance_read_cursor() {
        let mut memory = Memory::new(3, 0);
        let mut channel = open(&mut memory);
        memory.fail_data = true;
        assert!(channel.consume(&mut memory, 4).is_err());
        assert!(memory.writes.is_empty());
    }
    #[test]
    fn cursor_failure_is_returned_without_retry() {
        let mut memory = Memory::new(3, 0);
        let mut channel = open(&mut memory);
        memory.fail_write = true;
        assert!(channel.consume(&mut memory, 4).is_err());
        assert_eq!(memory.writes.len(), 1);
    }
    #[test]
    fn metadata_reset_or_competing_reader_is_rejected_before_consumption() {
        let mut memory = Memory::new(3, 0);
        let mut channel = open(&mut memory);
        memory.descriptor[4] = 1;
        assert!(channel.consume(&mut memory, 4).is_err());
        assert!(memory.writes.is_empty());
        memory.descriptor[4] = 0;
        memory.descriptor[1] = 0x20000300;
        assert!(channel.consume(&mut memory, 4).is_err());
        assert!(memory.writes.is_empty());
        memory.descriptor[1] = 0x20000200;
        memory.header[0] = 0;
        assert!(channel.consume(&mut memory, 4).is_err());
        assert!(memory.writes.is_empty());
    }
    #[test]
    fn corrupted_non_ram_pointer_and_out_of_range_cursor_fail_without_data_access() {
        for descriptor in [
            [0, 0x40000000, 8, 3, 0, 0],
            [0, 0x20000200, 8, 8, 0, 0],
            [0, 0x20000118, 8, 3, 0, 0],
        ] {
            let mut memory = Memory::new(3, 0);
            memory.descriptor = descriptor;
            assert!(
                NativeRttChannel::initialize(
                    &mut memory,
                    &RttSelection {
                        core: 0,
                        control_block: Address(0x20000100),
                        channel: 0
                    },
                    &RttMemoryScope {
                        start: Address(0x20000000),
                        length: 0x40000
                    }
                )
                .is_err()
            );
            assert!(memory.writes.is_empty());
            assert_eq!(memory.reads.len(), 1);
        }
    }
}
