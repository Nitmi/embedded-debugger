pub fn minimal_esp32s3_idf_elf() -> Vec<u8> {
    minimal_idf_elf(94, 0x4037_0000, 0x3c00_0020)
}

pub fn minimal_esp32c3_idf_elf() -> Vec<u8> {
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
