//! Pure `#![no_std]` reflected CRC-64/ISO (ISO 3309) checksum used by Litestream `"LTX1"`.

const CRC64_ISO_POLY: u64 = 0xD800_0000_0000_0000;
const CRC64_TABLE: [u64; 256] = build_crc64_iso_table();

const fn build_crc64_iso_table() -> [u64; 256] {
    let mut table = [0u64; 256];
    let mut i = 0usize;
    while i < 256 {
        let mut crc = i as u64;
        let mut bit = 0;
        while bit < 8 {
            crc = if (crc & 1) != 0 {
                (crc >> 1) ^ CRC64_ISO_POLY
            } else {
                crc >> 1
            };
            bit += 1;
        }
        table[i] = crc;
        i += 1;
    }
    table
}

/// Computes the reflected CRC-64/ISO (ISO 3309) checksum of `data`.
#[must_use]
pub fn crc64_iso(data: &[u8]) -> u64 {
    crc64_iso_update(0, data)
}

/// Updates a running CRC-64/ISO checksum with additional `data`.
#[must_use]
pub fn crc64_iso_update(mut crc: u64, data: &[u8]) -> u64 {
    crc = !crc;
    for &b in data {
        crc = (crc >> 8) ^ CRC64_TABLE[((crc ^ u64::from(b)) & 0xFF) as usize];
    }
    !crc
}
