use anyhow::{Result, bail};
use byteorder::{BigEndian, ReadBytesExt};
use std::io::{Cursor, Read};

use crate::oodle::Oodle;

/// Parse a DCX-compressed file and return decompressed bytes.
/// DCX is big-endian throughout. Nightreign uses KRAK (Oodle Kraken).
pub fn decompress_dcx(data: &[u8], oodle: &Oodle) -> Result<Vec<u8>> {
    let mut r = Cursor::new(data);

    // 0x00: Magic "DCX\0"
    let mut magic = [0u8; 4];
    r.read_exact(&mut magic)?;
    if &magic != b"DCX\0" {
        bail!("Not a DCX file (magic: {:?})", magic);
    }

    // 0x04: version marker (0x10000 or 0x11000)
    let _version = r.read_u32::<BigEndian>()?;
    // 0x08: DCS offset constant (0x18)
    let _dcs_offset = r.read_u32::<BigEndian>()?;
    // 0x0C: DCP offset constant (0x24)
    let _dcp_offset = r.read_u32::<BigEndian>()?;
    // 0x10: DCA offset/unk
    let _unk10 = r.read_u32::<BigEndian>()?;
    // 0x14: data start offset/unk
    let _unk14 = r.read_u32::<BigEndian>()?;

    // 0x18: DCS block
    let mut dcs_magic = [0u8; 4];
    r.read_exact(&mut dcs_magic)?;
    if &dcs_magic != b"DCS\0" {
        bail!("Expected DCS block, got {:?}", dcs_magic);
    }
    // 0x1C: uncompressed size
    let uncompressed_size = r.read_u32::<BigEndian>()? as usize;
    // 0x20: compressed size
    let compressed_size = r.read_u32::<BigEndian>()? as usize;

    // 0x24: DCP block
    let mut dcp_magic = [0u8; 4];
    r.read_exact(&mut dcp_magic)?;
    if &dcp_magic != b"DCP\0" {
        bail!("Expected DCP block, got {:?}", dcp_magic);
    }

    // 0x28: algorithm identifier
    let mut algo = [0u8; 4];
    r.read_exact(&mut algo)?;
    if &algo != b"KRAK" {
        bail!(
            "Unsupported DCX algorithm: {} (only KRAK supported)",
            std::str::from_utf8(&algo).unwrap_or("???")
        );
    }

    // 0x2C..0x44: DCP payload fields (skip)
    // 0x2C: i32 (0x20)
    // 0x30: u8 compression level + 3 pad bytes
    // 0x34..0x40: zeros
    // 0x40: i32 flags
    let mut dcp_rest = [0u8; 24]; // 0x2C to 0x44
    r.read_exact(&mut dcp_rest)?;

    // 0x44: DCA block
    let mut dca_magic = [0u8; 4];
    r.read_exact(&mut dca_magic)?;
    if &dca_magic != b"DCA\0" {
        bail!("Expected DCA block, got {:?}", dca_magic);
    }
    // 0x48: DCA size (8)
    let _dca_size = r.read_u32::<BigEndian>()?;

    // 0x4C: compressed data
    let pos = r.position() as usize;
    if pos + compressed_size > data.len() {
        bail!(
            "Compressed data extends beyond file ({} + {} > {})",
            pos, compressed_size, data.len()
        );
    }
    let compressed_data = &data[pos..pos + compressed_size];

    oodle.decompress(compressed_data, uncompressed_size)
}

pub fn is_dcx(data: &[u8]) -> bool {
    data.len() >= 4 && &data[..4] == b"DCX\0"
}
