use anyhow::{Result, bail};
use byteorder::{LittleEndian, ReadBytesExt};
use std::io::{Cursor, Read, Seek, SeekFrom};

pub struct Tpf {
    pub textures: Vec<TpfTexture>,
}

pub struct TpfTexture {
    pub name: String,
    pub data: Vec<u8>, // Complete DDS file bytes (PC platform)
}

impl Tpf {
    /// Parse a TPF container from raw bytes (already decompressed if was DCX-wrapped)
    pub fn parse(data: &[u8]) -> Result<Self> {
        let mut r = Cursor::new(data);

        // 0x00: Magic "TPF\0"
        let mut magic = [0u8; 4];
        r.read_exact(&mut magic)?;
        if &magic != b"TPF\0" {
            bail!("Not a TPF file (magic: {:?})", magic);
        }

        // 0x04: data length
        let _data_length = r.read_i32::<LittleEndian>()?;
        // 0x08: file count
        let file_count = r.read_i32::<LittleEndian>()? as usize;
        // 0x0C: platform (0 = PC)
        let platform = r.read_u8()?;
        // 0x0D: flag2
        let _flag2 = r.read_u8()?;
        // 0x0E: encoding (0=Shift-JIS, 1=UTF-16, 2=Shift-JIS)
        let encoding = r.read_u8()?;
        // 0x0F: padding
        let _pad = r.read_u8()?;

        if platform != 0 {
            bail!("Only PC platform (0) supported, got {}", platform);
        }

        let mut textures = Vec::with_capacity(file_count);

        for _ in 0..file_count {
            // PC texture entry: 20 bytes (0x14)
            let data_offset = r.read_u32::<LittleEndian>()? as usize;
            let data_size = r.read_i32::<LittleEndian>()? as usize;
            let _format = r.read_u8()?;
            let _tex_type = r.read_u8()?;
            let _mipmaps = r.read_u8()?;
            let _flags1 = r.read_u8()?;
            let name_offset = r.read_u32::<LittleEndian>()? as u64;
            let has_float_struct = r.read_i32::<LittleEndian>()?;

            // Skip FloatStruct if present
            if has_float_struct == 1 {
                let _float_id = r.read_i32::<LittleEndian>()?;
                let float_data_len = r.read_i32::<LittleEndian>()? as i64;
                r.seek(SeekFrom::Current(float_data_len))?;
            }

            // Save position, read name
            let saved = r.position();
            r.seek(SeekFrom::Start(name_offset))?;
            let name = if encoding == 1 {
                read_utf16_string(&mut r)?
            } else {
                read_null_string(&mut r)?
            };
            r.seek(SeekFrom::Start(saved))?;

            // Read texture data
            if data_offset + data_size > data.len() {
                bail!(
                    "Texture data extends beyond TPF ({} + {} > {})",
                    data_offset, data_size, data.len()
                );
            }
            let tex_data = data[data_offset..data_offset + data_size].to_vec();

            textures.push(TpfTexture {
                name,
                data: tex_data,
            });
        }

        Ok(Tpf { textures })
    }
}

fn read_null_string(r: &mut Cursor<&[u8]>) -> Result<String> {
    let mut bytes = Vec::new();
    loop {
        let b = r.read_u8()?;
        if b == 0 { break; }
        bytes.push(b);
    }
    Ok(String::from_utf8_lossy(&bytes).into_owned())
}

fn read_utf16_string(r: &mut Cursor<&[u8]>) -> Result<String> {
    let mut units = Vec::new();
    loop {
        let lo = r.read_u8()?;
        let hi = r.read_u8()?;
        let unit = u16::from_le_bytes([lo, hi]);
        if unit == 0 { break; }
        units.push(unit);
    }
    String::from_utf16(&units).map_err(|e| anyhow::anyhow!("Invalid UTF-16: {}", e))
}

