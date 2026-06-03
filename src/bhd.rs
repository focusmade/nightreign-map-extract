use anyhow::{Context, Result, bail};
use byteorder::{LittleEndian, ReadBytesExt};
use std::fs;
use std::io::{Cursor, Read, Seek, SeekFrom};
use std::path::Path;

use crate::rsa;

#[derive(Debug)]
pub struct Bhd5 {
    pub file_headers: Vec<FileHeader>,
}

#[derive(Debug)]
pub struct FileHeader {
    #[allow(dead_code)]
    pub file_name_hash: u64,
    pub padded_file_size: i32,
    pub unpadded_file_size: i32,
    pub file_offset: i64,
    pub aes_key: Option<AesKeyInfo>,
}

#[derive(Debug)]
pub struct AesKeyInfo {
    pub key: [u8; 16],
    pub ranges: Vec<(i64, i64)>,
}

impl Bhd5 {
    /// Read and RSA-decrypt a .bhd file, then parse the BHD5 header.
    pub fn open(bhd_path: &Path, rsa_key_pem: &str) -> Result<Self> {
        let encrypted = fs::read(bhd_path)
            .with_context(|| format!("Failed to read {}", bhd_path.display()))?;

        let (n, e) = rsa::parse_pkcs1_public_key(rsa_key_pem)
            .context("Failed to parse RSA public key")?;

        let decrypted = rsa::rsa_decrypt(&encrypted, &n, &e);

        Self::parse(&decrypted)
    }

    fn parse(data: &[u8]) -> Result<Self> {
        let mut r = Cursor::new(data);

        // Magic: "BHD5"
        let mut magic = [0u8; 4];
        r.read_exact(&mut magic)?;
        if &magic != b"BHD5" {
            bail!("Not a BHD5 file (magic: {:?}). RSA decryption may have failed.", magic);
        }

        let endian_flag = r.read_i8()?; // 0=big-endian, -1=little-endian
        let _unk05 = r.read_u8()?;
        let _pad1 = r.read_u8()?;
        let _pad2 = r.read_u8()?;

        // For Nightreign/ER, it's little-endian (endian_flag == -1 / 0xFF)
        // We'll assume LE since that's what ER uses
        if endian_flag != -1 {
            bail!("Expected little-endian BHD5 (got endian flag {})", endian_flag);
        }

        let version = r.read_i32::<LittleEndian>()?;
        if version != 1 {
            bail!("Unexpected BHD5 version: {}", version);
        }
        let _file_size = r.read_i32::<LittleEndian>()?;

        // Detect 64-bit format (Elden Ring):
        // Peek at offsets 0x14 and 0x1C — if both are 0, it's 64-bit
        let saved_pos = r.position();
        r.seek(SeekFrom::Start(0x14))?;
        let test0 = r.read_i32::<LittleEndian>()?;
        r.seek(SeekFrom::Start(0x1C))?;
        let test1 = r.read_i32::<LittleEndian>()?;
        let is_64bit = test0 == 0 && test1 == 0;
        r.seek(SeekFrom::Start(saved_pos))?;

        let (bucket_count, buckets_offset) = if is_64bit {
            let bc = r.read_i64::<LittleEndian>()? as usize;
            let bo = r.read_i64::<LittleEndian>()? as u64;
            (bc, bo)
        } else {
            let bc = r.read_i32::<LittleEndian>()? as usize;
            let bo = r.read_i32::<LittleEndian>()? as u64;
            (bc, bo)
        };

        // Salt (ER format includes it)
        let salt_length = r.read_i32::<LittleEndian>()?;
        if salt_length > 0 {
            let mut salt = vec![0u8; salt_length as usize];
            r.read_exact(&mut salt)?;
        }

        // Parse buckets
        let mut file_headers = Vec::new();
        r.seek(SeekFrom::Start(buckets_offset))?;

        for _ in 0..bucket_count {
            let file_header_count = r.read_i32::<LittleEndian>()? as usize;

            let file_headers_offset = if is_64bit {
                let _unk = r.read_i32::<LittleEndian>()?; // assert 1 in 64-bit mode
                r.read_i64::<LittleEndian>()? as u64
            } else {
                r.read_i32::<LittleEndian>()? as u64
            };

            let saved = r.position();
            r.seek(SeekFrom::Start(file_headers_offset))?;

            for _ in 0..file_header_count {
                let fh = Self::read_file_header(&mut r, data, is_64bit)?;
                file_headers.push(fh);
            }

            r.seek(SeekFrom::Start(saved))?;
        }

        Ok(Bhd5 { file_headers })
    }

    fn read_file_header(r: &mut Cursor<&[u8]>, _data: &[u8], _is_64bit: bool) -> Result<FileHeader> {
        // Elden Ring format (64-bit): hash(u64), paddedSize(i32), unpaddedSize(i32),
        // offset(i64), shaOffset(i64), aesOffset(i64)
        let file_name_hash = r.read_u64::<LittleEndian>()?;
        let padded_file_size = r.read_i32::<LittleEndian>()?;
        let unpadded_file_size = r.read_i32::<LittleEndian>()?;
        let file_offset = r.read_i64::<LittleEndian>()?;
        let _sha_hash_offset = r.read_i64::<LittleEndian>()?;
        let aes_key_offset = r.read_i64::<LittleEndian>()?;

        let mut aes_key = None;
        if aes_key_offset != 0 {
            let saved = r.position();
            r.seek(SeekFrom::Start(aes_key_offset as u64))?;

            let mut key = [0u8; 16];
            r.read_exact(&mut key)?;
            let range_count = r.read_i32::<LittleEndian>()? as usize;
            let mut ranges = Vec::with_capacity(range_count);
            for _ in 0..range_count {
                let start = r.read_i64::<LittleEndian>()?;
                let end = r.read_i64::<LittleEndian>()?;
                ranges.push((start, end));
            }
            aes_key = Some(AesKeyInfo { key, ranges });

            r.seek(SeekFrom::Start(saved))?;
        }

        Ok(FileHeader {
            file_name_hash,
            padded_file_size,
            unpadded_file_size,
            file_offset,
            aes_key,
        })
    }
}

impl FileHeader {
    /// Read file data from the BDT, applying AES decryption if needed
    pub fn read_from_bdt(&self, bdt_data: &[u8]) -> Result<Vec<u8>> {
        let offset = self.file_offset as usize;
        let size = self.padded_file_size as usize;

        if offset + size > bdt_data.len() {
            bail!(
                "File offset+size ({} + {}) exceeds BDT size ({})",
                offset, size, bdt_data.len()
            );
        }

        let mut bytes = bdt_data[offset..offset + size].to_vec();

        if let Some(ref aes) = self.aes_key {
            aes_decrypt_ranges(&mut bytes, &aes.key, &aes.ranges)?;
        }

        // Truncate to unpadded size
        let actual_size = if self.unpadded_file_size > 0 {
            self.unpadded_file_size as usize
        } else {
            size
        };
        bytes.truncate(actual_size);

        Ok(bytes)
    }
}

/// AES-128-ECB decryption of specified ranges in-place
fn aes_decrypt_ranges(data: &mut [u8], key: &[u8; 16], ranges: &[(i64, i64)]) -> Result<()> {
    use std::convert::TryInto;

    for &(start, end) in ranges {
        if start == -1 || end == -1 || start == end {
            continue;
        }
        let s = start as usize;
        let e = end as usize;
        if e > data.len() {
            continue;
        }

        let slice = &mut data[s..e];
        // AES-128-ECB: process in 16-byte blocks
        for block in slice.chunks_exact_mut(16) {
            let mut state: [u8; 16] = block.try_into().unwrap();
            aes_ecb_decrypt_block(&mut state, key);
            block.copy_from_slice(&state);
        }
    }
    Ok(())
}

/// Single-block AES-128-ECB decrypt (simple implementation)
fn aes_ecb_decrypt_block(block: &mut [u8; 16], key: &[u8; 16]) {
    // AES-128: 10 rounds, 44 round keys
    let round_keys = aes_key_expansion(key);

    let mut state = *block;

    // Initial round (add round key 10)
    xor_block(&mut state, &round_keys[10]);

    // Rounds 9..1
    for round in (1..10).rev() {
        inv_shift_rows(&mut state);
        inv_sub_bytes(&mut state);
        xor_block(&mut state, &round_keys[round]);
        inv_mix_columns(&mut state);
    }

    // Final round (round 0)
    inv_shift_rows(&mut state);
    inv_sub_bytes(&mut state);
    xor_block(&mut state, &round_keys[0]);

    *block = state;
}

fn xor_block(state: &mut [u8; 16], key: &[u8; 16]) {
    for i in 0..16 {
        state[i] ^= key[i];
    }
}

const SBOX: [u8; 256] = [
    0x63,0x7c,0x77,0x7b,0xf2,0x6b,0x6f,0xc5,0x30,0x01,0x67,0x2b,0xfe,0xd7,0xab,0x76,
    0xca,0x82,0xc9,0x7d,0xfa,0x59,0x47,0xf0,0xad,0xd4,0xa2,0xaf,0x9c,0xa4,0x72,0xc0,
    0xb7,0xfd,0x93,0x26,0x36,0x3f,0xf7,0xcc,0x34,0xa5,0xe5,0xf1,0x71,0xd8,0x31,0x15,
    0x04,0xc7,0x23,0xc3,0x18,0x96,0x05,0x9a,0x07,0x12,0x80,0xe2,0xeb,0x27,0xb2,0x75,
    0x09,0x83,0x2c,0x1a,0x1b,0x6e,0x5a,0xa0,0x52,0x3b,0xd6,0xb3,0x29,0xe3,0x2f,0x84,
    0x53,0xd1,0x00,0xed,0x20,0xfc,0xb1,0x5b,0x6a,0xcb,0xbe,0x39,0x4a,0x4c,0x58,0xcf,
    0xd0,0xef,0xaa,0xfb,0x43,0x4d,0x33,0x85,0x45,0xf9,0x02,0x7f,0x50,0x3c,0x9f,0xa8,
    0x51,0xa3,0x40,0x8f,0x92,0x9d,0x38,0xf5,0xbc,0xb6,0xda,0x21,0x10,0xff,0xf3,0xd2,
    0xcd,0x0c,0x13,0xec,0x5f,0x97,0x44,0x17,0xc4,0xa7,0x7e,0x3d,0x64,0x5d,0x19,0x73,
    0x60,0x81,0x4f,0xdc,0x22,0x2a,0x90,0x88,0x46,0xee,0xb8,0x14,0xde,0x5e,0x0b,0xdb,
    0xe0,0x32,0x3a,0x0a,0x49,0x06,0x24,0x5c,0xc2,0xd3,0xac,0x62,0x91,0x95,0xe4,0x79,
    0xe7,0xc8,0x37,0x6d,0x8d,0xd5,0x4e,0xa9,0x6c,0x56,0xf4,0xea,0x65,0x7a,0xae,0x08,
    0xba,0x78,0x25,0x2e,0x1c,0xa6,0xb4,0xc6,0xe8,0xdd,0x74,0x1f,0x4b,0xbd,0x8b,0x8a,
    0x70,0x3e,0xb5,0x66,0x48,0x03,0xf6,0x0e,0x61,0x35,0x57,0xb9,0x86,0xc1,0x1d,0x9e,
    0xe1,0xf8,0x98,0x11,0x69,0xd9,0x8e,0x94,0x9b,0x1e,0x87,0xe9,0xce,0x55,0x28,0xdf,
    0x8c,0xa1,0x89,0x0d,0xbf,0xe6,0x42,0x68,0x41,0x99,0x2d,0x0f,0xb0,0x54,0xbb,0x16,
];

const INV_SBOX: [u8; 256] = [
    0x52,0x09,0x6a,0xd5,0x30,0x36,0xa5,0x38,0xbf,0x40,0xa3,0x9e,0x81,0xf3,0xd7,0xfb,
    0x7c,0xe3,0x39,0x82,0x9b,0x2f,0xff,0x87,0x34,0x8e,0x43,0x44,0xc4,0xde,0xe9,0xcb,
    0x54,0x7b,0x94,0x32,0xa6,0xc2,0x23,0x3d,0xee,0x4c,0x95,0x0b,0x42,0xfa,0xc3,0x4e,
    0x08,0x2e,0xa1,0x66,0x28,0xd9,0x24,0xb2,0x76,0x5b,0xa2,0x49,0x6d,0x8b,0xd1,0x25,
    0x72,0xf8,0xf6,0x64,0x86,0x68,0x98,0x16,0xd4,0xa4,0x5c,0xcc,0x5d,0x65,0xb6,0x92,
    0x6c,0x70,0x48,0x50,0xfd,0xed,0xb9,0xda,0x5e,0x15,0x46,0x57,0xa7,0x8d,0x9d,0x84,
    0x90,0xd8,0xab,0x00,0x8c,0xbc,0xd3,0x0a,0xf7,0xe4,0x58,0x05,0xb8,0xb3,0x45,0x06,
    0xd0,0x2c,0x1e,0x8f,0xca,0x3f,0x0f,0x02,0xc1,0xaf,0xbd,0x03,0x01,0x13,0x8a,0x6b,
    0x3a,0x91,0x11,0x41,0x4f,0x67,0xdc,0xea,0x97,0xf2,0xcf,0xce,0xf0,0xb4,0xe6,0x73,
    0x96,0xac,0x74,0x22,0xe7,0xad,0x35,0x85,0xe2,0xf9,0x37,0xe8,0x1c,0x75,0xdf,0x6e,
    0x47,0xf1,0x1a,0x71,0x1d,0x29,0xc5,0x89,0x6f,0xb7,0x62,0x0e,0xaa,0x18,0xbe,0x1b,
    0xfc,0x56,0x3e,0x4b,0xc6,0xd2,0x79,0x20,0x9a,0xdb,0xc0,0xfe,0x78,0xcd,0x5a,0xf4,
    0x1f,0xdd,0xa8,0x33,0x88,0x07,0xc7,0x31,0xb1,0x12,0x10,0x59,0x27,0x80,0xec,0x5f,
    0x60,0x51,0x7f,0xa9,0x19,0xb5,0x4a,0x0d,0x2d,0xe5,0x7a,0x9f,0x93,0xc9,0x9c,0xef,
    0xa0,0xe0,0x3b,0x4d,0xae,0x2a,0xf5,0xb0,0xc8,0xeb,0xbb,0x3c,0x83,0x53,0x99,0x61,
    0x17,0x2b,0x04,0x7e,0xba,0x77,0xd6,0x26,0xe1,0x69,0x14,0x63,0x55,0x21,0x0c,0x7d,
];

const RCON: [u8; 10] = [0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36];

fn aes_key_expansion(key: &[u8; 16]) -> [[u8; 16]; 11] {
    let mut w = [0u32; 44];
    for i in 0..4 {
        w[i] = u32::from_be_bytes([key[4*i], key[4*i+1], key[4*i+2], key[4*i+3]]);
    }
    for i in 4..44 {
        let mut temp = w[i - 1];
        if i % 4 == 0 {
            temp = sub_word(rot_word(temp)) ^ ((RCON[i/4 - 1] as u32) << 24);
        }
        w[i] = w[i - 4] ^ temp;
    }

    let mut round_keys = [[0u8; 16]; 11];
    for r in 0..11 {
        for j in 0..4 {
            let bytes = w[r * 4 + j].to_be_bytes();
            round_keys[r][4*j..4*j+4].copy_from_slice(&bytes);
        }
    }
    round_keys
}

fn rot_word(w: u32) -> u32 { w.rotate_left(8) }

fn sub_word(w: u32) -> u32 {
    let b = w.to_be_bytes();
    u32::from_be_bytes([SBOX[b[0] as usize], SBOX[b[1] as usize], SBOX[b[2] as usize], SBOX[b[3] as usize]])
}

fn inv_sub_bytes(state: &mut [u8; 16]) {
    for b in state.iter_mut() { *b = INV_SBOX[*b as usize]; }
}

fn inv_shift_rows(s: &mut [u8; 16]) {
    // Row 1: shift right 1 (column-major: indices 1,5,9,13)
    let t = s[13]; s[13] = s[9]; s[9] = s[5]; s[5] = s[1]; s[1] = t;
    // Row 2: shift right 2 (indices 2,6,10,14)
    let (t0, t1) = (s[2], s[6]); s[2] = s[10]; s[6] = s[14]; s[10] = t0; s[14] = t1;
    // Row 3: shift right 3 = shift left 1 (indices 3,7,11,15)
    let t = s[3]; s[3] = s[7]; s[7] = s[11]; s[11] = s[15]; s[15] = t;
}

fn inv_mix_columns(s: &mut [u8; 16]) {
    for col in 0..4 {
        let i = col * 4;
        let (a0, a1, a2, a3) = (s[i], s[i+1], s[i+2], s[i+3]);
        s[i]   = gf_mul(a0, 0x0e) ^ gf_mul(a1, 0x0b) ^ gf_mul(a2, 0x0d) ^ gf_mul(a3, 0x09);
        s[i+1] = gf_mul(a0, 0x09) ^ gf_mul(a1, 0x0e) ^ gf_mul(a2, 0x0b) ^ gf_mul(a3, 0x0d);
        s[i+2] = gf_mul(a0, 0x0d) ^ gf_mul(a1, 0x09) ^ gf_mul(a2, 0x0e) ^ gf_mul(a3, 0x0b);
        s[i+3] = gf_mul(a0, 0x0b) ^ gf_mul(a1, 0x0d) ^ gf_mul(a2, 0x09) ^ gf_mul(a3, 0x0e);
    }
}

fn gf_mul(mut a: u8, mut b: u8) -> u8 {
    let mut result = 0u8;
    while b != 0 {
        if b & 1 != 0 { result ^= a; }
        let hi = a & 0x80;
        a <<= 1;
        if hi != 0 { a ^= 0x1b; }
        b >>= 1;
    }
    result
}
