# nightreign-map-extract

Self-contained Rust CLI that extracts and stitches world map tiles from **Elden Ring: Nightreign** game archives. No Docker, no C#/Python pipeline, no external tools beyond the Oodle shared library.

## Usage

```bash
# Auto-detect game installation (Steam), output to ./maps/
nightreign-map-extract

# Specify paths manually
nightreign-map-extract --game-dir /path/to/Game --oodle-lib ./liboo2corelinux64.so.9

# Dump individual tiles instead of stitching
nightreign-map-extract --dump-tiles

# Process a single archive
nightreign-map-extract --archive data0
```

The `--game-dir` path should point to the `Game` folder containing `data0.bhd`.

## Oodle library

The tool needs the Oodle decompression library at runtime. It searches automatically:
- Next to the executable
- Current working directory
- Game directory (Windows: `oo2core_9_win64.dll`)
- System paths (`/usr/lib`, `/usr/local/lib`)
- `LD_LIBRARY_PATH`

For Linux, grab `liboo2corelinux64.so.9` from [WorkingRobot/OodleUE](https://github.com/WorkingRobot/OodleUE) under `Engine/Source/Runtime/OodleDataCompression/Sdks/2.9.13/lib/Linux/`.

## Building

```bash
cargo build --release
```

Binary lands in `target/release/nightreign-map-extract`.

## Pipeline

```
BHD (RSA-encrypted) ──► RSA decrypt ──► BHD5 header parse
                                              │
BDT (data archive) ◄─── file offsets ─────────┘
       │
       ▼
  AES-128-ECB decrypt (if file has encrypted ranges)
       │
       ▼
  DCX decompress (Oodle Kraken)
       │
       ▼
  TPF texture container parse
       │
       ▼
  Filter MENU_MapTile_* textures
       │
       ▼
  DDS BC7_UNORM decode ──► RGBA pixels
       │
       ▼
  Group by layer + underground variant
       │
       ▼
  Stitch tiles (Y-axis flip) ──► PNG
```

## Technical notes

### RSA output block size: 255, not 256

This is the one that will bite you if you reimplement this.

FromSoftware's BHD5 archives are RSA-encrypted with raw RSA (no PKCS padding). The natural assumption is that a 2048-bit RSA key produces 256-byte output blocks (2048 / 8 = 256). **Wrong.** The output block size is **255 bytes**.

Why: FromSoftware uses BouncyCastle's RSA implementation. `RsaCoreEngine.GetOutputBlockSize()` returns `(bitSize - 1) / 8` for decryption, which is `(2048 - 1) / 8 = 255`. The engine's `ProcessBlock` returns the raw `BigInteger.toByteArray()` (variable length), and the caller zero-pads each result to 255 bytes.

So the decryption loop is:
- Read 256-byte ciphertext blocks
- Compute `m = c^e mod n` (raw modular exponentiation, no padding)
- Left-pad the result to **255** bytes with zeros
- Concatenate all 255-byte blocks to get the plaintext

If you use 256-byte output blocks, you get `\0BHD` instead of `BHD5` as the magic — the extra zero byte from each block shifts everything by one byte per block.

Reference: [BouncyCastle RsaCoreEngine.cs](https://github.com/bcgit/bc-csharp/blob/master/crypto/src/crypto/engines/RsaCoreEngine.cs), `GetOutputBlockSize()` method.

### BHD5 format (Elden Ring / Nightreign variant)

- Endian flag at offset 0x04: `0xFF` = little-endian (all ER/Nightreign)
- 64-bit detection: peek offsets 0x14 and 0x1C in decrypted header; both zero = 64-bit format
- Bucket entries: `count: i32, flag: i32, offset: i64` (16 bytes)
- File entries: `hash: u64, padded_size: i32, unpadded_size: i32, offset: i64, sha_offset: i64, aes_offset: i64`
- AES info (when aes_offset != 0): 16-byte key, then `count: i32` followed by `(start: i64, end: i64)` range pairs. Ranges with start or end == -1 are skipped. AES-128-ECB, no padding.

### DCX compression

Big-endian header. Fixed layout:
- `DCX\0` at offset 0x00
- `DCS\0` at 0x18, followed by `uncompressed_size: u32` and `compressed_size: u32`
- `DCP\0` at 0x24, algorithm name at 0x28 (only `KRAK` supported = Oodle Kraken)
- Compressed data starts at offset 0x4C

### RSA keys

7 archives with PKCS#1 public keys (`BEGIN RSA PUBLIC KEY`, not `BEGIN PUBLIC KEY`). PKCS#1 DER is just `SEQUENCE { modulus INTEGER, exponent INTEGER }`. Keys sourced from [Smithbox](https://github.com/vawser/Smithbox) and [DantelionDataManager](https://github.com/Jeongmin94/DantelionDataManager).

| Archive | Contents |
|---------|----------|
| data0 | Map tiles, most game textures |
| data1 | Additional assets |
| data2 | Additional assets |
| data3 | Additional assets |
| dlc01 | DLC content |
| sd | Sound/streaming data |
| sd_dlc01 | DLC sound (shares key with sd) |

### Tile coordinate system

Tile names follow `MENU_MapTile_L{layer}_{col}_{row}(_B{n})?`:
- First number after layer = column (X axis)
- Second number = row (Y axis)
- Y-axis must be flipped for image output: `flipped_row = max_row - row`
- `_B1` suffix = underground variant
- L0 = overworld, L1 = interior

### Known realms (8 variants)

Each TPF in data0 represents one realm. The 8 Nightreign realms:
- roundtable-hold
- roundtable-hold-alt
- limveld (base)
- limveld-frost
- limveld-volcanic
- limveld-corruption
- limveld-castle
- enir-ilim

Each realm produces up to 4 map images: surface (L0), underground (L0_B1), interior (L1), interior-underground (L1_B1).
