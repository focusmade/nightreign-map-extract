mod bhd;
mod dcx;
mod keys;
mod oodle;
mod rsa;
mod steam;
mod stitch;
mod tpf;

use anyhow::{Context, Result};
use clap::Parser;
use indicatif::{ProgressBar, ProgressStyle};
use std::path::PathBuf;
use std::time::Instant;

const BOLD: &str = "\x1b[1m";
const DIM: &str = "\x1b[2m";
const RESET: &str = "\x1b[0m";
const GREEN: &str = "\x1b[32m";
const YELLOW: &str = "\x1b[33m";
const CYAN: &str = "\x1b[36m";

struct RealmInfo {
    hash: u64,
    name: &'static str,
}

const REALMS: &[RealmInfo] = &[
    RealmInfo { hash: 0xA28A0C950AA06C27, name: "limveld" },
    RealmInfo { hash: 0xA7F963AB16C713AB, name: "enir-ilim" },
    RealmInfo { hash: 0xA3E5E25A8DAA1608, name: "limveld-frost" },
    RealmInfo { hash: 0x57401C321EA5AE0C, name: "roundtable-hold" },
    RealmInfo { hash: 0xA955397099D0BD8C, name: "limveld-castle" },
    RealmInfo { hash: 0xA541B82010B3BFE9, name: "limveld-volcanic" },
    RealmInfo { hash: 0x589BF1F7A1AF57ED, name: "roundtable-hold-alt" },
    RealmInfo { hash: 0xA69D8DE593BD69CA, name: "limveld-corruption" },
];

fn realm_name(hash: u64) -> Option<&'static str> {
    REALMS.iter().find(|r| r.hash == hash).map(|r| r.name)
}

#[derive(Parser)]
#[command(name = "nightreign-map-extract")]
#[command(about = "Extract and stitch map tiles from Elden Ring: Nightreign")]
struct Args {
    /// Path to the game's 'Game' directory (auto-detected from Steam if omitted)
    #[arg(long)]
    game_dir: Option<PathBuf>,

    /// Path to Oodle decompression library (auto-detected if omitted)
    #[arg(long)]
    oodle_lib: Option<PathBuf>,

    /// Output directory for stitched map PNGs
    #[arg(short, long, default_value = "maps")]
    output: PathBuf,

    /// Only process this archive (e.g. "data0"). Processes all by default.
    #[arg(long)]
    archive: Option<String>,

    /// Dump individual tiles instead of stitching
    #[arg(long)]
    dump_tiles: bool,
}

fn main() -> Result<()> {
    let args = Args::parse();
    let start = Instant::now();

    eprintln!(
        "\n  {BOLD}nightreign-map-extract{RESET} {DIM}v{}{RESET}\n",
        env!("CARGO_PKG_VERSION")
    );

    let game_dir = match args.game_dir {
        Some(d) => d,
        None => steam::find_game_dir()?,
    };
    eprintln!("  {DIM}Game{RESET}     {}", game_dir.display());

    let (oodle, oodle_path) = match args.oodle_lib {
        Some(ref p) => (oodle::Oodle::load_from(p)?, p.clone()),
        None => oodle::Oodle::load(&game_dir)?,
    };
    eprintln!("  {DIM}Oodle{RESET}    {}", oodle_path.display());
    eprintln!("  {DIM}Output{RESET}   {}", args.output.display());

    std::fs::create_dir_all(&args.output)?;

    let archives: Vec<&keys::ArchiveKey> = match args.archive {
        Some(ref name) => {
            let a = keys::ARCHIVES
                .iter()
                .find(|a| a.name == name)
                .with_context(|| {
                    format!(
                        "Unknown archive '{}'. Valid: {:?}",
                        name,
                        keys::ARCHIVES.iter().map(|a| a.name).collect::<Vec<_>>()
                    )
                })?;
            vec![a]
        }
        None => keys::ARCHIVES.iter().collect(),
    };

    let mut total_maps = 0usize;
    let mut total_bytes = 0u64;

    for archive in &archives {
        let bhd_path = game_dir.join(archive.bhd_path);
        let bdt_path = game_dir.join(archive.bdt_path);

        if !bhd_path.exists() {
            eprintln!(
                "\n  {DIM}{} · skipped (not found){RESET}",
                archive.name
            );
            continue;
        }

        let bhd = bhd::Bhd5::open(&bhd_path, archive.pem)
            .with_context(|| format!("Failed to parse {}", archive.name))?;

        eprintln!(
            "\n  {BOLD}{}{RESET} {DIM}·{RESET} {} entries",
            archive.name,
            fmt_num(bhd.file_headers.len())
        );

        let bdt_data = std::fs::read(&bdt_path)
            .with_context(|| format!("Failed to read {}", bdt_path.display()))?;

        let pb = ProgressBar::new(bhd.file_headers.len() as u64);
        pb.set_style(
            ProgressStyle::default_bar()
                .template("  {bar:40.cyan/235} {pos:>5}/{len}")
                .unwrap(),
        );

        // (realm_label, tiles)
        let mut map_tpfs: Vec<(String, Vec<(stitch::TileInfo, Vec<u8>)>)> = Vec::new();
        let mut unknown_index = 0usize;

        for fh in &bhd.file_headers {
            pb.inc(1);

            let file_data = match fh.read_from_bdt(&bdt_data) {
                Ok(d) => d,
                Err(_) => continue,
            };

            if file_data.len() < 4 {
                continue;
            }

            let decompressed = if dcx::is_dcx(&file_data) {
                match dcx::decompress_dcx(&file_data, &oodle) {
                    Ok(d) => d,
                    Err(_) => continue,
                }
            } else {
                file_data
            };

            if decompressed.len() < 4 || &decompressed[..4] != b"TPF\0" {
                continue;
            }

            let tpf_result = match tpf::Tpf::parse(&decompressed) {
                Ok(t) => t,
                Err(_) => continue,
            };

            let has_map_tiles = tpf_result
                .textures
                .iter()
                .any(|t| t.name.contains("MENU_MapTile_"));
            if !has_map_tiles {
                continue;
            }

            let label = match realm_name(fh.file_name_hash) {
                Some(name) => name.to_string(),
                None => {
                    let fallback = format!("unknown_{:02}", unknown_index);
                    unknown_index += 1;
                    fallback
                }
            };

            let mut tiles = Vec::new();
            for tex in &tpf_result.textures {
                if let Some(info) = stitch::parse_tile_name(&tex.name) {
                    match decode_dds_to_rgba(&tex.data) {
                        Ok((pixels, w, h)) => {
                            if args.dump_tiles {
                                let _ =
                                    dump_tile(&args.output, &label, &tex.name, &pixels, w, h);
                            }
                            tiles.push((info, pixels));
                        }
                        Err(e) => {
                            pb.println(format!(
                                "  {YELLOW}!{RESET} failed to decode {}: {}",
                                tex.name, e
                            ));
                        }
                    }
                }
            }

            if !tiles.is_empty() {
                pb.println(format!(
                    "  {CYAN}>{RESET} {BOLD}{}{RESET} — {} tiles",
                    label,
                    tiles.len()
                ));
                map_tpfs.push((label, tiles));
            }
        }
        pb.finish_and_clear();

        if map_tpfs.is_empty() {
            eprintln!("  {DIM}no map tiles{RESET}");
            continue;
        }

        if !args.dump_tiles {
            for (realm, tiles) in &map_tpfs {
                let tile_w = 256u32;
                let tile_h = 256u32;

                let groups = stitch::stitch_all_groups(tiles.clone(), tile_w, tile_h)?;

                for (group_label, img) in &groups {
                    let (subdir, filename) = map_output_path(realm, group_label);
                    let dir = args.output.join(&subdir);
                    std::fs::create_dir_all(&dir)?;
                    let path = dir.join(&filename);

                    img.save(&path)
                        .with_context(|| format!("Failed to save {}", path.display()))?;
                    let file_size = std::fs::metadata(&path).map(|m| m.len()).unwrap_or(0);

                    let rel_path = format!("{}/{}", subdir, filename);
                    eprintln!(
                        "  {GREEN}✓{RESET} {:<40} {DIM}{}×{}{RESET}  {}",
                        rel_path,
                        img.width(),
                        img.height(),
                        fmt_size(file_size),
                    );
                    total_maps += 1;
                    total_bytes += file_size;
                }
            }
        } else {
            let tile_count: usize = map_tpfs.iter().map(|(_, t)| t.len()).sum();
            eprintln!(
                "  {GREEN}✓{RESET} {} tiles dumped to {}/tiles/",
                tile_count,
                args.output.display()
            );
        }
    }

    let elapsed = start.elapsed();
    if total_maps > 0 {
        eprintln!(
            "\n  {GREEN}✓{RESET} {BOLD}{} maps{RESET} saved to {BOLD}{}{RESET} ({}, {:.1}s)\n",
            total_maps,
            args.output.display(),
            fmt_size(total_bytes),
            elapsed.as_secs_f64(),
        );
    } else {
        eprintln!(
            "\n  {YELLOW}!{RESET} No map tiles found ({:.1}s)\n",
            elapsed.as_secs_f64(),
        );
    }

    Ok(())
}

/// Map a stitch group label (e.g. "L0", "L0_B1", "L1", "L1_B1") to (subdirectory, filename).
fn map_output_path(realm: &str, group_label: &str) -> (String, String) {
    let filename = format!("{}.png", realm);
    let subdir = match group_label {
        "L0" => "surface".to_string(),
        "L1" => "interior".to_string(),
        label if label.starts_with("L0") => "underground".to_string(),
        label if label.starts_with("L1") => {
            // L1_B1 → interior with -underground suffix
            return ("interior".to_string(), format!("{}-underground.png", realm));
        }
        other => other.to_string(),
    };
    (subdir, filename)
}

fn fmt_num(n: usize) -> String {
    let s = n.to_string();
    let mut result = String::new();
    for (i, c) in s.chars().rev().enumerate() {
        if i > 0 && i % 3 == 0 {
            result.push(',');
        }
        result.push(c);
    }
    result.chars().rev().collect()
}

fn fmt_size(bytes: u64) -> String {
    if bytes >= 1_000_000 {
        format!("{:.1} MB", bytes as f64 / 1_000_000.0)
    } else if bytes >= 1_000 {
        format!("{} KB", bytes / 1_000)
    } else {
        format!("{} B", bytes)
    }
}

fn decode_dds_to_rgba(dds_bytes: &[u8]) -> Result<(Vec<u8>, u32, u32)> {
    let mut cursor = std::io::Cursor::new(dds_bytes);
    let dds = ddsfile::Dds::read(&mut cursor)
        .map_err(|e| anyhow::anyhow!("Failed to parse DDS: {}", e))?;

    let img = image_dds::image_from_dds(&dds, 0)
        .map_err(|e| anyhow::anyhow!("Failed to decode DDS pixels: {}", e))?;

    let width = img.width();
    let height = img.height();
    let pixels = img.into_raw();

    Ok((pixels, width, height))
}

fn dump_tile(
    output_dir: &std::path::Path,
    realm: &str,
    name: &str,
    pixels: &[u8],
    width: u32,
    height: u32,
) -> Result<()> {
    let dir = output_dir.join("tiles").join(realm);
    std::fs::create_dir_all(&dir)?;
    let filename = format!("{}.png", name.replace('/', "_"));
    let path = dir.join(&filename);

    if let Some(img) =
        image::ImageBuffer::<image::Rgba<u8>, _>::from_raw(width, height, pixels.to_vec())
    {
        img.save(&path)?;
    }
    Ok(())
}
