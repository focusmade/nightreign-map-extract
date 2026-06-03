use anyhow::{Context, Result};
use image::{ImageBuffer, Rgba, RgbaImage};
use regex::Regex;
use std::collections::HashMap;

#[derive(Debug, Clone)]
pub struct TileInfo {
    pub layer: u32,
    pub col: u32,
    pub row: u32,
    pub underground: String, // e.g. "_B1", "" for surface
    #[allow(dead_code)]
    pub name: String,
}

#[derive(Debug, Clone, Hash, Eq, PartialEq)]
struct TileGroup {
    layer: u32,
    underground: String,
}

/// Parse a tile name like "MENU_MapTile_L0_12_5" or "MENU_MapTile_L1_3_2_B1"
pub fn parse_tile_name(name: &str) -> Option<TileInfo> {
    let re = Regex::new(r"MENU_MapTile_L(\d+)_(\d+)_(\d+)(_B\d+)?").ok()?;
    let caps = re.captures(name)?;
    Some(TileInfo {
        layer: caps[1].parse().ok()?,
        col: caps[2].parse().ok()?,   // First number = column (X axis)
        row: caps[3].parse().ok()?,   // Second number = row (Y axis)
        underground: caps.get(4).map(|m| m.as_str().to_string()).unwrap_or_default(),
        name: name.to_string(),
    })
}

/// Stitch tiles into a single image.
/// tile_width/tile_height = dimensions of each tile (typically 256x256).
/// tiles: Vec of (TileInfo, RGBA pixel data).
pub fn stitch_tiles(tiles: &[(TileInfo, Vec<u8>)], tile_width: u32, tile_height: u32) -> Result<RgbaImage> {
    if tiles.is_empty() {
        anyhow::bail!("No tiles to stitch");
    }

    let max_col = tiles.iter().map(|(t, _)| t.col).max().unwrap();
    let max_row = tiles.iter().map(|(t, _)| t.row).max().unwrap();
    let min_col = tiles.iter().map(|(t, _)| t.col).min().unwrap();
    let min_row = tiles.iter().map(|(t, _)| t.row).min().unwrap();

    let cols = max_col - min_col + 1;
    let rows = max_row - min_row + 1;

    let canvas_w = cols * tile_width;
    let canvas_h = rows * tile_height;

    let mut canvas: RgbaImage = ImageBuffer::new(canvas_w, canvas_h);

    for (info, pixels) in tiles {
        let col = info.col - min_col;
        // Y-axis flip: game origin is bottom-left, image origin is top-left
        let flipped_row = (max_row - min_row) - (info.row - min_row);

        let x_offset = col * tile_width;
        let y_offset = flipped_row * tile_height;

        if let Some(tile_img) = ImageBuffer::<Rgba<u8>, _>::from_raw(tile_width, tile_height, pixels.clone()) {
            image::imageops::overlay(&mut canvas, &tile_img, x_offset as i64, y_offset as i64);
        }
    }

    Ok(canvas)
}

/// Group tiles by layer+underground variant and stitch each group into a separate image.
/// Returns (group_label, image) pairs.
pub fn stitch_all_groups(
    tiles: Vec<(TileInfo, Vec<u8>)>,
    tile_width: u32,
    tile_height: u32,
) -> Result<Vec<(String, RgbaImage)>> {
    let mut groups: HashMap<TileGroup, Vec<(TileInfo, Vec<u8>)>> = HashMap::new();

    for (info, data) in tiles {
        let group = TileGroup {
            layer: info.layer,
            underground: info.underground.clone(),
        };
        groups.entry(group).or_default().push((info, data));
    }

    let mut results = Vec::new();
    let mut sorted_groups: Vec<_> = groups.into_iter().collect();
    sorted_groups.sort_by_key(|(g, _)| (g.layer, g.underground.clone()));

    for (group, group_tiles) in sorted_groups {
        let label = if group.underground.is_empty() {
            format!("L{}", group.layer)
        } else {
            format!("L{}{}", group.layer, group.underground)
        };

        let img = stitch_tiles(&group_tiles, tile_width, tile_height)
            .with_context(|| format!("Failed to stitch group {}", label))?;
        results.push((label, img));
    }

    Ok(results)
}

