use std::path::PathBuf;
use anyhow::{Result, bail};

const GAME_DIR_NAME: &str = "ELDEN RING NIGHTREIGN";
const _APP_ID: &str = "2953840";

pub fn find_game_dir() -> Result<PathBuf> {
    let candidates = steam_library_folders();

    for lib in &candidates {
        let game = lib.join("steamapps/common").join(GAME_DIR_NAME).join("Game");
        if game.join("data0.bhd").exists() {
            return Ok(game);
        }
    }

    bail!(
        "Could not find Nightreign game files. Searched {} Steam library paths.\n\
         Pass --game-dir <path> to specify manually (the 'Game' folder containing data0.bhd).",
        candidates.len()
    )
}

fn steam_library_folders() -> Vec<PathBuf> {
    let mut dirs = Vec::new();

    #[cfg(target_os = "windows")]
    {
        for drive in &["C", "D", "E", "F", "G"] {
            dirs.push(PathBuf::from(format!(r"{}:\Program Files (x86)\Steam", drive)));
            dirs.push(PathBuf::from(format!(r"{}:\Program Files\Steam", drive)));
            dirs.push(PathBuf::from(format!(r"{}:\Steam", drive)));
            dirs.push(PathBuf::from(format!(r"{}:\SteamLibrary", drive)));
        }
    }

    #[cfg(target_os = "linux")]
    {
        if let Ok(home) = std::env::var("HOME") {
            dirs.push(PathBuf::from(format!("{}/.steam/steam", home)));
            dirs.push(PathBuf::from(format!("{}/.local/share/Steam", home)));
            dirs.push(PathBuf::from(format!("{}/.steam/debian-installation", home)));
        }
        dirs.push(PathBuf::from("/usr/share/steam"));
    }

    #[cfg(target_os = "macos")]
    {
        if let Ok(home) = std::env::var("HOME") {
            dirs.push(PathBuf::from(format!(
                "{}/Library/Application Support/Steam",
                home
            )));
        }
    }

    // Parse libraryfolders.vdf from each candidate to find additional library paths
    let base_dirs = dirs.clone();
    for base in &base_dirs {
        let vdf = base.join("steamapps/libraryfolders.vdf");
        if let Ok(content) = std::fs::read_to_string(&vdf) {
            for line in content.lines() {
                let trimmed = line.trim();
                if trimmed.starts_with("\"path\"") {
                    if let Some(path) = extract_vdf_value(trimmed) {
                        let p = PathBuf::from(path);
                        if !dirs.contains(&p) {
                            dirs.push(p);
                        }
                    }
                }
            }
        }
    }

    dirs
}

fn extract_vdf_value(line: &str) -> Option<String> {
    let parts: Vec<&str> = line.splitn(2, "\"path\"").collect();
    if parts.len() < 2 {
        return None;
    }
    let rest = parts[1].trim();
    if let Some(start) = rest.find('"') {
        let after = &rest[start + 1..];
        if let Some(end) = after.find('"') {
            return Some(after[..end].replace("\\\\", "/"));
        }
    }
    None
}
