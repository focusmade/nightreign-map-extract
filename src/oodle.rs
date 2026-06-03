use anyhow::{Context, Result, bail};
use libloading::{Library, Symbol};
use std::path::{Path, PathBuf};

type OodleDecompressFn = unsafe extern "C" fn(
    comp_buf: *const u8,
    comp_buf_size: isize,
    raw_buf: *mut u8,
    raw_len: isize,
    fuzz_safe: i32,
    check_crc: i32,
    verbosity: i32,
    dec_buf_base: *mut u8,
    dec_buf_size: isize,
    fp_callback: *mut u8,
    callback_user_data: *mut u8,
    decoder_memory: *mut u8,
    decoder_memory_size: isize,
    thread_phase: i32,
) -> isize;

pub struct Oodle {
    _lib: Library,
    decompress: OodleDecompressFn,
}

impl Oodle {
    pub fn load_from(lib_path: &Path) -> Result<Self> {
        Self::load_lib(lib_path)
    }

    pub fn load(game_dir: &Path) -> Result<(Self, PathBuf)> {
        let lib_path = find_oodle_lib(game_dir)?;
        let oodle = Self::load_lib(&lib_path)?;
        Ok((oodle, lib_path))
    }

    fn load_lib(lib_path: &Path) -> Result<Self> {
        unsafe {
            let lib = Library::new(lib_path)
                .with_context(|| format!("Failed to load Oodle library: {}", lib_path.display()))?;

            let decompress: Symbol<OodleDecompressFn> = lib
                .get(b"OodleLZ_Decompress")
                .context("OodleLZ_Decompress symbol not found in Oodle library")?;

            let decompress = *decompress;

            Ok(Oodle {
                _lib: lib,
                decompress,
            })
        }
    }

    pub fn decompress(&self, compressed: &[u8], decompressed_size: usize) -> Result<Vec<u8>> {
        let mut output = vec![0u8; decompressed_size];

        let result = unsafe {
            (self.decompress)(
                compressed.as_ptr(),
                compressed.len() as isize,
                output.as_mut_ptr(),
                decompressed_size as isize,
                1,     // fuzzSafe
                0,     // checkCRC
                0,     // verbosity
                std::ptr::null_mut(),
                0,
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                0,
                0,     // threadPhase
            )
        };

        if result < 0 {
            bail!("Oodle decompression failed (returned {})", result);
        }
        if (result as usize) != decompressed_size {
            bail!(
                "Oodle decompressed {} bytes but expected {}",
                result,
                decompressed_size
            );
        }

        Ok(output)
    }
}

fn find_oodle_lib(game_dir: &Path) -> Result<PathBuf> {
    let mut candidates: Vec<PathBuf> = Vec::new();

    // Check next to the executable itself
    if let Ok(exe) = std::env::current_exe() {
        if let Some(dir) = exe.parent() {
            candidates.push(dir.join("oo2core_9_win64.dll"));
            candidates.push(dir.join("liboo2corelinux64.so.9"));
        }
    }

    // Current working directory (must be absolute — dlopen ignores CWD for bare names)
    if let Ok(cwd) = std::env::current_dir() {
        candidates.push(cwd.join("liboo2corelinux64.so.9"));
        candidates.push(cwd.join("oo2core_9_win64.dll"));
    }

    // Game directory (Windows ships the DLL here)
    candidates.push(game_dir.join("oo2core_9_win64.dll"));
    for v in (6..=13).rev() {
        candidates.push(game_dir.join(format!("oo2core_{}_win64.dll", v)));
    }

    // Linux: game dir and system paths
    candidates.push(game_dir.join("liboo2corelinux64.so.9"));
    candidates.push(game_dir.join("liboo2corelinux64.so"));
    candidates.push(PathBuf::from("/usr/lib/liboo2corelinux64.so.9"));
    candidates.push(PathBuf::from("/usr/local/lib/liboo2corelinux64.so.9"));

    // LD_LIBRARY_PATH
    if let Ok(ld_path) = std::env::var("LD_LIBRARY_PATH") {
        for dir in ld_path.split(':') {
            candidates.push(PathBuf::from(dir).join("liboo2corelinux64.so.9"));
        }
    }

    for p in &candidates {
        if p.exists() {
            return Ok(p.clone());
        }
    }

    bail!(
        "Could not find Oodle decompression library.\n\
         Windows: expected oo2core_9_win64.dll in game directory or next to this executable.\n\
         Linux: place liboo2corelinux64.so.9 next to this executable, in the game dir, or in /usr/lib.\n\
         You can also specify the path with --oodle-lib <path>."
    )
}
