//! `getrusage`-based RSS sampler (peak resident set size).
//!
//! Used by the soak test to detect runaway memory growth.
//!
//! On macOS `ru_maxrss` is reported in bytes; on Linux it's in kilobytes.

pub fn peak_rss_bytes() -> u64 {
    unsafe {
        let mut ru: libc::rusage = std::mem::zeroed();
        if libc::getrusage(libc::RUSAGE_SELF, &mut ru) != 0 {
            return 0;
        }
        let raw = ru.ru_maxrss as i64;
        if raw <= 0 {
            return 0;
        }
        #[cfg(target_os = "macos")]
        {
            raw as u64
        }
        #[cfg(not(target_os = "macos"))]
        {
            (raw as u64).saturating_mul(1024)
        }
    }
}

pub fn fmt_bytes(b: u64) -> String {
    const KB: u64 = 1024;
    const MB: u64 = KB * 1024;
    if b >= MB {
        format!("{:.2} MiB", b as f64 / MB as f64)
    } else if b >= KB {
        format!("{:.2} KiB", b as f64 / KB as f64)
    } else {
        format!("{b} B")
    }
}
