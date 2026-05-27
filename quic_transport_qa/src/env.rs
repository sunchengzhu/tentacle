//! Small env-var helpers so each program can be tuned from the command line
//! without `clap`.

use std::{str::FromStr, time::Duration};

pub fn env_or<T: FromStr>(key: &str, default: T) -> T {
    match std::env::var(key) {
        Ok(v) => v.parse().unwrap_or(default),
        Err(_) => default,
    }
}

pub fn duration_secs(key: &str, default_secs: u64) -> Duration {
    Duration::from_secs(env_or(key, default_secs))
}
