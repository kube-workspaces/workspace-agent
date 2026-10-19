//! Independent updater lifetime. No listener, installer dispatch or permissive
//! recovery authority is enabled by the shipped service host.

pub const PROTOCOL_VERSION: u32 = 1;
pub const VERSION: &str = match option_env!("KW_UPDATER_VERSION") {
    Some(version) => version,
    None => env!("CARGO_PKG_VERSION"),
};

#[cfg(windows)]
pub mod service;
