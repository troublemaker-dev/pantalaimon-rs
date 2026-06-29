#![allow(dead_code)]

use std::{
    net::{IpAddr, Ipv4Addr},
    path::Path,
};

use anyhow::{bail, Context};
use configparser::ini::Ini;
use tracing::Level;
use url::Url;

#[derive(Debug, thiserror::Error)]
#[error("config error: {0}")]
pub struct PanConfigError(pub String);

/// Per-server proxy configuration — mirrors Python's ServerConfig.
#[derive(Debug, Clone)]
pub struct ServerConfig {
    pub name: String,
    pub homeserver: Url,
    pub listen_address: IpAddr,
    pub listen_port: u16,
    pub proxy: Option<Url>,
    pub ssl: bool,
    pub ignore_verification: bool,
    pub use_keyring: bool,
    pub search_requests: bool,
    pub index_encrypted_only: bool,
    pub indexing_batch_size: u32,
    /// Delay between history-fetch batches (seconds).
    pub history_fetch_delay: f64,
    pub drop_old_keys: bool,
}

#[derive(Debug, Clone)]
pub struct PanConfig {
    pub log_level: Level,
    pub debug_encryption: bool,
    pub notifications: bool,
    pub servers: indexmap::IndexMap<String, ServerConfig>,
}

// `url` is not in the workspace yet — add it, or parse URLs manually.
// For now we re-export via a thin newtype so callers stay stable.
pub fn read_config(path: &Path) -> anyhow::Result<PanConfig> {
    let mut ini = Ini::new_cs();
    ini.load(path)
        .map_err(|e| anyhow::anyhow!("Failed to read config {}: {}", path.display(), e))?;

    // Helper: get a key, trying the named section first then "Default".
    let get = |section: &str, key: &str| -> Option<String> {
        ini.get(section, key).or_else(|| ini.get("Default", key))
    };

    let get_bool = |section: &str, key: &str| -> anyhow::Result<Option<bool>> {
        match get(section, key) {
            None => Ok(None),
            Some(v) => match v.to_lowercase().as_str() {
                "true" | "yes" | "on" | "1" => Ok(Some(true)),
                "false" | "no" | "off" | "0" => Ok(Some(false)),
                other => bail!("Invalid boolean '{}' for key '{}'", other, key),
            },
        }
    };

    let get_u16 = |section: &str, key: &str| -> anyhow::Result<Option<u16>> {
        match get(section, key) {
            None => Ok(None),
            Some(v) => Ok(Some(v.trim().parse::<u16>().with_context(|| {
                format!("Invalid integer '{}' for key '{}'", v, key)
            })?)),
        }
    };

    let get_u32 = |section: &str, key: &str| -> anyhow::Result<Option<u32>> {
        match get(section, key) {
            None => Ok(None),
            Some(v) => Ok(Some(v.trim().parse::<u32>().with_context(|| {
                format!("Invalid integer '{}' for key '{}'", v, key)
            })?)),
        }
    };

    // Global defaults from [Default] section.
    let log_level = match get("Default", "LogLevel")
        .unwrap_or_else(|| "warning".into())
        .to_lowercase()
        .as_str()
    {
        "error" => Level::ERROR,
        "warning" => Level::WARN,
        "info" => Level::INFO,
        "debug" => Level::DEBUG,
        _ => Level::WARN,
    };

    let debug_encryption = get_bool("Default", "DebugEncryption")?.unwrap_or(false);
    let notifications = get_bool("Default", "Notifications")?.unwrap_or(true);

    let mut servers = indexmap::IndexMap::new();

    for section in ini.sections() {
        if section == "Default" {
            continue;
        }

        let homeserver_str = get(&section, "Homeserver")
            .ok_or_else(|| anyhow::anyhow!("[{}] Homeserver is required", section))?;
        let homeserver = Url::parse(&homeserver_str)
            .with_context(|| format!("[{}] Invalid Homeserver URL", section))?;

        let listen_address: IpAddr = match get(&section, "ListenAddress")
            .unwrap_or_else(|| "localhost".into())
            .as_str()
        {
            "localhost" => IpAddr::V4(Ipv4Addr::LOCALHOST),
            addr => addr.parse().with_context(|| {
                format!("[{}] Invalid ListenAddress", section)
            })?,
        };

        let listen_port = get_u16(&section, "ListenPort")?.unwrap_or(8009);

        let proxy = get(&section, "Proxy")
            .map(|v| Url::parse(&v))
            .transpose()
            .with_context(|| format!("[{}] Invalid Proxy URL", section))?;

        let ssl = get_bool(&section, "UseSSL")?
            .or(get_bool(&section, "SSL")?)
            .unwrap_or(true);
        let ignore_verification = get_bool(&section, "IgnoreVerification")?.unwrap_or(false);
        let use_keyring = get_bool(&section, "UseKeyring")?.unwrap_or(true);
        let search_requests = get_bool(&section, "SearchRequests")?.unwrap_or(false);
        let index_encrypted_only = get_bool(&section, "IndexEncryptedOnly")?.unwrap_or(true);
        let drop_old_keys = get_bool(&section, "DropOldKeys")?.unwrap_or(false);

        let indexing_batch_size = get_u32(&section, "IndexingBatchSize")?.unwrap_or(100);
        if !(1 < indexing_batch_size && indexing_batch_size <= 1000) {
            bail!(
                "[{}] IndexingBatchSize must be between 1 and 1000",
                section
            );
        }

        let history_fetch_delay_ms = get_u32(&section, "HistoryFetchDelay")?.unwrap_or(3000);
        if !(100 < history_fetch_delay_ms && history_fetch_delay_ms <= 10000) {
            bail!(
                "[{}] HistoryFetchDelay must be between 100 and 10000 ms",
                section
            );
        }

        servers.insert(
            section.clone(),
            ServerConfig {
                name: section,
                homeserver,
                listen_address,
                listen_port,
                proxy,
                ssl,
                ignore_verification,
                use_keyring,
                search_requests,
                index_encrypted_only,
                indexing_batch_size,
                history_fetch_delay: history_fetch_delay_ms as f64 / 1000.0,
                drop_old_keys,
            },
        );
    }

    Ok(PanConfig {
        log_level,
        debug_encryption,
        notifications,
        servers,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use tempfile::NamedTempFile;

    fn write_config(content: &str) -> NamedTempFile {
        let mut f = NamedTempFile::new().unwrap();
        f.write_all(content.as_bytes()).unwrap();
        f
    }

    #[test]
    fn test_minimal_config() {
        let f = write_config(
            "[Local]\n\
             Homeserver = http://localhost:8448\n",
        );
        let cfg = read_config(f.path()).unwrap();
        assert_eq!(cfg.servers.len(), 1);
        let s = cfg.servers.get("Local").unwrap();
        assert_eq!(s.homeserver.as_str(), "http://localhost:8448/");
        assert_eq!(s.listen_port, 8009);
        assert!(s.use_keyring);
        assert!(!s.ignore_verification);
    }

    #[test]
    fn test_overrides() {
        let f = write_config(
            "[MyServer]\n\
             Homeserver = https://matrix.example.com\n\
             ListenPort = 9009\n\
             UseKeyring = false\n\
             SSL = false\n\
             IgnoreVerification = true\n",
        );
        let cfg = read_config(f.path()).unwrap();
        let s = cfg.servers.get("MyServer").unwrap();
        assert_eq!(s.listen_port, 9009);
        assert!(!s.use_keyring);
        assert!(!s.ssl);
        assert!(s.ignore_verification);
    }

    #[test]
    fn test_default_section_inherited() {
        let f = write_config(
            "[Default]\n\
             UseKeyring = false\n\
             \n\
             [Local]\n\
             Homeserver = http://localhost:8448\n",
        );
        let cfg = read_config(f.path()).unwrap();
        let s = cfg.servers.get("Local").unwrap();
        // UseKeyring from [Default] should propagate to the server
        assert!(!s.use_keyring);
    }

    #[test]
    fn test_multiple_servers() {
        let f = write_config(
            "[Alpha]\n\
             Homeserver = http://alpha.local:8448\n\
             ListenPort = 8010\n\
             \n\
             [Beta]\n\
             Homeserver = http://beta.local:8448\n\
             ListenPort = 8011\n",
        );
        let cfg = read_config(f.path()).unwrap();
        assert_eq!(cfg.servers.len(), 2);
        assert_eq!(cfg.servers["Alpha"].listen_port, 8010);
        assert_eq!(cfg.servers["Beta"].listen_port, 8011);
    }

    #[test]
    fn test_log_level_parsed() {
        let f = write_config(
            "[Default]\n\
             LogLevel = debug\n\
             \n\
             [Local]\n\
             Homeserver = http://localhost:8448\n",
        );
        let cfg = read_config(f.path()).unwrap();
        assert_eq!(cfg.log_level, tracing::Level::DEBUG);
    }

    #[test]
    fn test_missing_homeserver_errors() {
        let f = write_config("[Local]\nListenPort = 8009\n");
        assert!(read_config(f.path()).is_err());
    }

    #[test]
    fn test_invalid_homeserver_url_errors() {
        let f = write_config("[Local]\nHomeserver = not-a-url\n");
        assert!(read_config(f.path()).is_err());
    }

    #[test]
    fn test_no_servers() {
        let f = write_config("[Default]\nLogLevel = info\n");
        let cfg = read_config(f.path()).unwrap();
        assert!(cfg.servers.is_empty());
    }

    #[test]
    fn test_use_ssl_alias() {
        // UseSSL and SSL are both accepted; UseSSL takes precedence.
        let f = write_config(
            "[Local]\n\
             Homeserver = http://localhost:8448\n\
             UseSSL = false\n",
        );
        let cfg = read_config(f.path()).unwrap();
        assert!(!cfg.servers["Local"].ssl);

        // SSL (old key) also works
        let f2 = write_config(
            "[Local]\n\
             Homeserver = http://localhost:8448\n\
             SSL = false\n",
        );
        let cfg2 = read_config(f2.path()).unwrap();
        assert!(!cfg2.servers["Local"].ssl);
    }

    #[test]
    fn test_proxy_url_parsed() {
        let f = write_config(
            "[Local]\n\
             Homeserver = http://localhost:8448\n\
             Proxy = http://squid.internal:3128\n",
        );
        let cfg = read_config(f.path()).unwrap();
        let proxy = cfg.servers["Local"].proxy.as_ref().unwrap();
        assert_eq!(proxy.host_str(), Some("squid.internal"));
        assert_eq!(proxy.port(), Some(3128));
    }

    #[test]
    fn test_invalid_proxy_url_errors() {
        let f = write_config(
            "[Local]\n\
             Homeserver = http://localhost:8448\n\
             Proxy = not-a-url\n",
        );
        assert!(read_config(f.path()).is_err());
    }

    #[test]
    fn test_indexing_batch_size_bounds() {
        let too_small = write_config(
            "[Local]\n\
             Homeserver = http://localhost:8448\n\
             IndexingBatchSize = 1\n",
        );
        assert!(read_config(too_small.path()).is_err());

        let too_large = write_config(
            "[Local]\n\
             Homeserver = http://localhost:8448\n\
             IndexingBatchSize = 1001\n",
        );
        assert!(read_config(too_large.path()).is_err());
    }

    #[test]
    fn test_history_fetch_delay_bounds() {
        let too_small = write_config(
            "[Local]\n\
             Homeserver = http://localhost:8448\n\
             HistoryFetchDelay = 100\n",
        );
        assert!(read_config(too_small.path()).is_err());

        let too_large = write_config(
            "[Local]\n\
             Homeserver = http://localhost:8448\n\
             HistoryFetchDelay = 10001\n",
        );
        assert!(read_config(too_large.path()).is_err());
    }

    #[test]
    fn test_history_fetch_delay_ms_to_seconds() {
        let f = write_config(
            "[Local]\n\
             Homeserver = http://localhost:8448\n\
             HistoryFetchDelay = 5000\n",
        );
        let cfg = read_config(f.path()).unwrap();
        assert!((cfg.servers["Local"].history_fetch_delay - 5.0).abs() < f64::EPSILON);
    }

    #[test]
    fn test_global_debug_encryption_and_notifications() {
        let f = write_config(
            "[Default]\n\
             DebugEncryption = true\n\
             Notifications = false\n\
             \n\
             [Local]\n\
             Homeserver = http://localhost:8448\n",
        );
        let cfg = read_config(f.path()).unwrap();
        assert!(cfg.debug_encryption);
        assert!(!cfg.notifications);
    }

    #[test]
    fn test_drop_old_keys_default_false() {
        let f = write_config("[Local]\nHomeserver = http://localhost:8448\n");
        let cfg = read_config(f.path()).unwrap();
        assert!(!cfg.servers["Local"].drop_old_keys);
    }

    #[test]
    fn test_drop_old_keys_enabled() {
        let f = write_config(
            "[Local]\n\
             Homeserver = http://localhost:8448\n\
             DropOldKeys = true\n",
        );
        let cfg = read_config(f.path()).unwrap();
        assert!(cfg.servers["Local"].drop_old_keys);
    }
}
