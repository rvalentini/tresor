use config::{ConfigError, Config, File, Environment};
use serde::Deserialize;

#[derive(Debug, Deserialize)]
pub struct Database {
    pub url: String
}

#[derive(Debug, Deserialize)]
pub struct Server {
    pub interface: String,
    pub port: String
}

#[derive(Debug, Deserialize)]
pub struct Logging {
    pub level: String
}

#[derive(Debug, Deserialize)]
pub struct Settings {
    pub database: Database,
    pub server: Server,
    pub logging: Logging
}

impl Settings {
    pub fn init() -> Result<Self, ConfigError> {
        let mut config = Config::new();

        config.merge(File::with_name("config/default"))?;

        //this includes all ENV overrides starting with TRESOR_
        //e.g. set global log-level via TRESOR_LOGGING_LEVEL=...
        config.merge(Environment::with_prefix("tresor").separator("_"))?;

        //for DEV, PROD etc. distinction follow
        // https://github.com/mehcode/config-rs/blob/master/examples/hierarchical-env/src/settings.rs

        config.try_into()
    }
}