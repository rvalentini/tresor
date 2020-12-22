use config::{ConfigError, Config, File, Environment};
use serde::Deserialize;
use std::env;

// Note: within the Settings model, variable names that would normally be
//       written with snake_case (e.g. run_mode) are intentionally written as
//       single, connected words (e.g. runmode). This is because of the hierarchical
//       structure of the Settings. The config.rs crate does currently not offer a
//       nice way to combine hierarchies + snake_case namings.
//       Maybe TODO: switch to different config crate or
//                   see the results from https://github.com/mehcode/config-rs/issues/111

#[derive(Debug, Deserialize)]
pub struct Database {
    pub url: String
}

#[derive(Debug, Deserialize)]
pub struct Server {
    pub interface: String,
    pub port: String,
    pub cookiemasterkey: String,
    #[serde(default)]
    pub runmode: RunMode,
}

#[derive(Debug, Deserialize)]
pub enum RunMode {
    Default,
    Debug,
}

impl Default for RunMode {
    fn default() -> Self {
        Self::Default
    }
}

#[derive(Debug, Deserialize)]
pub struct Logging {
    pub level: String
}

#[derive(Debug, Deserialize)]
pub struct Auth {
    pub issuerurl: String,
    pub clientid: String,
    pub clientsecret: String,
    pub scope: String,
    #[serde(default = "deny")]
    pub enabletestlogin: bool,
}

fn deny() -> bool { false }

#[derive(Debug, Deserialize)]
pub struct Settings {
    pub database: Database,
    pub server: Server,
    pub logging: Logging,
    pub auth: Auth,
}

impl Settings {
    pub fn init() -> Result<Self, ConfigError> {
        let mut config = Config::new();

        config.merge(File::with_name("config/default"))?;

        //this includes all ENV overrides starting with TRESOR_
        //e.g. set global log-level via TRESOR_LOGGING_LEVEL=...
        //Note: the hierarchy of variables (e.g. Server struct) is constructed by the '_'
        //      separator. The variable names themselves MUST NOT contain underscores!
        config.merge(Environment::with_prefix("tresor")
            .separator("_")
            .ignore_empty(true))?;

        // Add in optional environment files to enable features or overwrite defaults
        // currently available env. files:
        // * debug
        if let Ok(env) = env::var("TRESOR_SERVER_RUNMODE") {
            if !env.is_empty() {
                config.set("server.runmode", capitalize(&env.to_lowercase()))?;
                config.merge(File::with_name(&format!("config/{}", env.to_lowercase())).required(false))?;
            }
        }

        //for further  DEV, PROD etc. distinction follow
        // https://github.com/mehcode/config-rs/blob/master/examples/hierarchical-env/src/settings.rs

        config.try_into()
    }
}

fn capitalize(s: &str) -> String {
    let mut c = s.chars();
    match c.next() {
        None => String::new(),
        Some(f) => f.to_uppercase().collect::<String>() + c.as_str()
    }
}
