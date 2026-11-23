use std::{
    collections::BTreeMap,
    ffi::OsString,
    fs::{DirBuilder, File},
    path::{Path, PathBuf},
    process::Command,
};

use anyhow::{bail, Context, Result};
use clap::Parser;
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::config::Config;

const PLUGINS: &[&str] = &[
    "workingdir",
    "yaml",
    "fixed",
    "failtoban",
    "username-router",
    "lua",
];

#[derive(Serialize, Deserialize)]
struct Settings {
    #[serde(rename = "sshpiperd.plugins")]
    plugins: [Vec<String>; 1],
    #[serde(flatten)]
    flags: BTreeMap<String, Vec<[String; 2]>>,
}

impl Settings {
    fn from_document(document: Value, common: &Path) -> Result<Self> {
        let document = document
            .as_object()
            .context("Snap configuration must be an object")?;
        let selected = document
            .get("sshpiperd")
            .and_then(|value| value.get("plugins"));
        let plugins = match selected {
            None | Some(Value::Null) => vec!["workingdir".to_owned()],
            Some(Value::String(value)) if value.trim().is_empty() => vec!["workingdir".to_owned()],
            Some(Value::String(value)) => value.split_whitespace().map(str::to_owned).collect(),
            Some(Value::Array(values)) => values
                .iter()
                .map(|value| {
                    value
                        .as_str()
                        .map(str::to_owned)
                        .context("Snap plugin names must be strings")
                })
                .collect::<Result<_>>()?,
            _ => bail!("sshpiperd.plugins must be a space-separated string or array"),
        };
        let mut settings = Self {
            plugins: [plugins],
            flags: BTreeMap::new(),
        };
        for (namespace, values) in document {
            if namespace != "sshpiperd" && !PLUGINS.contains(&namespace.as_str()) {
                bail!("unsupported Snap namespace {namespace}");
            }
            if values.is_null() {
                continue;
            }
            for (key, value) in values
                .as_object()
                .context("Snap namespace must be an object")?
            {
                if namespace == "sshpiperd" && key == "plugins" {
                    continue;
                }
                let values = match value {
                    Value::Array(values) => values.as_slice(),
                    value => std::slice::from_ref(value),
                };
                for value in values {
                    let value = match value {
                        Value::Null => continue,
                        Value::String(value) if value.is_empty() => continue,
                        Value::String(value) => value.clone(),
                        Value::Bool(_) | Value::Number(_) => value.to_string(),
                        _ => bail!("Snap option {namespace}.{key} must have scalar values"),
                    };
                    settings
                        .flags
                        .entry(namespace.clone())
                        .or_default()
                        .push([key.clone(), value]);
                }
            }
        }
        settings.default("sshpiperd", "server-key-generate-mode", "notexist".into());
        settings.default(
            "sshpiperd",
            "server-key",
            path_string(&common.join("ssh_host_ed25519_key"))?,
        );
        settings.default(
            "workingdir",
            "root",
            path_string(&common.join("workingdir"))?,
        );
        Ok(settings)
    }

    fn default(&mut self, namespace: &str, name: &str, value: String) {
        let flags = self.flags.entry(namespace.to_owned()).or_default();
        if !flags.iter().any(|[key, _]| key == name) {
            flags.push([name.to_owned(), value]);
        }
    }

    fn config(&self, directory: &Path) -> Result<Config> {
        if self.plugins[0].is_empty() {
            bail!("at least one Snap plugin is required");
        }
        let append = |arguments: &mut Vec<OsString>, namespace: &str| {
            if let Some(flags) = self.flags.get(namespace) {
                for [key, value] in flags {
                    arguments.push(format!("--{key}={value}").into());
                }
            }
        };
        let mut arguments = vec![OsString::from("sshpiperd")];
        append(&mut arguments, "sshpiperd");
        for (index, plugin) in self.plugins[0].iter().enumerate() {
            if !PLUGINS.contains(&plugin.as_str()) {
                bail!("unsupported Snap plugin {plugin}");
            }
            if index != 0 {
                arguments.push("--".into());
            }
            arguments.push(directory.join(plugin).into_os_string());
            append(&mut arguments, plugin);
        }
        let config = Config::try_parse_from(arguments)?;
        config.validate()?;
        Ok(config)
    }

    fn save(&self, directory: &Path) -> Result<()> {
        // NamedTempFile uses mode 0600 and persists with an atomic replacement.
        let mut file = tempfile::NamedTempFile::new_in(directory)?;
        serde_json::to_writer(file.as_file_mut(), self)?;
        file.as_file().sync_all()?;
        file.persist(directory.join("flags.json"))?;
        Ok(())
    }
}

fn path_string(path: &Path) -> Result<String> {
    Ok(path
        .to_str()
        .context("Snap paths must be UTF-8")?
        .to_owned())
}

fn directory(name: &str) -> Result<PathBuf> {
    let path =
        PathBuf::from(std::env::var_os(name).with_context(|| format!("{name} is required"))?);
    if !path.is_absolute() {
        bail!("{name} must be an absolute directory");
    }
    Ok(path)
}

pub fn configure() -> Result<()> {
    let common = directory("SNAP_COMMON")?;
    let binary = directory("SNAP")?;
    let data = directory("SNAP_DATA")?;
    let output = Command::new("snapctl")
        .args(["get", "-d", "sshpiperd"])
        .args(PLUGINS)
        .output()
        .context("reading configuration from snapctl")?;
    if !output.status.success() {
        bail!(
            "snapctl get failed: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        );
    }
    let settings = Settings::from_document(serde_json::from_slice(&output.stdout)?, &common)?;
    settings.config(&binary)?;
    let root = common.join("workingdir");
    let root_string = path_string(&root)?;
    if settings.flags["workingdir"]
        .iter()
        .any(|[name, value]| name == "root" && value == &root_string)
    {
        let mut builder = DirBuilder::new();
        builder.recursive(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::DirBuilderExt;
            builder.mode(0o700);
        }
        builder.create(root)?;
    }
    settings.save(&data).context("saving Snap configuration")
}

pub fn load() -> Result<Config> {
    let cache = directory("SNAP_DATA")?.join("flags.json");
    let settings: Settings =
        serde_json::from_reader(File::open(cache).context("opening Snap flags.json")?)
            .context("reading Snap flags.json")?;
    settings.config(&directory("SNAP")?)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn defaults_and_typed_flags_preserve_arguments() {
        let directory = tempfile::tempdir().unwrap();
        let root = directory.path();
        let defaults = Settings::from_document(json!({}), root)
            .unwrap()
            .config(root)
            .unwrap();
        assert_eq!(defaults.server_key_generate_mode, "notexist");
        assert_eq!(
            defaults.server_key,
            root.join("ssh_host_ed25519_key").to_str().unwrap()
        );
        assert_eq!(
            defaults.plugin_commands().unwrap()[0][0],
            root.join("workingdir")
        );
        let settings = Settings::from_document(
            json!({
                "sshpiperd": {
                    "plugins": "fixed failtoban", "port": 2223,
                    "disable-local-forwarding": true, "reply-ping": false,
                    "inject-env": ["FIRST=has spaces", "SECOND=value"],
                },
                "fixed": { "target": "host with spaces:22" },
                "failtoban": { "max-failures": 3 },
                "yaml": null,
            }),
            root,
        )
        .unwrap();
        let config = settings.config(root).unwrap();
        assert_eq!(config.port, 2223);
        assert!(config.disable_local_forwarding);
        assert!(!config.reply_ping);
        assert_eq!(config.inject_env, ["FIRST=has spaces", "SECOND=value"]);
        let commands = config.plugin_commands().unwrap();
        assert_eq!(commands.len(), 2);
        assert_eq!(commands[0][1], "--target=host with spaces:22");
        assert_eq!(commands[1][1], "--max-failures=3");
    }

    #[test]
    fn cache_round_trip_accepts_legacy_shape_and_remains_private() {
        let directory = tempfile::tempdir().unwrap();
        let settings: Settings = serde_json::from_value(json!({
            "sshpiperd.plugins": [["fixed"]],
            "sshpiperd": [["port", "2244"]],
            "fixed": [["target", "localhost:22"]],
        }))
        .unwrap();
        for _ in 0..2 {
            settings.save(directory.path()).unwrap();
        }
        let cache = directory.path().join("flags.json");
        let loaded: Settings = serde_json::from_reader(File::open(&cache).unwrap()).unwrap();
        assert_eq!(loaded.config(directory.path()).unwrap().port, 2244);
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(
                cache.metadata().unwrap().permissions().mode() & 0o777,
                0o600
            );
        }
    }

    #[test]
    fn invalid_configuration_fails_closed() {
        let directory = tempfile::tempdir().unwrap();
        for document in [
            json!([]),
            json!({"sshpiperd": false}),
            json!({"sshpiperd": {"plugins": ["../fixed"]}}),
            json!({"sshpiperd": {"plugins": []}}),
            json!({"sshpiperd": {"port": "not-a-port"}}),
            json!({"fixed": {"target": {"nested": true}}}),
        ] {
            assert!(Settings::from_document(document, directory.path())
                .and_then(|settings| settings.config(directory.path()))
                .is_err());
        }
        assert!(serde_json::from_value::<Settings>(json!({
            "sshpiperd.plugins": [["fixed"]], "fixed": [["target"]]
        }))
        .is_err());
    }
}
