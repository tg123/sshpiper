use std::{ffi::OsString, time::Duration};

use anyhow::{bail, Result};
use clap::Parser;

#[derive(Clone, Debug, Parser)]
#[command(name = "sshpiperd", version = env!("SSHPIPERD_VERSION"), trailing_var_arg = true)]
pub struct Config {
    #[arg(
        long,
        short = 'l',
        env = "SSHPIPERD_ADDRESS",
        default_value = "0.0.0.0"
    )]
    pub address: String,
    #[arg(long, short = 'p', env = "SSHPIPERD_PORT", default_value_t = 2222)]
    pub port: u16,
    #[arg(
        long,
        short = 'i',
        env = "SSHPIPERD_SERVER_KEY",
        default_value = "/etc/ssh/ssh_host_ed25519_key"
    )]
    pub server_key: String,
    #[arg(long, env = "SSHPIPERD_SERVER_KEY_DATA")]
    pub server_key_data: Option<String>,
    #[arg(long, env = "SSHPIPERD_SERVER_CERT")]
    pub server_cert: Option<String>,
    #[arg(long, env = "SSHPIPERD_SERVER_CERT_DATA")]
    pub server_cert_data: Option<String>,
    #[arg(long, env = "SSHPIPERD_SERVER_KEY_GENERATE_MODE", default_value = "disable",
        value_parser = ["disable", "notexist", "always"])]
    pub server_key_generate_mode: String,
    #[arg(long, env = "SSHPIPERD_LOGIN_GRACE_TIME", default_value = "30s", value_parser = humantime::parse_duration)]
    pub login_grace_time: Duration,
    #[arg(long, env = "SSHPIPERD_LOG_LEVEL", default_value = "info")]
    pub log_level: String,
    #[arg(long, env = "SSHPIPERD_LOG_FORMAT", default_value = "text", value_parser = ["text", "json"])]
    pub log_format: String,
    #[arg(long, env = "SSHPIPERD_SCREEN_RECORDING_DIR")]
    pub screen_recording_dir: Option<String>,
    #[arg(long, env = "SSHPIPERD_SCREEN_RECORDING_FORMAT", default_value = "asciicast",
        value_parser = ["asciicast", "typescript"])]
    pub screen_recording_format: String,
    #[arg(long, env = "SSHPIPERD_USERNAME_AS_RECORDDIR", default_value_t = false,
        action = clap::ArgAction::Set, num_args = 0..=1, require_equals = true, default_missing_value = "true")]
    pub username_as_recorddir: bool,
    #[arg(long, env = "SSHPIPERD_BANNERTEXT")]
    pub banner_text: Option<String>,
    #[arg(long, env = "SSHPIPERD_BANNERFILE")]
    pub banner_file: Option<String>,
    #[arg(long, env = "SSHPIPERD_UPSTREAM_BANNER_MODE", default_value = "passthrough",
        value_parser = ["passthrough", "ignore", "dedup", "first-only"])]
    pub upstream_banner_mode: String,
    #[arg(long, env = "SSHPIPERD_DROP_HOSTKEYS_MESSAGE", default_value_t = false,
        action = clap::ArgAction::Set, num_args = 0..=1, require_equals = true, default_missing_value = "true")]
    pub drop_hostkeys_message: bool,
    #[arg(long, env = "SSHPIPERD_REPLY_PING", default_value_t = true,
        action = clap::ArgAction::Set, num_args = 0..=1, require_equals = true, default_missing_value = "true")]
    pub reply_ping: bool,
    #[arg(long, env = "SSHPIPERD_DISABLE_LOCAL_FORWARDING", default_value_t = false,
        action = clap::ArgAction::Set, num_args = 0..=1, require_equals = true, default_missing_value = "true")]
    pub disable_local_forwarding: bool,
    #[arg(long, env = "SSHPIPERD_DISABLE_REMOTE_FORWARDING", default_value_t = false,
        action = clap::ArgAction::Set, num_args = 0..=1, require_equals = true, default_missing_value = "true")]
    pub disable_remote_forwarding: bool,
    #[arg(long, env = "SSHPIPERD_INJECT_ENV", value_delimiter = ',')]
    pub inject_env: Vec<String>,
    #[arg(long, env = "SSHPIPERD_ALLOWED_PROXY_ADDRESSES", value_delimiter = ',')]
    pub allowed_proxy_addresses: Vec<ipnet::IpNet>,
    #[arg(long, env = "SSHPIPERD_PROXY_READ_HEADER_TIMEOUT", default_value = "200ms", value_parser = humantime::parse_duration)]
    pub proxy_read_header_timeout: Duration,
    #[arg(
        long,
        env = "SSHPIPERD_ALLOWED_DOWNSTREAM_KEYEXCHANGE_ALGOS",
        value_delimiter = ','
    )]
    pub allowed_downstream_keyexchange_algos: Vec<String>,
    #[arg(
        long,
        env = "SSHPIPERD_ALLOWED_DOWNSTREAM_CIPHERS_ALGOS",
        value_delimiter = ','
    )]
    pub allowed_downstream_ciphers_algos: Vec<String>,
    #[arg(
        long,
        env = "SSHPIPERD_ALLOWED_DOWNSTREAM_MACS_ALGOS",
        value_delimiter = ','
    )]
    pub allowed_downstream_macs_algos: Vec<String>,
    #[arg(
        long,
        env = "SSHPIPERD_ALLOWED_DOWNSTREAM_PUBKEY_ALGOS",
        value_delimiter = ','
    )]
    pub allowed_downstream_pubkey_algos: Vec<String>,
    #[arg(
        long,
        env = "SSHPIPERD_ADMIN_GRPC_ADDRESS",
        default_value = "127.0.0.1"
    )]
    pub admin_grpc_address: String,
    #[arg(long, env = "SSHPIPERD_ADMIN_GRPC_PORT", default_value_t = 0)]
    pub admin_grpc_port: u16,
    #[arg(long, env = "SSHPIPERD_ADMIN_GRPC_ID")]
    pub admin_grpc_id: Option<String>,
    #[arg(long, env = "SSHPIPERD_ADMIN_GRPC_INSECURE", default_value_t = false,
        action = clap::ArgAction::Set, num_args = 0..=1, require_equals = true, default_missing_value = "true")]
    pub admin_grpc_insecure: bool,
    #[arg(long, env = "SSHPIPERD_ADMIN_GRPC_TLS_CERT")]
    pub admin_grpc_tls_cert: Option<String>,
    #[arg(long, env = "SSHPIPERD_ADMIN_GRPC_TLS_KEY")]
    pub admin_grpc_tls_key: Option<String>,
    #[arg(long, env = "SSHPIPERD_ADMIN_GRPC_TLS_CACERT")]
    pub admin_grpc_tls_cacert: Option<String>,
    #[arg(allow_hyphen_values = true)]
    pub plugins: Vec<OsString>,
}

impl Config {
    pub fn validate(&self) -> Result<()> {
        self.transport_algorithms()?;
        if self.admin_grpc_port != 0 {
            let has_tls = self.admin_grpc_tls_cert.is_some()
                || self.admin_grpc_tls_key.is_some()
                || self.admin_grpc_tls_cacert.is_some();
            if self.admin_grpc_insecure && has_tls {
                bail!("--admin-grpc-insecure cannot be combined with TLS options");
            }
            if !self.admin_grpc_insecure
                && (self.admin_grpc_tls_cert.is_none() || self.admin_grpc_tls_key.is_none())
            {
                bail!("admin gRPC API requires --admin-grpc-tls-cert and --admin-grpc-tls-key (or pass --admin-grpc-insecure to disable TLS)");
            }
        }
        for entry in &self.inject_env {
            if !entry
                .split_once('=')
                .is_some_and(|(key, _)| !key.is_empty())
            {
                bail!("invalid --inject-env {entry:?}: expected KEY=VALUE");
            }
        }
        Ok(())
    }

    pub fn transport_algorithms(&self) -> Result<sshpiper_transport::Algorithms> {
        Ok(sshpiper_transport::Algorithms::new(
            &self.allowed_downstream_keyexchange_algos,
            &self.allowed_downstream_ciphers_algos,
            &self.allowed_downstream_macs_algos,
        )?)
    }

    pub fn plugin_commands(&self) -> Result<Vec<Vec<OsString>>> {
        let mut arguments = self.plugins.clone();
        if arguments.is_empty() {
            if let Some(plugin) = std::env::var_os("PLUGIN") {
                let mut directories = vec![std::env::current_exe()?
                    .parent()
                    .ok_or_else(|| anyhow::anyhow!("executable has no parent directory"))?
                    .join("plugins")];
                if let Some(path) = std::env::var_os("SSHPIPERD_PLUGIN_PATH") {
                    directories.push(path.into());
                }
                let found = directories
                    .iter()
                    .map(|dir| dir.join(&plugin))
                    .find(|path| path.is_file());
                arguments.push(found.map(|path| path.into_os_string()).unwrap_or(plugin));
            }
        }
        let commands: Vec<_> = arguments
            .split(|arg| arg == "--")
            .filter(|command| !command.is_empty())
            .map(|command| command.to_vec())
            .collect();
        if commands.is_empty() {
            bail!("at least one plugin is required");
        }
        Ok(commands)
    }
}
