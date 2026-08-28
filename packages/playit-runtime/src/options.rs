use std::path::PathBuf;

use playit_api_client::api::{AgentVersion, Platform};
use serde::Deserialize;

/// The default variant identifier used by the Playit agent.
pub const DEFAULT_VARIANT_ID: &str = "308943e8-faef-4835-a2ba-270351f72aa3";

/// Version and variant identity sent to the Playit control plane.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VersionDetails {
    pub variant_id: String,
    pub major: u32,
    pub minor: u32,
    pub patch: u32,
}

impl VersionDetails {
    pub fn from_cargo_package() -> Result<Self, String> {
        Self::from_version_string(env!("CARGO_PKG_VERSION"), DEFAULT_VARIANT_ID)
    }

    pub fn from_version_string(version: &str, variant_id: &str) -> Result<Self, String> {
        let mut parts = version.split('-').next().unwrap_or(version).split('.');
        let major = parts
            .next()
            .ok_or_else(|| format!("missing major version in {version}"))
            .and_then(parse_version_part)?;
        let minor = parts
            .next()
            .ok_or_else(|| format!("missing minor version in {version}"))
            .and_then(parse_version_part)?;
        let patch = parts
            .next()
            .ok_or_else(|| format!("missing patch version in {version}"))
            .and_then(parse_version_part)?;

        Ok(Self {
            variant_id: variant_id.to_string(),
            major,
            minor,
            patch,
        })
    }

    pub fn version_string(&self) -> String {
        format!("{}.{}.{}", self.major, self.minor, self.patch)
    }

    pub fn apply_overrides(&mut self, overrides: VersionOverrideFile) {
        if let Some(variant_id) = overrides.variant_id {
            self.variant_id = variant_id;
        }
        if let Some(major) = overrides.major {
            self.major = major;
        }
        if let Some(minor) = overrides.minor {
            self.minor = minor;
        }
        if let Some(patch) = overrides.patch {
            self.patch = patch;
        }
    }

    pub(crate) fn agent_version(&self) -> Result<AgentVersion, String> {
        Ok(AgentVersion {
            variant_id: self
                .variant_id
                .parse()
                .map_err(|error| format!("invalid variant ID {}: {error}", self.variant_id))?,
            version_major: self.major,
            version_minor: self.minor,
            version_patch: self.patch,
        })
    }
}

#[derive(Debug, Default, Deserialize)]
pub struct VersionOverrideFile {
    pub variant_id: Option<String>,
    pub major: Option<u32>,
    pub minor: Option<u32>,
    pub patch: Option<u32>,
}

/// Configuration for an embedded Playit runtime.
///
/// The caller must run [`PlayitRuntime::start`](crate::PlayitRuntime::start)
/// inside an existing Tokio runtime. The runtime never reads process-global
/// logging or API configuration; `api_base` and the dedicated secret path are
/// explicit options.
#[derive(Clone)]
pub struct RuntimeOptions {
    /// Dedicated file used for the Playit secret.
    pub secret_path: PathBuf,
    /// Optional inline secret for daemon compatibility. Embedded callers
    /// should normally leave this as `None` and use `secret_path`.
    pub secret: Option<String>,
    /// Version/variant identity sent during agent registration and claim.
    pub version: VersionDetails,
    /// Register the agent as a Docker platform.
    pub platform_docker: bool,
    /// Playit API base URL. This is useful for local test servers.
    pub api_base: String,
}

impl std::fmt::Debug for RuntimeOptions {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("RuntimeOptions")
            .field("secret_path", &self.secret_path)
            .field("secret", &self.secret.as_ref().map(|_| "<redacted>"))
            .field("version", &self.version)
            .field("platform_docker", &self.platform_docker)
            .field("api_base", &self.api_base)
            .finish()
    }
}

impl Default for RuntimeOptions {
    fn default() -> Self {
        Self {
            secret_path: PathBuf::from("playit-secret.toml"),
            secret: None,
            version: VersionDetails::from_cargo_package()
                .expect("Cargo package version must be a valid semver triplet"),
            platform_docker: false,
            api_base: "https://api.playit.gg".to_string(),
        }
    }
}

pub(crate) fn platform_for_options(options: &RuntimeOptions) -> Platform {
    if options.platform_docker {
        Platform::Docker
    } else {
        playit_agent_core::agent_control::platform::current_platform()
    }
}

fn parse_version_part(part: &str) -> Result<u32, String> {
    part.parse::<u32>()
        .map_err(|error| format!("Invalid version component {part}: {error}"))
}

#[cfg(test)]
mod tests {
    use super::RuntimeOptions;

    #[test]
    fn debug_output_redacts_inline_secrets() {
        let options = RuntimeOptions {
            secret: Some("deadbeef".to_string()),
            ..RuntimeOptions::default()
        };
        let debug = format!("{options:?}");

        assert!(debug.contains("<redacted>"));
        assert!(!debug.contains("deadbeef"));
    }
}
