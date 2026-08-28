use std::process::Command;

use crate::manager::ServiceManagerError;

const SYSTEMD_SERVICE_NAME: &str = "playit";
const OPENRC_SERVICE_NAME: &str = "playit";
pub(crate) fn start_systemd_service() -> Result<(), ServiceManagerError> {
    run_systemctl(&systemd_start_args(), ServiceManagerError::StartFailed)
}

pub(crate) fn start_openrc_service() -> Result<(), ServiceManagerError> {
    run_rc_service(&openrc_start_args(), ServiceManagerError::StartFailed)
}

pub(crate) fn is_systemd_service_active() -> Result<bool, ServiceManagerError> {
    let args = systemd_is_active_args();
    let output = Command::new("systemctl")
        .args(args)
        .output()
        .map_err(|e| ServiceManagerError::NotAvailable(format!("Failed to run systemctl: {e}")))?;

    match output.status.code() {
        Some(0) => Ok(true),
        Some(3) | Some(4) => Ok(false),
        _ => {
            let stderr = String::from_utf8_lossy(&output.stderr).trim().to_string();
            let stdout = String::from_utf8_lossy(&output.stdout).trim().to_string();
            let detail = if !stderr.is_empty() {
                stderr
            } else if !stdout.is_empty() {
                stdout
            } else {
                format!("exit status {}", output.status)
            };

            Err(ServiceManagerError::NotAvailable(format!(
                "systemctl {} failed: {}",
                args.join(" "),
                detail
            )))
        }
    }
}

pub(crate) fn is_openrc_service_active() -> Result<bool, ServiceManagerError> {
    let args = openrc_status_args();
    let output = Command::new("rc-service")
        .args(args)
        .output()
        .map_err(|e| ServiceManagerError::NotAvailable(format!("Failed to run rc-service: {e}")))?;

    Ok(output.status.success())
}

pub(crate) fn stop_systemd_service() -> Result<(), ServiceManagerError> {
    run_systemctl(&systemd_stop_args(), ServiceManagerError::StopFailed)
}

pub(crate) fn stop_openrc_service() -> Result<(), ServiceManagerError> {
    run_rc_service(&openrc_stop_args(), ServiceManagerError::StopFailed)
}

fn systemd_start_args() -> [&'static str; 2] {
    ["start", SYSTEMD_SERVICE_NAME]
}

fn systemd_is_active_args() -> [&'static str; 3] {
    ["is-active", "--quiet", SYSTEMD_SERVICE_NAME]
}

fn systemd_stop_args() -> [&'static str; 2] {
    ["stop", SYSTEMD_SERVICE_NAME]
}

fn openrc_start_args() -> [&'static str; 2] {
    [OPENRC_SERVICE_NAME, "start"]
}

fn openrc_status_args() -> [&'static str; 2] {
    [OPENRC_SERVICE_NAME, "status"]
}

fn openrc_stop_args() -> [&'static str; 2] {
    [OPENRC_SERVICE_NAME, "stop"]
}

fn run_systemctl(
    args: &[&str],
    err_builder: fn(String) -> ServiceManagerError,
) -> Result<(), ServiceManagerError> {
    let output = Command::new("systemctl")
        .args(args)
        .output()
        .map_err(|e| err_builder(format!("Failed to run systemctl: {e}")))?;

    if output.status.success() {
        return Ok(());
    }

    let stderr = String::from_utf8_lossy(&output.stderr).trim().to_string();
    Err(err_builder(format!(
        "systemctl {} failed: {}",
        args.join(" "),
        stderr
    )))
}

fn run_rc_service(
    args: &[&str],
    err_builder: fn(String) -> ServiceManagerError,
) -> Result<(), ServiceManagerError> {
    let output = Command::new("rc-service")
        .args(args)
        .output()
        .map_err(|e| err_builder(format!("Failed to run rc-service: {e}")))?;

    if output.status.success() {
        return Ok(());
    }

    let stderr = String::from_utf8_lossy(&output.stderr).trim().to_string();
    let stdout = String::from_utf8_lossy(&output.stdout).trim().to_string();
    let detail = if !stderr.is_empty() {
        stderr
    } else if !stdout.is_empty() {
        stdout
    } else {
        format!("exit status {}", output.status)
    };

    Err(err_builder(format!(
        "rc-service {} failed: {}",
        args.join(" "),
        detail
    )))
}

#[cfg(test)]
mod tests {
    use super::{
        openrc_start_args, openrc_status_args, openrc_stop_args, systemd_start_args,
        systemd_stop_args,
    };

    #[test]
    fn systemd_command_args_are_stable() {
        assert_eq!(systemd_start_args(), ["start", "playit"]);
        assert_eq!(systemd_stop_args(), ["stop", "playit"]);
    }

    #[test]
    fn openrc_command_args_are_stable() {
        assert_eq!(openrc_start_args(), ["playit", "start"]);
        assert_eq!(openrc_status_args(), ["playit", "status"]);
        assert_eq!(openrc_stop_args(), ["playit", "stop"]);
    }
}
