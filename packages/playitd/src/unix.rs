use std::{io, path::Path};

#[cfg(not(target_os = "linux"))]
use std::os::unix::fs::PermissionsExt;
#[cfg(target_os = "linux")]
use std::{
    ffi::CString,
    os::unix::{ffi::OsStrExt, fs::PermissionsExt},
};

use playit_ipc::ipc::IpcError;

#[cfg(target_os = "linux")]
const PLAYIT_SOCKET_GROUP_NAME: &str = "playit";
#[cfg(target_os = "linux")]
const PLAYIT_SOCKET_MODE: u32 = 0o660;
#[cfg(not(target_os = "linux"))]
const PLAYIT_SOCKET_MODE: u32 = 0o600;

pub(crate) fn socket_mode() -> libc::mode_t {
    PLAYIT_SOCKET_MODE as libc::mode_t
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct SocketPermissionTarget<'a> {
    path: &'a str,
    #[cfg(target_os = "linux")]
    group_name: &'static str,
    mode: u32,
    chown_group: bool,
}

pub(crate) fn configure_socket_permissions(socket_path: &str) -> Result<(), IpcError> {
    let effective_uid = {
        #[cfg(target_os = "linux")]
        {
            crate::unix_account::effective_uid()
        }
        #[cfg(not(target_os = "linux"))]
        {
            0
        }
    };

    let Some(target) = socket_permission_target(socket_path, effective_uid) else {
        return Ok(());
    };

    if !Path::new(target.path).exists() {
        return Err(IpcError::BindFailed(io::Error::new(
            io::ErrorKind::NotFound,
            format!("IPC socket {} was not created", target.path),
        )));
    }

    #[cfg(target_os = "linux")]
    let group_gid = if target.chown_group {
        match crate::unix_account::group_gid_by_name(target.group_name) {
            Some(group_gid) => Some(group_gid),
            None => {
                tracing::warn!(
                    group = target.group_name,
                    socket_path = %target.path,
                    "IPC socket group is missing, leaving the current socket group in place"
                );
                None
            }
        }
    } else {
        None
    };

    #[cfg(not(target_os = "linux"))]
    let group_gid = None;

    apply_socket_permissions(target.path, group_gid, target.mode)
}

fn socket_permission_target(
    socket_path: &str,
    effective_uid: u32,
) -> Option<SocketPermissionTarget<'_>> {
    if socket_path.starts_with('@') || socket_path.starts_with(r"\\.\pipe\") {
        return None;
    }

    Some(SocketPermissionTarget {
        path: socket_path,
        #[cfg(target_os = "linux")]
        group_name: PLAYIT_SOCKET_GROUP_NAME,
        mode: PLAYIT_SOCKET_MODE,
        chown_group: cfg!(target_os = "linux") && effective_uid == 0,
    })
}

fn apply_socket_permissions(
    socket_path: &str,
    group_gid: Option<u32>,
    mode: u32,
) -> Result<(), IpcError> {
    let path = Path::new(socket_path);
    let permissions = std::fs::Permissions::from_mode(mode);
    std::fs::set_permissions(path, permissions).map_err(|error| {
        IpcError::BindFailed(io::Error::new(
            error.kind(),
            format!("failed to chmod IPC socket {socket_path} to {mode:o}: {error}"),
        ))
    })?;

    #[cfg(target_os = "linux")]
    if let Some(group_gid) = group_gid {
        let path_cstr = CString::new(path.as_os_str().as_bytes()).map_err(|error| {
            IpcError::BindFailed(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("invalid IPC socket path {socket_path:?}: {error}"),
            ))
        })?;

        let chown_status = unsafe { libc::chown(path_cstr.as_ptr(), u32::MAX, group_gid) };
        if chown_status != 0 {
            return Err(IpcError::BindFailed(io::Error::new(
                io::ErrorKind::PermissionDenied,
                format!(
                    "failed to chown IPC socket {socket_path} to group gid {group_gid}: {}",
                    io::Error::last_os_error()
                ),
            )));
        }
    }

    #[cfg(not(target_os = "linux"))]
    let _ = group_gid;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{PLAYIT_SOCKET_MODE, socket_permission_target};

    #[cfg(target_os = "linux")]
    #[test]
    fn root_linux_socket_uses_restricted_playit_group_permissions() {
        let target = socket_permission_target("/run/playit/playitd.sock", 0).unwrap();

        assert_eq!(target.mode, PLAYIT_SOCKET_MODE);
        assert_eq!(target.group_name, "playit");
        assert!(target.chown_group);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn non_root_linux_socket_keeps_group_and_restricts_mode() {
        let target = socket_permission_target("/run/playit/playitd.sock", 1234).unwrap();

        assert_eq!(target.mode, PLAYIT_SOCKET_MODE);
        assert!(!target.chown_group);
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn macos_socket_is_owner_only() {
        let target =
            socket_permission_target("/Users/test/Library/Application Support/playit.sock", 0)
                .unwrap();

        assert_eq!(target.mode, 0o600);
        assert!(!target.chown_group);
    }

    #[test]
    fn non_filesystem_endpoints_are_not_chmodded() {
        assert!(socket_permission_target("@playitd", 0).is_none());
        assert!(socket_permission_target(r"\\.\pipe\playitd-system", 0).is_none());
    }
}
