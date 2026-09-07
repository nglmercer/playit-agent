use std::ffi::OsString;
use std::io;
use std::os::windows::ffi::OsStringExt;
use std::path::{Path, PathBuf};
use std::ptr::{NonNull, null, null_mut};

use interprocess::os::windows::security_descriptor::SecurityDescriptor;
use playit_ipc::ipc::IpcError;
use widestring::U16CString;
use windows_sys::Win32::Foundation::{CloseHandle, HANDLE, LocalFree};
use windows_sys::Win32::Security::Authorization::{
    ConvertSidToStringSidW, ConvertStringSecurityDescriptorToSecurityDescriptorW, SDDL_REVISION_1,
    SE_FILE_OBJECT, SetNamedSecurityInfoW,
};
use windows_sys::Win32::Security::{
    ACL, DACL_SECURITY_INFORMATION, GetSecurityDescriptorDacl, GetTokenInformation,
    PROTECTED_DACL_SECURITY_INFORMATION, PSECURITY_DESCRIPTOR, TOKEN_QUERY, TOKEN_USER, TokenUser,
};
use windows_sys::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};

use crate::windows_service_data_dir;

const RESTRICTED_DATA_SDDL: &str = "D:P(A;;FA;;;SY)(A;;FA;;;BA)";

pub fn installed_user_sid_path() -> PathBuf {
    windows_service_data_dir().join("installed_user.sid")
}

pub fn read_installed_user_sid() -> Option<String> {
    let content = match std::fs::read_to_string(installed_user_sid_path()) {
        Ok(content) => content,
        Err(error) => {
            tracing::debug!("failed to read installed user SID: {error}");
            return None;
        }
    };

    match normalize_sid(content.trim()) {
        Some(sid) => Some(sid.to_string()),
        None => {
            tracing::warn!("installed user SID file is invalid, ignoring it");
            None
        }
    }
}

pub fn write_current_user_sid() -> io::Result<PathBuf> {
    let path = installed_user_sid_path();

    // The MSI's deferred, elevated step writes and protects this file before
    // this compatibility custom action runs. Avoid reopening a protected file
    // from the impersonated installer user.
    if read_installed_user_sid().is_some() {
        return Ok(path);
    }

    let sid = current_process_user_sid()?;
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    std::fs::write(&path, format!("{sid}\n"))?;
    secure_installed_user_sid_storage()?;
    Ok(path)
}

/// Restrict the data directory and the SID file to SYSTEM and Administrators.
///
/// The SID is used to build the named-pipe ACL on the next daemon start. It is
/// therefore security configuration, rather than ordinary user data. Keeping
/// the parent directory protected also prevents an unprivileged user from
/// replacing the file even when they cannot write its contents.
pub fn secure_installed_user_sid_storage() -> io::Result<()> {
    let path = installed_user_sid_path();
    if let Some(parent) = path.parent() {
        set_restricted_data_dacl(parent)?;
    }
    set_restricted_data_dacl(&path)
}

fn set_restricted_data_dacl(path: &Path) -> io::Result<()> {
    let sddl = U16CString::from_str(RESTRICTED_DATA_SDDL).map_err(|error| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("invalid data security descriptor: {error}"),
        )
    })?;
    let mut descriptor = null_mut::<std::ffi::c_void>();
    let mut descriptor_size = 0;
    if unsafe {
        ConvertStringSecurityDescriptorToSecurityDescriptorW(
            sddl.as_ptr(),
            SDDL_REVISION_1,
            &mut descriptor,
            &mut descriptor_size,
        )
    } == 0
    {
        return Err(io::Error::last_os_error());
    }
    let descriptor = LocalSecurityDescriptor::new(descriptor).ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            "Windows returned an empty security descriptor",
        )
    })?;

    let mut dacl_present = 0;
    let mut dacl = null_mut::<ACL>();
    let mut dacl_defaulted = 0;
    if unsafe {
        GetSecurityDescriptorDacl(
            descriptor.raw(),
            &mut dacl_present,
            &mut dacl,
            &mut dacl_defaulted,
        )
    } == 0
    {
        return Err(io::Error::last_os_error());
    }
    if dacl_present == 0 || dacl.is_null() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "security descriptor has no DACL",
        ));
    }

    let path = U16CString::from_os_str(path).map_err(|error| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("invalid data path: {error}"),
        )
    })?;

    let result = unsafe {
        SetNamedSecurityInfoW(
            path.as_ptr(),
            SE_FILE_OBJECT,
            DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION,
            null_mut(),
            null_mut(),
            dacl.cast_const(),
            null(),
        )
    };
    if result == 0 {
        Ok(())
    } else {
        Err(io::Error::from_raw_os_error(result as i32))
    }
}

pub fn current_process_user_sid() -> io::Result<String> {
    let mut token = null_mut();
    if unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) } == 0 {
        return Err(io::Error::last_os_error());
    }

    let token = Handle::new(token).ok_or_else(io::Error::last_os_error)?;
    token_user_sid_string(token.raw())
}

pub fn restricted_pipe_security_descriptor() -> Result<SecurityDescriptor, IpcError> {
    let mut user_sid = read_installed_user_sid();
    if user_sid.is_none() {
        match current_process_user_sid() {
            Ok(sid) => user_sid = Some(sid),
            Err(error) => {
                tracing::warn!("failed to read current process SID for IPC ACL fallback: {error}");
            }
        }
    }

    let sddl = pipe_security_sddl(user_sid.as_deref());
    let sddl = U16CString::from_str(&sddl).map_err(|error| {
        IpcError::BindFailed(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("invalid pipe security descriptor string: {error}"),
        ))
    })?;

    SecurityDescriptor::deserialize(&sddl).map_err(IpcError::BindFailed)
}

fn token_user_sid_string(token: HANDLE) -> io::Result<String> {
    let mut needed = 0;
    unsafe {
        GetTokenInformation(token, TokenUser, null_mut(), 0, &mut needed);
    }

    if needed == 0 {
        return Err(io::Error::last_os_error());
    }

    let mut buffer = vec![0u8; needed as usize];
    if unsafe {
        GetTokenInformation(
            token,
            TokenUser,
            buffer.as_mut_ptr().cast(),
            needed,
            &mut needed,
        )
    } == 0
    {
        return Err(io::Error::last_os_error());
    }

    let token_user = unsafe { &*(buffer.as_ptr().cast::<TOKEN_USER>()) };
    sid_to_string(token_user.User.Sid)
}

fn sid_to_string(sid: *mut std::ffi::c_void) -> io::Result<String> {
    let mut string_sid = null_mut();
    if unsafe { ConvertSidToStringSidW(sid, &mut string_sid) } == 0 {
        return Err(io::Error::last_os_error());
    }

    let string_sid = LocalString::new(string_sid).ok_or_else(io::Error::last_os_error)?;
    Ok(string_sid.to_string())
}

fn normalize_sid(sid: &str) -> Option<&str> {
    if !sid.starts_with("S-1-") {
        return None;
    }

    if sid
        .chars()
        .any(|c| c.is_whitespace() || matches!(c, '(' | ')' | ';'))
    {
        return None;
    }

    if !sid
        .chars()
        .all(|c| c.is_ascii_digit() || matches!(c, 'S' | '-'))
    {
        return None;
    }

    let mut parts = sid.split('-');
    if parts.next() != Some("S") || parts.next() != Some("1") {
        return None;
    }
    if !parts.all(|part| !part.is_empty() && part.chars().all(|c| c.is_ascii_digit())) {
        return None;
    }

    Some(sid)
}

fn pipe_security_sddl(user_sid: Option<&str>) -> String {
    let mut sddl = String::from("D:P(A;;GA;;;SY)(A;;GA;;;BA)");
    if let Some(user_sid) = user_sid.and_then(normalize_sid) {
        sddl.push_str("(A;;GA;;;");
        sddl.push_str(user_sid);
        sddl.push(')');
    }
    sddl
}

struct Handle(NonNull<std::ffi::c_void>);

impl Handle {
    fn new(handle: HANDLE) -> Option<Self> {
        NonNull::new(handle).map(Self)
    }

    fn raw(&self) -> HANDLE {
        self.0.as_ptr()
    }
}

impl Drop for Handle {
    fn drop(&mut self) {
        unsafe {
            CloseHandle(self.raw());
        }
    }
}

struct LocalString(NonNull<u16>);

impl LocalString {
    fn new(ptr: *mut u16) -> Option<Self> {
        NonNull::new(ptr).map(Self)
    }

    fn to_string(&self) -> String {
        let mut len = 0;
        unsafe {
            while *self.0.as_ptr().add(len) != 0 {
                len += 1;
            }
            OsString::from_wide(std::slice::from_raw_parts(self.0.as_ptr(), len))
                .to_string_lossy()
                .into_owned()
        }
    }
}

impl Drop for LocalString {
    fn drop(&mut self) {
        unsafe {
            let _ = LocalFree(self.0.as_ptr().cast());
        }
    }
}

struct LocalSecurityDescriptor(NonNull<std::ffi::c_void>);

impl LocalSecurityDescriptor {
    fn new(ptr: PSECURITY_DESCRIPTOR) -> Option<Self> {
        NonNull::new(ptr).map(Self)
    }

    fn raw(&self) -> PSECURITY_DESCRIPTOR {
        self.0.as_ptr()
    }
}

impl Drop for LocalSecurityDescriptor {
    fn drop(&mut self) {
        unsafe {
            let _ = LocalFree(self.0.as_ptr().cast());
        }
    }
}

#[cfg(test)]
mod tests {
    use interprocess::os::windows::security_descriptor::AsSecurityDescriptorExt;

    use super::{
        DACL_SECURITY_INFORMATION, RESTRICTED_DATA_SDDL, normalize_sid, pipe_security_sddl,
    };

    #[test]
    fn pipe_sddl_allows_service_admins_and_installed_user_only() {
        let sddl = pipe_security_sddl(Some("S-1-5-21-1-2-3-1001"));

        assert!(sddl.contains("(A;;GA;;;SY)"));
        assert!(sddl.contains("(A;;GA;;;BA)"));
        assert!(sddl.contains("(A;;GA;;;S-1-5-21-1-2-3-1001)"));
        assert!(!sddl.contains(";;;AU)"));
        assert!(!sddl.contains(";;;WD)"));
        assert!(!sddl.contains(";;;BU)"));
    }

    #[test]
    fn pipe_sddl_fallback_does_not_grant_broad_access() {
        let sddl = pipe_security_sddl(None);

        assert!(sddl.contains("(A;;GA;;;SY)"));
        assert!(sddl.contains("(A;;GA;;;BA)"));
        assert!(!sddl.contains(";;;AU)"));
        assert!(!sddl.contains(";;;WD)"));
        assert!(!sddl.contains(";;;BU)"));
    }

    #[test]
    fn installed_sid_storage_sddl_is_restricted() {
        assert!(RESTRICTED_DATA_SDDL.starts_with("D:P"));
        assert!(RESTRICTED_DATA_SDDL.contains("(A;;FA;;;SY)"));
        assert!(RESTRICTED_DATA_SDDL.contains("(A;;FA;;;BA)"));
        assert!(!RESTRICTED_DATA_SDDL.contains(";;;AU)"));
        assert!(!RESTRICTED_DATA_SDDL.contains(";;;WD)"));
        assert!(!RESTRICTED_DATA_SDDL.contains(";;;BU)"));
    }

    #[test]
    fn parsed_pipe_descriptor_has_no_broad_user_access() {
        let descriptor = super::restricted_pipe_security_descriptor().unwrap();
        let sddl = descriptor
            .serialize(DACL_SECURITY_INFORMATION, |security_descriptor| {
                security_descriptor.to_string_lossy()
            })
            .unwrap();

        assert!(sddl.contains(";;;SY)"));
        assert!(sddl.contains(";;;BA)"));
        assert!(!sddl.contains(";;;AU)"));
        assert!(!sddl.contains(";;;WD)"));
        assert!(!sddl.contains(";;;BU)"));
    }

    #[test]
    fn sid_validation_rejects_sddl_breakout_characters() {
        assert_eq!(
            normalize_sid("S-1-5-21-1-2-3-1001"),
            Some("S-1-5-21-1-2-3-1001")
        );
        assert_eq!(normalize_sid(""), None);
        assert_eq!(normalize_sid("S-1-"), None);
        assert_eq!(normalize_sid(" S-1-5-21-1-2-3-1001"), None);
        assert_eq!(normalize_sid("S-1-5-21-1-2-3-1001 "), None);
        assert_eq!(normalize_sid("S-1-5-21-1-2-3-1001)"), None);
        assert_eq!(normalize_sid("S-1-5-21-1-2-3-1001;"), None);
        assert_eq!(normalize_sid("S-1-5-21-1-2-3-1001("), None);
    }
}
