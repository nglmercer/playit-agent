use std::ffi::OsString;
use std::io;
use std::os::windows::ffi::{OsStrExt, OsStringExt};
use std::path::Path;
use std::ptr::{NonNull, null, null_mut};

use windows_sys::Win32::Foundation::{CloseHandle, HANDLE, LocalFree};
use windows_sys::Win32::Security::Authorization::{
    ConvertSidToStringSidW, ConvertStringSecurityDescriptorToSecurityDescriptorW, SDDL_REVISION_1,
    SE_FILE_OBJECT, SetNamedSecurityInfoW,
};
use windows_sys::Win32::Security::{
    ACL, DACL_SECURITY_INFORMATION, GetSecurityDescriptorDacl, GetTokenInformation,
    PROTECTED_DACL_SECURITY_INFORMATION, PSECURITY_DESCRIPTOR, TOKEN_QUERY, TOKEN_USER, TokenUser,
};
use windows_sys::Win32::Storage::FileSystem::{
    MOVEFILE_REPLACE_EXISTING, MOVEFILE_WRITE_THROUGH, MoveFileExW,
};
use windows_sys::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};

const SECRET_FILE_ACCESS_SDDL_PREFIX: &str = "D:P(A;;FA;;;SY)(A;;FA;;;BA)(A;;FA;;;";

/// Apply a protected DACL to a secret file or its dedicated parent directory.
///
/// The ACL deliberately contains only SYSTEM, local Administrators, and the
/// identity running the embedded process. `D:P` prevents inherited broad ACEs
/// from being reintroduced by the parent directory.
pub(crate) fn protect_path(path: &Path) -> io::Result<()> {
    let user_sid = current_process_user_sid()?;
    let sddl = secret_path_sddl(&user_sid)?;
    let sddl = wide_string(&sddl)?;

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
            "Windows returned an empty secret security descriptor",
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
            "secret security descriptor has no DACL",
        ));
    }

    let path = wide_path(path)?;
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

pub(crate) async fn protect_path_async(path: &Path) -> io::Result<()> {
    let path = path.to_path_buf();
    tokio::task::spawn_blocking(move || protect_path(&path))
        .await
        .map_err(|error| io::Error::other(format!("secret ACL task failed: {error}")))?
}

pub(crate) fn replace_file(source: &Path, destination: &Path) -> io::Result<()> {
    let source = wide_path(source)?;
    let destination = wide_path(destination)?;
    let flags = MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH;
    if unsafe { MoveFileExW(source.as_ptr(), destination.as_ptr(), flags) } == 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(())
    }
}

fn secret_path_sddl(user_sid: &str) -> io::Result<String> {
    let user_sid = normalize_sid(user_sid).ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "Windows returned an invalid current-user SID",
        )
    })?;

    Ok(format!("{SECRET_FILE_ACCESS_SDDL_PREFIX}{user_sid})"))
}

fn current_process_user_sid() -> io::Result<String> {
    let mut token = null_mut();
    if unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) } == 0 {
        return Err(io::Error::last_os_error());
    }

    let token = Handle::new(token).ok_or_else(io::Error::last_os_error)?;
    token_user_sid_string(token.raw())
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
    Ok(string_sid.to_string_lossy())
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

fn wide_string(value: &str) -> io::Result<Vec<u16>> {
    let mut wide: Vec<u16> = value.encode_utf16().collect();
    if wide.contains(&0) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "Windows security descriptor contains an embedded NUL",
        ));
    }
    wide.push(0);
    Ok(wide)
}

fn wide_path(path: &Path) -> io::Result<Vec<u16>> {
    let mut wide: Vec<u16> = path.as_os_str().encode_wide().collect();
    if wide.contains(&0) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "secret path contains an embedded NUL",
        ));
    }
    wide.push(0);
    Ok(wide)
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

    fn to_string_lossy(&self) -> String {
        unsafe {
            let mut len = 0;
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
    use super::{
        DACL_SECURITY_INFORMATION, LocalSecurityDescriptor, protect_path, secret_path_sddl,
        wide_path,
    };
    use std::path::Path;
    use std::ptr::{NonNull, null_mut};
    use windows_sys::Win32::Foundation::LocalFree;
    use windows_sys::Win32::Security::Authorization::{
        ConvertSecurityDescriptorToStringSecurityDescriptorW, GetNamedSecurityInfoW,
        SDDL_REVISION_1, SE_FILE_OBJECT,
    };

    #[test]
    fn secret_sddl_allows_only_system_administrators_and_current_user() {
        let sddl = secret_path_sddl("S-1-5-21-1-2-3-1001").unwrap();

        assert!(sddl.starts_with("D:P"));
        assert!(sddl.contains("(A;;FA;;;SY)"));
        assert!(sddl.contains("(A;;FA;;;BA)"));
        assert!(sddl.contains("(A;;FA;;;S-1-5-21-1-2-3-1001)"));
        assert!(!sddl.contains(";;;AU)"));
        assert!(!sddl.contains(";;;WD)"));
        assert!(!sddl.contains(";;;BU)"));
    }

    #[test]
    fn sid_validation_rejects_sddl_breakout_characters() {
        assert_eq!(
            super::normalize_sid("S-1-5-21-1-2-3-1001"),
            Some("S-1-5-21-1-2-3-1001")
        );
        assert_eq!(super::normalize_sid(""), None);
        assert_eq!(super::normalize_sid("S-1-"), None);
        assert_eq!(super::normalize_sid("S-1-5-21-1-2-3-1001)"), None);
        assert_eq!(super::normalize_sid("S-1-5-21-1-2-3-1001;"), None);
    }

    #[test]
    fn protects_a_secret_file_with_the_restricted_dacl() {
        let path = std::env::temp_dir().join(format!(
            "playit-runtime-windows-secret-{}-{}.tmp",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));

        let result = (|| {
            std::fs::write(&path, b"secret")?;
            protect_path(&path)?;
            read_dacl_sddl(&path)
        })();
        let _ = std::fs::remove_file(&path);

        let sddl = result.unwrap();
        assert!(sddl.starts_with("D:P"));
        assert!(sddl.contains(";;;SY)"));
        assert!(sddl.contains(";;;BA)"));
        assert!(!sddl.contains(";;;AU)"));
        assert!(!sddl.contains(";;;WD)"));
        assert!(!sddl.contains(";;;BU)"));
    }

    fn read_dacl_sddl(path: &Path) -> std::io::Result<String> {
        let path = wide_path(path)?;
        let mut descriptor = null_mut();
        let result = unsafe {
            GetNamedSecurityInfoW(
                path.as_ptr(),
                SE_FILE_OBJECT,
                DACL_SECURITY_INFORMATION,
                null_mut(),
                null_mut(),
                null_mut(),
                null_mut(),
                &mut descriptor,
            )
        };
        if result != 0 {
            return Err(std::io::Error::from_raw_os_error(result as i32));
        }
        let descriptor = LocalSecurityDescriptor::new(descriptor).ok_or_else(|| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "Windows returned an empty file security descriptor",
            )
        })?;

        let mut string_descriptor = null_mut();
        let mut length = 0;
        if unsafe {
            ConvertSecurityDescriptorToStringSecurityDescriptorW(
                descriptor.raw(),
                SDDL_REVISION_1,
                DACL_SECURITY_INFORMATION,
                &mut string_descriptor,
                &mut length,
            )
        } == 0
        {
            return Err(std::io::Error::last_os_error());
        }

        let string_descriptor = NonNull::new(string_descriptor).ok_or_else(|| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "Windows returned an empty string security descriptor",
            )
        })?;
        let mut string_length = 0;
        unsafe {
            while *string_descriptor.as_ptr().add(string_length) != 0 {
                string_length += 1;
            }
            let string = String::from_utf16_lossy(std::slice::from_raw_parts(
                string_descriptor.as_ptr(),
                string_length,
            ));
            let _ = LocalFree(string_descriptor.as_ptr().cast());
            Ok(string)
        }
    }
}
