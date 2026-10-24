//! Read-only input boundary diagnostics. Session equality does not imply that
//! SendInput can reach a secure desktop or a higher-integrity foreground app.
use serde::Serialize;

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Access {
    pub requires_console: bool,
    pub reason: Option<&'static str>,
    pub process_integrity: Option<u32>,
    pub foreground_integrity: Option<u32>,
}

fn classify(same_desktop: bool, process: Option<u32>, foreground: Option<u32>) -> Access {
    let reason = if !same_desktop {
        Some("protected-desktop")
    } else if matches!((process, foreground), (Some(current), Some(target)) if target > current) {
        Some("higher-integrity-window")
    } else {
        None
    };
    Access {
        requires_console: reason.is_some(),
        reason,
        process_integrity: process,
        foreground_integrity: foreground,
    }
}

#[cfg(target_os = "linux")]
pub fn status() -> Access {
    classify(crate::input::session_state().can_inject(), None, None)
}

#[cfg(not(any(windows, target_os = "linux")))]
pub fn status() -> Access {
    classify(true, None, None)
}

#[cfg(windows)]
pub fn status() -> Access {
    use windows::Win32::{
        Foundation::{CloseHandle, HANDLE},
        Security::*,
        System::{StationsAndDesktops::*, Threading::*},
        UI::WindowsAndMessaging::*,
    };
    struct Owned(HANDLE);
    impl Drop for Owned {
        fn drop(&mut self) {
            unsafe {
                let _ = CloseHandle(self.0);
            }
        }
    }
    unsafe fn integrity(pid: u32) -> Option<u32> {
        let process = Owned(OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, pid).ok()?);
        let mut token = HANDLE::default();
        OpenProcessToken(process.0, TOKEN_QUERY, &mut token).ok()?;
        let token = Owned(token);
        let mut bytes = 0;
        let _ = GetTokenInformation(token.0, TokenIntegrityLevel, None, 0, &mut bytes);
        if bytes == 0 {
            return None;
        }
        let mut buffer = vec![0usize; (bytes as usize).div_ceil(std::mem::size_of::<usize>())];
        GetTokenInformation(
            token.0,
            TokenIntegrityLevel,
            Some(buffer.as_mut_ptr().cast()),
            bytes,
            &mut bytes,
        )
        .ok()?;
        let label = &*buffer.as_ptr().cast::<TOKEN_MANDATORY_LABEL>();
        let count = *GetSidSubAuthorityCount(label.Label.Sid);
        if count == 0 {
            return None;
        }
        Some(*GetSidSubAuthority(label.Label.Sid, (count - 1) as u32))
    }
    unsafe fn name(desktop: HDESK) -> Option<String> {
        let mut buffer = [0u16; 256];
        GetUserObjectInformationW(
            HANDLE(desktop.0),
            UOI_NAME,
            Some(buffer.as_mut_ptr().cast()),
            (buffer.len() * 2) as u32,
            None,
        )
        .ok()?;
        let len = buffer.iter().position(|v| *v == 0)?;
        String::from_utf16(&buffer[..len]).ok()
    }
    unsafe {
        let process = integrity(GetCurrentProcessId());
        let desktop = match OpenInputDesktop(DESKTOP_CONTROL_FLAGS(0), false, DESKTOP_READOBJECTS) {
            Ok(desktop) => desktop,
            Err(_) => return classify(false, process, None),
        };
        let input_name = name(desktop);
        let current_name = GetThreadDesktop(GetCurrentThreadId())
            .ok()
            .and_then(|d| name(d));
        let _ = CloseDesktop(desktop);
        let same = input_name.is_some() && input_name == current_name;
        let mut pid = 0;
        GetWindowThreadProcessId(GetForegroundWindow(), Some(&mut pid));
        let foreground = if pid == 0 { None } else { integrity(pid) };
        classify(same, process, foreground)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn secure_desktop_and_uipi_are_distinct_from_session_capability() {
        assert_eq!(
            classify(false, Some(8192), None).reason,
            Some("protected-desktop")
        );
        assert_eq!(
            classify(true, Some(8192), Some(12288)).reason,
            Some("higher-integrity-window")
        );
        assert!(!classify(true, Some(12288), Some(12288)).requires_console);
        assert!(!classify(true, Some(8192), None).requires_console);
    }
}
