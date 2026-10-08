//! Bounded Unicode text clipboard access in the agent's interactive session.
//! No files, images, command execution, or clipboard-content diagnostics.

pub const MAX_TEXT_BYTES: usize = 64 * 1024;

pub fn validate_text(text: &str) -> Result<(), String> {
    if text.len() > MAX_TEXT_BYTES {
        return Err("clipboard-text-too-large".into());
    }
    if text.contains('\0') {
        return Err("clipboard-text-contains-nul".into());
    }
    Ok(())
}

pub fn read_text() -> Result<Option<String>, String> {
    platform::read_text()
}

pub fn write_text(text: &str) -> Result<(), String> {
    validate_text(text)?;
    platform::write_text(text)
}

#[cfg(not(target_os = "windows"))]
mod platform {
    pub fn read_text() -> Result<Option<String>, String> {
        Err("clipboard-backend-unavailable".into())
    }
    pub fn write_text(_text: &str) -> Result<(), String> {
        Err("clipboard-backend-unavailable".into())
    }
}

#[cfg(target_os = "windows")]
mod platform {
    use super::*;
    use windows::core::w;
    use windows::Win32::Foundation::{GlobalFree, HANDLE, HGLOBAL, HWND};
    use windows::Win32::System::DataExchange::{
        CloseClipboard, EmptyClipboard, GetClipboardData, IsClipboardFormatAvailable,
        OpenClipboard, SetClipboardData,
    };
    use windows::Win32::System::Memory::{
        GlobalAlloc, GlobalLock, GlobalSize, GlobalUnlock, GMEM_MOVEABLE,
    };
    use windows::Win32::UI::WindowsAndMessaging::{
        CreateWindowExW, DestroyWindow, HWND_MESSAGE, WINDOW_EX_STYLE, WINDOW_STYLE,
    };

    const UNICODE_TEXT: u32 = 13;

    struct Clipboard(HWND);
    impl Clipboard {
        fn open() -> Result<Self, String> {
            // EmptyClipboard with a NULL owner makes SetClipboardData fail.
            // Own a hidden window on this thread for the duration of access.
            let hwnd = unsafe {
                CreateWindowExW(
                    WINDOW_EX_STYLE(0),
                    w!("STATIC"),
                    w!(""),
                    WINDOW_STYLE(0),
                    0,
                    0,
                    0,
                    0,
                    HWND_MESSAGE,
                    None,
                    None,
                    None,
                )
            };
            if hwnd.0 == 0 {
                return Err("clipboard-window-unavailable".into());
            }
            // Other applications hold the clipboard briefly; retry boundedly.
            for _ in 0..5 {
                if unsafe { OpenClipboard(hwnd) }.is_ok() {
                    return Ok(Self(hwnd));
                }
                std::thread::sleep(std::time::Duration::from_millis(20));
            }
            unsafe {
                let _ = DestroyWindow(hwnd);
            }
            Err("clipboard-busy".into())
        }
    }
    impl Drop for Clipboard {
        fn drop(&mut self) {
            unsafe {
                let _ = CloseClipboard();
                let _ = DestroyWindow(self.0);
            }
        }
    }

    pub fn read_text() -> Result<Option<String>, String> {
        let _clipboard = Clipboard::open()?;
        unsafe {
            if IsClipboardFormatAvailable(UNICODE_TEXT).is_err() {
                return Ok(None);
            }
            let handle = GetClipboardData(UNICODE_TEXT).map_err(|_| "clipboard-read-failed")?;
            let global = HGLOBAL(handle.0 as *mut _);
            let size = GlobalSize(global);
            if !(2..=(MAX_TEXT_BYTES + 1) * 2).contains(&size) || size % 2 != 0 {
                return Err("clipboard-text-too-large-or-invalid".into());
            }
            let ptr = GlobalLock(global) as *const u16;
            if ptr.is_null() {
                return Err("clipboard-lock-failed".into());
            }
            let units = std::slice::from_raw_parts(ptr, size / 2);
            let text = match units.iter().position(|&unit| unit == 0) {
                Some(end) => String::from_utf16(&units[..end])
                    .map_err(|_| "clipboard-invalid-unicode".to_owned()),
                None => Err("clipboard-unterminated-text".into()),
            };
            let _ = GlobalUnlock(global);
            let text = text?;
            validate_text(&text)?;
            Ok(Some(text))
        }
    }

    pub fn write_text(text: &str) -> Result<(), String> {
        let units: Vec<u16> = text.encode_utf16().chain(std::iter::once(0)).collect();
        let _clipboard = Clipboard::open()?;
        unsafe {
            let global = GlobalAlloc(GMEM_MOVEABLE, units.len() * 2)
                .map_err(|_| "clipboard-allocation-failed")?;
            let ptr = GlobalLock(global) as *mut u16;
            if ptr.is_null() {
                let _ = GlobalFree(global);
                return Err("clipboard-lock-failed".into());
            }
            std::ptr::copy_nonoverlapping(units.as_ptr(), ptr, units.len());
            let _ = GlobalUnlock(global);
            let result = EmptyClipboard().and_then(|()| {
                SetClipboardData(UNICODE_TEXT, HANDLE(global.0 as isize)).map(|_| ())
            });
            if result.is_err() {
                let _ = GlobalFree(global);
                return Err("clipboard-write-failed".into());
            }
            // Windows owns the allocation after successful SetClipboardData.
            Ok(())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn text_limits_count_utf8_and_reject_embedded_nul() {
        assert!(validate_text("PowerShell\r\nλ 🦀\t").is_ok());
        assert!(validate_text("").is_ok());
        assert!(validate_text(&"x".repeat(MAX_TEXT_BYTES)).is_ok());
        assert!(validate_text(&"é".repeat(MAX_TEXT_BYTES)).is_err());
        assert!(validate_text("left\0right").is_err());
    }

    #[cfg(target_os = "windows")]
    #[test]
    fn native_unicode_clipboard_roundtrip() {
        if std::env::var("KW_CLIPBOARD_NATIVE_TEST").as_deref() != Ok("1") {
            return;
        }
        // Preserve existing text. Do not replace non-text clipboard formats
        // that this deliberately text-only backend cannot restore.
        let Some(previous) = read_text().expect("read original clipboard") else {
            return;
        };
        struct Restore(String);
        impl Drop for Restore {
            fn drop(&mut self) {
                let _ = write_text(&self.0);
            }
        }
        let _restore = Restore(previous);
        for text in ["clipboard proof\r\nλ 🦀\t", ""] {
            write_text(text).expect("write clipboard");
            assert_eq!(read_text().expect("read clipboard"), Some(text.to_owned()));
        }
        println!("native clipboard Unicode/empty-text roundtrip verified");
    }
}
