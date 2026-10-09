//! Guest input injection: keyboard, pointer and wheel into the agent's
//! interactive desktop session. No macros, no privilege elevation and no
//! generic command execution — only the bounded named events the protocol
//! defines.
//!
//! Windows restricts `SendInput` to the caller's session, so a service in
//! session 0 cannot drive the console desktop. The agent therefore runs in
//! the interactive session and [`available`] is true only when this process
//! shares the active console session. Everything else fails fast rather than
//! silently injecting into an invisible desktop.
//!
//! Key mapping is deterministic and layout-independent for named keys and
//! US-layout alphanumerics/punctuation: the viewer sends X11 keysyms and also
//! presses Shift/Ctrl/Alt itself, so only the base key is emitted here.

use std::sync::Mutex;

/// One resolved virtual key: virtual-key code plus whether it is an
/// extended key (arrows, Insert/Delete, nav cluster, right Ctrl/Alt, Windows
/// and menu keys, numpad divide/enter).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Key {
    pub code: u16,
    pub extended: bool,
}

/// Stateful injector: remembers the pressed mouse buttons so a pointer event
/// can emit only the button transitions. One per served session.
pub struct Injector {
    output_name: Option<String>,
    buttons: u8,
    keys: std::collections::BTreeSet<u32>,
}

impl Injector {
    pub fn new() -> Result<Self, String> {
        Self::for_output(None)
    }

    pub fn for_output(output_name: Option<String>) -> Result<Self, String> {
        platform::pointer_space(output_name.as_deref())?;
        Ok(Self {
            output_name,
            buttons: 0,
            keys: std::collections::BTreeSet::new(),
        })
    }

    pub fn key(&mut self, keysym: u32, down: bool) -> Result<(), String> {
        platform::key(keysym, down)?;
        if down {
            self.keys.insert(keysym);
        } else {
            self.keys.remove(&keysym);
        }
        Ok(())
    }

    pub fn pointer(&mut self, x: i32, y: i32, buttons: u8) -> Result<(), String> {
        let space = platform::pointer_space(self.output_name.as_deref())?;
        platform::pointer(&mut self.buttons, space, x, y, buttons)
    }

    pub fn wheel(&mut self, dx: i32, dy: i32) -> Result<(), String> {
        platform::wheel(dx, dy)
    }

    /// Release any mouse buttons still held. Called at session teardown so a
    /// disconnect cannot leave a button stuck down on the guest desktop.
    /// Best-effort: a failed release is not worth surfacing.
    pub fn release(&mut self) {
        for keysym in std::mem::take(&mut self.keys) {
            let _ = platform::key(keysym, false);
        }
        platform::release(&mut self.buttons);
    }
}

/// Where the process runs relative to the active console session, for honest
/// logs and to gate `serve --input`.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct SessionState {
    pub current: Option<u32>,
    pub active_console: Option<u32>,
}

impl SessionState {
    /// Injection can reach the visible desktop only from the active console
    /// session (never session 0, which has no interactive desktop).
    pub fn can_inject(&self) -> bool {
        matches!((self.current, self.active_console), (Some(cur), Some(console)) if cur == console && cur != 0)
    }
}

/// This process's session and the OS's active console session.
pub fn session_state() -> SessionState {
    platform::session_state()
}

/// Whether input injection is usable from this process right now.
pub fn available() -> bool {
    session_state().can_inject()
}

/// Shared handle used by the transport's input trait.
pub type SharedInjector = Mutex<Injector>;

/// Map an X11 keysym to a virtual key. Named keys, US-layout letters, digits
/// and punctuation are handled; unmapped keysyms fall through to
/// [`keysym_to_unicode`].
pub fn keysym_to_key(keysym: u32) -> Option<Key> {
    let key = |code: u32, extended: bool| {
        Some(Key {
            code: code as u16,
            extended,
        })
    };
    match keysym {
        // Whitespace / control.
        0x20 => key(0x20, false),            // space
        0xFF08 => key(0x08, false),          // BackSpace
        0xFF09 | 0xFE20 => key(0x09, false), // Tab / ISO_Left_Tab
        0xFF0D => key(0x0D, false),          // Return
        0xFF1B => key(0x1B, false),          // Escape
        // Editing / navigation (extended).
        0xFFFF => key(0x2E, true),  // Delete
        0xFF63 => key(0x2D, true),  // Insert
        0xFF50 => key(0x24, true),  // Home
        0xFF57 => key(0x23, true),  // End
        0xFF55 => key(0x21, true),  // Page_Up
        0xFF56 => key(0x22, true),  // Page_Down
        0xFF51 => key(0x25, true),  // Left
        0xFF52 => key(0x26, true),  // Up
        0xFF53 => key(0x27, true),  // Right
        0xFF54 => key(0x28, true),  // Down
        0xFF61 => key(0x2C, true),  // Print
        0xFF13 => key(0x13, false), // Pause
        // Locks.
        0xFFE5 => key(0x14, false), // Caps_Lock
        0xFF7F => key(0x90, true),  // Num_Lock
        0xFF14 => key(0x91, false), // Scroll_Lock
        // Modifiers.
        0xFFE1 => key(0xA0, false), // Shift_L
        0xFFE2 => key(0xA1, false), // Shift_R
        0xFFE3 => key(0xA2, false), // Control_L
        0xFFE4 => key(0xA3, true),  // Control_R
        0xFFE9 => key(0xA4, false), // Alt_L
        0xFFEA => key(0xA5, true),  // Alt_R
        0xFFEB => key(0x5B, true),  // Super_L (left Windows)
        0xFFEC => key(0x5C, true),  // Super_R (right Windows)
        0xFF67 => key(0x5D, true),  // Menu
        // Function keys.
        0xFFBE..=0xFFC9 => key(0x70 + (keysym - 0xFFBE), false), // F1..F12
        // Keypad.
        0xFFB0..=0xFFB9 => key(0x60 + (keysym - 0xFFB0), false), // KP_0..KP_9
        0xFF8D => key(0x0D, true),                               // KP_Enter
        0xFFAA => key(0x6A, false),                              // KP_Multiply
        0xFFAB => key(0x6B, false),                              // KP_Add
        0xFFAC => key(0x6C, false),                              // KP_Separator
        0xFFAD => key(0x6D, false),                              // KP_Subtract
        0xFFAE => key(0x6E, false),                              // KP_Decimal
        0xFFAF => key(0x6F, true),                               // KP_Divide
        // US-layout ASCII: emit the base key; Shift is the viewer's job.
        _ => ascii_to_key(keysym).map(|(code, extended)| Key { code, extended }),
    }
}

/// Deterministic US-layout ASCII mapping (no Shift synthesis).
fn ascii_to_key(keysym: u32) -> Option<(u16, bool)> {
    let code = match keysym {
        0x30..=0x39 => keysym,        // 0-9 (also the base for !@#...)
        0x41..=0x5A => keysym,        // A-Z
        0x61..=0x7A => keysym - 0x20, // a-z
        // Shifted symbols: only the shifted keysym is listed here; the
        // unshifted digit is already handled by the 0x30..=0x39 arm.
        0x21 => 0x31,        // ! → 1
        0x40 => 0x32,        // @ → 2
        0x23 => 0x33,        // # → 3
        0x24 => 0x34,        // $ → 4
        0x25 => 0x35,        // % → 5
        0x5E => 0x36,        // ^ → 6
        0x26 => 0x37,        // & → 7
        0x2A => 0x38,        // * → 8
        0x28 => 0x39,        // ( → 9
        0x29 => 0x30,        // ) → 0
        0x2D | 0x5F => 0xBD, // - _
        0x3D | 0x2B => 0xBB, // = +
        0x5B | 0x7B => 0xDB, // [ {
        0x5D | 0x7D => 0xDD, // ] }
        0x5C | 0x7C => 0xDC, // \ |
        0x3B | 0x3A => 0xBA, // ; :
        0x27 | 0x22 => 0xDE, // ' "
        0x60 | 0x7E => 0xC0, // ` ~
        0x2C | 0x3C => 0xBC, // , <
        0x2E | 0x3E => 0xBE, // . >
        0x2F | 0x3F => 0xBF, // / ?
        _ => return None,
    };
    Some((code as u16, false))
}

/// Unicode codepoint carried by an X11 keysym, if any: the `0x01000000 | cp`
/// convention or Latin-1. NUL is rejected (no meaningful key event).
pub fn keysym_to_unicode(keysym: u32) -> Option<u32> {
    let cp = match keysym {
        0x0100_0000..=0x0110_FFFF => keysym - 0x0100_0000,
        0x20..=0x7E | 0xA0..=0xFF => keysym,
        _ => return None,
    };
    (cp != 0 && char::from_u32(cp).is_some()).then_some(cp)
}

/// Map a coordinate in `[0, extent)` onto the 0..65535 absolute range
/// `SendInput` expects, clamping out-of-range input instead of wrapping.
pub fn normalize(value: i32, extent: i32) -> u16 {
    if extent <= 1 {
        return 0;
    }
    let clamped = value.clamp(0, extent - 1) as i64;
    ((clamped * 65535) / (extent as i64 - 1)) as u16
}

/// Number of pixels one wheel step moves.
pub const WHEEL_DELTA: i32 = 120;

/// Map guest-local coordinates through the selected monitor's desktop origin.
#[derive(Clone, Copy, Debug)]
pub struct PointerSpace {
    pub left: i32,
    pub top: i32,
    pub width: i32,
    pub height: i32,
    pub virtual_left: i32,
    pub virtual_top: i32,
    pub virtual_width: i32,
    pub virtual_height: i32,
}

impl PointerSpace {
    pub fn absolute(&self, x: i32, y: i32) -> (u16, u16) {
        let x = self
            .left
            .saturating_sub(self.virtual_left)
            .saturating_add(x.clamp(0, (self.width - 1).max(0)));
        let y = self
            .top
            .saturating_sub(self.virtual_top)
            .saturating_add(y.clamp(0, (self.height - 1).max(0)));
        (
            normalize(x, self.virtual_width),
            normalize(y, self.virtual_height),
        )
    }
}

#[cfg(not(target_os = "windows"))]
mod platform {
    use super::{Key, PointerSpace, SessionState, WHEEL_DELTA};

    pub fn pointer_space(_name: Option<&str>) -> Result<PointerSpace, String> {
        Err("input-backend-unavailable".into())
    }

    pub fn session_state() -> SessionState {
        SessionState::default()
    }

    pub fn key(_keysym: u32, _down: bool) -> Result<(), String> {
        Err("input-backend-unavailable".into())
    }

    pub fn pointer(
        _buttons: &mut u8,
        _space: PointerSpace,
        _x: i32,
        _y: i32,
        _mask: u8,
    ) -> Result<(), String> {
        Err("input-backend-unavailable".into())
    }

    pub fn wheel(_dx: i32, _dy: i32) -> Result<(), String> {
        Err("input-backend-unavailable".into())
    }

    pub fn release(_buttons: &mut u8) {}

    // Keep the constants referenced so the module stays warning-free as the
    // Windows path evolves.
    #[allow(dead_code)]
    fn _tie(_key: Key) -> i32 {
        WHEEL_DELTA
    }
}

#[cfg(target_os = "windows")]
mod platform {
    use super::{keysym_to_key, keysym_to_unicode, PointerSpace, SessionState, WHEEL_DELTA};
    use windows::core::PCWSTR;
    use windows::Win32::Graphics::Gdi::{EnumDisplaySettingsW, DEVMODEW, ENUM_CURRENT_SETTINGS};
    use windows::Win32::System::RemoteDesktop::{
        ProcessIdToSessionId, WTSGetActiveConsoleSessionId,
    };
    use windows::Win32::System::Threading::GetCurrentProcessId;
    use windows::Win32::UI::HiDpi::{
        SetThreadDpiAwarenessContext, DPI_AWARENESS_CONTEXT,
        DPI_AWARENESS_CONTEXT_PER_MONITOR_AWARE_V2,
    };
    use windows::Win32::UI::Input::KeyboardAndMouse::{
        SendInput, INPUT, INPUT_0, INPUT_KEYBOARD, INPUT_MOUSE, KEYBDINPUT, KEYBD_EVENT_FLAGS,
        KEYEVENTF_EXTENDEDKEY, KEYEVENTF_KEYUP, KEYEVENTF_UNICODE, MOUSEEVENTF_ABSOLUTE,
        MOUSEEVENTF_HWHEEL, MOUSEEVENTF_LEFTDOWN, MOUSEEVENTF_LEFTUP, MOUSEEVENTF_MIDDLEDOWN,
        MOUSEEVENTF_MIDDLEUP, MOUSEEVENTF_MOVE, MOUSEEVENTF_RIGHTDOWN, MOUSEEVENTF_RIGHTUP,
        MOUSEEVENTF_VIRTUALDESK, MOUSEEVENTF_WHEEL, MOUSEINPUT, MOUSE_EVENT_FLAGS, VIRTUAL_KEY,
    };
    use windows::Win32::UI::WindowsAndMessaging::{
        GetSystemMetrics, SM_CXSCREEN, SM_CXVIRTUALSCREEN, SM_CYSCREEN, SM_CYVIRTUALSCREEN,
        SM_XVIRTUALSCREEN, SM_YVIRTUALSCREEN,
    };

    pub fn session_state() -> SessionState {
        let current = current_session();
        let console = unsafe { WTSGetActiveConsoleSessionId() };
        SessionState {
            current,
            active_console: (console != u32::MAX).then_some(console),
        }
    }

    fn current_session() -> Option<u32> {
        let mut session = 0u32;
        let pid = unsafe { GetCurrentProcessId() };
        unsafe { ProcessIdToSessionId(pid, &mut session) }.ok()?;
        Some(session)
    }

    pub fn pointer_space(name: Option<&str>) -> Result<PointerSpace, String> {
        struct DpiGuard(DPI_AWARENESS_CONTEXT);
        impl Drop for DpiGuard {
            fn drop(&mut self) {
                unsafe { SetThreadDpiAwarenessContext(self.0) };
            }
        }
        // EnumDisplaySettings/DXGI report physical pixels. Read virtual-desktop
        // metrics in that same coordinate space even with mixed monitor DPI.
        let previous =
            unsafe { SetThreadDpiAwarenessContext(DPI_AWARENESS_CONTEXT_PER_MONITOR_AWARE_V2) };
        if previous.0 == 0 {
            return Err("input-dpi-context-unavailable".into());
        }
        let _dpi = DpiGuard(previous);
        let mut space = PointerSpace {
            left: 0,
            top: 0,
            width: unsafe { GetSystemMetrics(SM_CXSCREEN) },
            height: unsafe { GetSystemMetrics(SM_CYSCREEN) },
            virtual_left: unsafe { GetSystemMetrics(SM_XVIRTUALSCREEN) },
            virtual_top: unsafe { GetSystemMetrics(SM_YVIRTUALSCREEN) },
            virtual_width: unsafe { GetSystemMetrics(SM_CXVIRTUALSCREEN) },
            virtual_height: unsafe { GetSystemMetrics(SM_CYVIRTUALSCREEN) },
        };
        if let Some(name) = name {
            let name: Vec<u16> = name.encode_utf16().chain(std::iter::once(0)).collect();
            let mut mode = DEVMODEW {
                dmSize: std::mem::size_of::<DEVMODEW>() as u16,
                ..Default::default()
            };
            if !unsafe {
                EnumDisplaySettingsW(PCWSTR(name.as_ptr()), ENUM_CURRENT_SETTINGS, &mut mode)
            }
            .as_bool()
            {
                return Err("input-output-unavailable".into());
            }
            let position = unsafe { mode.Anonymous1.Anonymous2.dmPosition };
            space.left = position.x;
            space.top = position.y;
            space.width = mode.dmPelsWidth as i32;
            space.height = mode.dmPelsHeight as i32;
        }
        if space.width <= 0
            || space.height <= 0
            || space.virtual_width <= 0
            || space.virtual_height <= 0
        {
            return Err("input-no-screen-metrics".into());
        }
        Ok(space)
    }

    fn send(inputs: &[INPUT]) -> Result<(), String> {
        if inputs.is_empty() {
            return Ok(());
        }
        let sent = unsafe { SendInput(inputs, std::mem::size_of::<INPUT>() as i32) };
        if sent as usize == inputs.len() {
            Ok(())
        } else {
            Err(format!(
                "input-sendinput-incomplete: {sent}/{}",
                inputs.len()
            ))
        }
    }

    fn key_input(vk: u16, scan: u16, flags: KEYBD_EVENT_FLAGS) -> INPUT {
        INPUT {
            r#type: INPUT_KEYBOARD,
            Anonymous: INPUT_0 {
                ki: KEYBDINPUT {
                    wVk: VIRTUAL_KEY(vk),
                    wScan: scan,
                    dwFlags: flags,
                    time: 0,
                    dwExtraInfo: 0,
                },
            },
        }
    }

    fn mouse_input(dx: i32, dy: i32, data: u32, flags: MOUSE_EVENT_FLAGS) -> INPUT {
        INPUT {
            r#type: INPUT_MOUSE,
            Anonymous: INPUT_0 {
                mi: MOUSEINPUT {
                    dx,
                    dy,
                    mouseData: data,
                    dwFlags: flags,
                    time: 0,
                    dwExtraInfo: 0,
                },
            },
        }
    }

    pub fn key(keysym: u32, down: bool) -> Result<(), String> {
        if let Some(resolved) = keysym_to_key(keysym) {
            let mut flags = KEYBD_EVENT_FLAGS(0);
            if !down {
                flags |= KEYEVENTF_KEYUP;
            }
            if resolved.extended {
                flags |= KEYEVENTF_EXTENDEDKEY;
            }
            send(&[key_input(resolved.code, 0, flags)])
        } else if let Some(cp) = keysym_to_unicode(keysym) {
            let mut flags = KEYEVENTF_UNICODE;
            if !down {
                flags |= KEYEVENTF_KEYUP;
            }
            let scalar = char::from_u32(cp).ok_or("input-invalid-unicode")?;
            let mut units = [0u16; 2];
            let inputs: Vec<_> = scalar
                .encode_utf16(&mut units)
                .iter()
                .map(|&unit| key_input(0, unit, flags))
                .collect();
            send(&inputs)
        } else {
            Err(format!("input-unmapped-keysym: 0x{keysym:08x}"))
        }
    }

    pub fn pointer(
        buttons: &mut u8,
        space: PointerSpace,
        x: i32,
        y: i32,
        mask: u8,
    ) -> Result<(), String> {
        let (x, y) = space.absolute(x, y);
        let mut inputs = vec![mouse_input(
            x as i32,
            y as i32,
            0,
            MOUSEEVENTF_MOVE | MOUSEEVENTF_ABSOLUTE | MOUSEEVENTF_VIRTUALDESK,
        )];
        // RFB mask: bit 0 left, bit 1 middle, bit 2 right. Emit transitions
        // only, so holding a button does not re-press it every move.
        let transitions = [
            (0x01, MOUSEEVENTF_LEFTDOWN, MOUSEEVENTF_LEFTUP),
            (0x02, MOUSEEVENTF_MIDDLEDOWN, MOUSEEVENTF_MIDDLEUP),
            (0x04, MOUSEEVENTF_RIGHTDOWN, MOUSEEVENTF_RIGHTUP),
        ];
        for (bit, press, release) in transitions {
            if *buttons & bit == mask & bit {
                continue;
            }
            let flag = if mask & bit != 0 { press } else { release };
            inputs.push(mouse_input(0, 0, 0, flag));
        }
        let result = send(&inputs);
        *buttons = if result.is_ok() {
            mask
        } else {
            *buttons | mask
        };
        result
    }

    pub fn release(buttons: &mut u8) {
        if *buttons == 0 {
            return;
        }
        let releases = [
            (0x01, MOUSEEVENTF_LEFTUP),
            (0x02, MOUSEEVENTF_MIDDLEUP),
            (0x04, MOUSEEVENTF_RIGHTUP),
        ];
        let inputs: Vec<INPUT> = releases
            .into_iter()
            .filter(|(bit, _)| *buttons & bit != 0)
            .map(|(_, flag)| mouse_input(0, 0, 0, flag))
            .collect();
        *buttons = 0;
        let _ = send(&inputs);
    }

    pub fn wheel(dx: i32, dy: i32) -> Result<(), String> {
        let mut inputs = Vec::with_capacity(2);
        if dy != 0 {
            // Protocol: positive dy = down. Windows wheel is positive away
            // from the user (up). The DWORD carries the signed delta two's
            // complement, so a negative step is a large u32 by design.
            inputs.push(mouse_input(
                0,
                0,
                (-dy * WHEEL_DELTA) as u32,
                MOUSEEVENTF_WHEEL,
            ));
        }
        if dx != 0 {
            inputs.push(mouse_input(
                0,
                0,
                (dx * WHEEL_DELTA) as u32,
                MOUSEEVENTF_HWHEEL,
            ));
        }
        send(&inputs)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn named_and_ascii_keys_resolve() {
        assert_eq!(
            keysym_to_key(0xFF0D),
            Some(Key {
                code: 0x0D,
                extended: false
            })
        );
        assert_eq!(
            keysym_to_key(0xFF51),
            Some(Key {
                code: 0x25,
                extended: true
            })
        );
        assert_eq!(keysym_to_key(0x61), keysym_to_key(0x41)); // a == A virtual key
        assert_eq!(keysym_to_key(0x31).map(|k| k.code), Some(0x31));
        assert_eq!(keysym_to_key(0x21).map(|k| k.code), Some(0x31)); // ! is base 1
        assert_eq!(keysym_to_key(0x5F).map(|k| k.code), Some(0xBD)); // _ is -
        assert_eq!(keysym_to_key(0xFFBE).map(|k| k.code), Some(0x70)); // F1
        assert_eq!(keysym_to_key(0xFFC9).map(|k| k.code), Some(0x7B)); // F12
        assert!(keysym_to_key(0x1100_0000).is_none());
    }

    #[test]
    fn unicode_keysyms_map_and_reject_nul() {
        assert_eq!(keysym_to_unicode(0x0100_0021), Some(0x21));
        assert_eq!(keysym_to_unicode(0x0100_03BB), Some(0x3BB));
        assert_eq!(keysym_to_unicode(0x00E9), Some(0xE9));
        assert_eq!(keysym_to_unicode(0x0100_0000), None);
        assert_eq!(keysym_to_unicode(0xFF0D), None);
        assert_eq!(keysym_to_unicode(0x0101_F600), Some(0x1_F600));
        assert_eq!(keysym_to_unicode(0x0100_D800), None);
    }

    #[test]
    fn coordinates_normalize_and_clamp() {
        assert_eq!(normalize(0, 1920), 0);
        assert_eq!(normalize(1919, 1920), 65535);
        assert_eq!(normalize(-10, 1920), 0);
        assert_eq!(normalize(9999, 1920), 65535);
        assert_eq!(normalize(5, 0), 0);
        assert!(normalize(960, 1920) > 30000 && normalize(960, 1920) < 35000);
    }

    #[test]
    fn selected_monitor_coordinates_include_negative_virtual_origins() {
        let mut space = PointerSpace {
            left: -800,
            top: -200,
            width: 800,
            height: 600,
            virtual_left: -800,
            virtual_top: -200,
            virtual_width: 2080,
            virtual_height: 1000,
        };
        assert_eq!(space.absolute(0, 0), (0, 0));
        assert_eq!(space.absolute(-10, -10), (0, 0));
        // The primary screen starts inside the combined desktop, not at its
        // normalized origin. Its far edge is the combined desktop's far edge.
        space.left = 0;
        space.top = 0;
        space.width = 1280;
        space.height = 800;
        assert_eq!(space.absolute(0, 0), (25217, 13120));
        assert_eq!(space.absolute(1279, 799), (65535, 65535));
        assert_eq!(space.absolute(9999, 9999), (65535, 65535));
    }

    #[test]
    fn session_gate_requires_interactive_console() {
        assert!(SessionState {
            current: Some(1),
            active_console: Some(1)
        }
        .can_inject());
        assert!(!SessionState {
            current: Some(0),
            active_console: Some(0)
        }
        .can_inject());
        assert!(!SessionState {
            current: Some(0),
            active_console: Some(1)
        }
        .can_inject());
        assert!(!SessionState::default().can_inject());
    }
}
