//! Selected DXGI-output display modes. Changes are temporary (no registry
//! persistence), tested by Windows before applying and read back afterward.

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Size {
    pub width: u32,
    pub height: u32,
}

pub fn resize(output_index: u32, requested: Size) -> Result<Size, String> {
    if !(320..=8192).contains(&requested.width) || !(200..=8192).contains(&requested.height) {
        return Err("display-invalid-size".into());
    }
    platform::resize(output_index, requested)
}

#[cfg(not(target_os = "windows"))]
mod platform {
    use super::Size;
    pub fn resize(_output_index: u32, _requested: Size) -> Result<Size, String> {
        Err("display-backend-unavailable".into())
    }
}

#[cfg(target_os = "windows")]
mod platform {
    use super::Size;
    use windows::core::PCWSTR;
    use windows::Win32::Foundation::HWND;
    use windows::Win32::Graphics::Dxgi::{CreateDXGIFactory1, IDXGIFactory1};
    use windows::Win32::Graphics::Gdi::{
        ChangeDisplaySettingsExW, EnumDisplaySettingsW, CDS_TEST, CDS_TYPE, DEVMODEW,
        DISP_CHANGE_SUCCESSFUL, DM_PELSHEIGHT, DM_PELSWIDTH, ENUM_CURRENT_SETTINGS,
    };

    pub fn resize(output_index: u32, requested: Size) -> Result<Size, String> {
        // Match Duplicator's selection: the requested output on the first
        // adapter exposing it. Never fall back to an unrelated monitor.
        let factory: IDXGIFactory1 =
            unsafe { CreateDXGIFactory1() }.map_err(|_| "display-enumeration-failed")?;
        let mut name = None;
        for index in 0..32 {
            let adapter = match unsafe { factory.EnumAdapters1(index) } {
                Ok(adapter) => adapter,
                Err(_) => break,
            };
            if let Ok(output) = unsafe { adapter.EnumOutputs(output_index) } {
                let mut desc = Default::default();
                unsafe { output.GetDesc(&mut desc) }.map_err(|_| "display-description-failed")?;
                name = Some(desc.DeviceName);
                break;
            }
        }
        let name = name.ok_or("display-output-unavailable")?;
        let device = PCWSTR(name.as_ptr());
        let mut mode = DEVMODEW {
            dmSize: std::mem::size_of::<DEVMODEW>() as u16,
            ..Default::default()
        };
        if !unsafe { EnumDisplaySettingsW(device, ENUM_CURRENT_SETTINGS, &mut mode) }.as_bool() {
            return Err("display-current-mode-unavailable".into());
        }
        mode.dmPelsWidth = requested.width;
        mode.dmPelsHeight = requested.height;
        mode.dmFields = DM_PELSWIDTH | DM_PELSHEIGHT;
        let test = unsafe {
            ChangeDisplaySettingsExW(device, Some(&mode), HWND::default(), CDS_TEST, None)
        };
        if test != DISP_CHANGE_SUCCESSFUL {
            return Err(format!("display-mode-unsupported:{}", test.0));
        }
        let result = unsafe {
            ChangeDisplaySettingsExW(device, Some(&mode), HWND::default(), CDS_TYPE(0), None)
        };
        if result != DISP_CHANGE_SUCCESSFUL {
            return Err(format!("display-mode-change-failed:{}", result.0));
        }
        if !unsafe { EnumDisplaySettingsW(device, ENUM_CURRENT_SETTINGS, &mut mode) }.as_bool() {
            return Err("display-mode-readback-failed".into());
        }
        Ok(Size {
            width: mode.dmPelsWidth,
            height: mode.dmPelsHeight,
        })
    }
}
