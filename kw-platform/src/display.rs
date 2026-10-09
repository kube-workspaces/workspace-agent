//! Selected DXGI-output display modes. Changes are temporary (no registry
//! persistence), tested by Windows before applying and read back afterward.

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Size {
    pub width: u32,
    pub height: u32,
}

pub fn resize(output_index: u32, requested: Size) -> Result<Size, String> {
    resize_selected(output_index, None, requested)
}

pub fn selected_name(output_index: u32, name: Option<&str>) -> Result<String, String> {
    platform::selected_name(output_index, name)
}

/// OS mode list for the selected output. Read-only; empty where the
/// backend is gated. Callers dedupe/sort; the raw enumeration repeats a
/// size per refresh rate and bit depth.
pub fn modes(output_index: u32, name: Option<&str>) -> Vec<crate::DisplayMode> {
    platform::modes(output_index, name)
}

pub fn resize_selected(
    output_index: u32,
    name: Option<&str>,
    requested: Size,
) -> Result<Size, String> {
    if !(320..=8192).contains(&requested.width) || !(200..=8192).contains(&requested.height) {
        return Err("display-invalid-size".into());
    }
    platform::resize(output_index, name, requested)
}

#[cfg(not(target_os = "windows"))]
mod platform {
    use super::Size;
    pub fn selected_name(_output_index: u32, _name: Option<&str>) -> Result<String, String> {
        Err("display-backend-unavailable".into())
    }
    pub fn modes(_output_index: u32, _name: Option<&str>) -> Vec<crate::DisplayMode> {
        Vec::new()
    }
    pub fn resize(
        _output_index: u32,
        _name: Option<&str>,
        _requested: Size,
    ) -> Result<Size, String> {
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

    pub fn selected_name(
        output_index: u32,
        requested_name: Option<&str>,
    ) -> Result<String, String> {
        let factory: IDXGIFactory1 =
            unsafe { CreateDXGIFactory1() }.map_err(|_| "display-enumeration-failed")?;
        let (_, output) = super::choose_output(&factory, output_index, requested_name)
            .map_err(|error| format!("display-output-unavailable:{error}"))?;
        let mut desc = Default::default();
        unsafe { output.GetDesc(&mut desc) }.map_err(|_| "display-description-failed")?;
        let length = desc
            .DeviceName
            .iter()
            .position(|c| *c == 0)
            .unwrap_or(desc.DeviceName.len());
        Ok(String::from_utf16_lossy(&desc.DeviceName[..length]))
    }

    pub fn modes(output_index: u32, requested_name: Option<&str>) -> Vec<crate::DisplayMode> {
        match selected_name(output_index, requested_name) {
            Ok(name) => crate::output_modes(&name),
            Err(_) => Vec::new(),
        }
    }

    pub fn resize(
        output_index: u32,
        requested_name: Option<&str>,
        requested: Size,
    ) -> Result<Size, String> {
        let name = selected_name(output_index, requested_name)?;
        let name: Vec<u16> = name.encode_utf16().chain(std::iter::once(0)).collect();
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

/// Shared selection for capture and modes. Explicit names search every adapter;
/// legacy index selection retains the first adapter exposing that index.
#[cfg(target_os = "windows")]
pub(crate) fn choose_output(
    factory: &windows::Win32::Graphics::Dxgi::IDXGIFactory1,
    output_index: u32,
    name: Option<&str>,
) -> Result<
    (
        windows::Win32::Graphics::Dxgi::IDXGIAdapter1,
        windows::Win32::Graphics::Dxgi::IDXGIOutput,
    ),
    crate::Error,
> {
    for adapter_index in 0..32 {
        let adapter = match unsafe { factory.EnumAdapters1(adapter_index) } {
            Ok(adapter) => adapter,
            Err(_) => break,
        };
        for index in 0..32 {
            if name.is_none() && index != output_index {
                continue;
            }
            let output = match unsafe { adapter.EnumOutputs(index) } {
                Ok(output) => output,
                Err(_) => break,
            };
            let mut desc = Default::default();
            unsafe { output.GetDesc(&mut desc) }
                .map_err(|e| crate::Error::Os(e.code().0 as u32))?;
            if !desc.AttachedToDesktop.as_bool() {
                continue;
            }
            let length = desc
                .DeviceName
                .iter()
                .position(|c| *c == 0)
                .unwrap_or(desc.DeviceName.len());
            let actual = String::from_utf16_lossy(&desc.DeviceName[..length]);
            if name.map_or(true, |wanted| wanted.eq_ignore_ascii_case(&actual)) {
                return Ok((adapter, output));
            }
        }
    }
    Err(crate::Error::Empty)
}
