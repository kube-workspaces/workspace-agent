//! Selected DXGI-output display modes. Changes are temporary (no registry
//! persistence), tested by Windows before applying and read back afterward.
//!
//! Default output selection prefers a virtual/indirect display driver: that
//! monitor exposes the configurable mode list, whereas the emulated basic VGA
//! is a fixed-mode output. Callers that need a specific monitor still pass
//! `--capture-output-name`.

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Size {
    pub width: u32,
    pub height: u32,
}

/// One attached output discovered across every DXGI adapter.
#[cfg(any(target_os = "windows", test))]
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct OutputCandidate {
    pub name: String,
    pub adapter_description: String,
    pub attached: bool,
    pub output_index: u32,
}

/// Whether an adapter description identifies a virtual/indirect display driver
/// (`\\.\DISPLAYn` whose mode list the host controls). The pinned MikeTheTech
/// Virtual Display Driver reports "Virtual Display Driver"; the emulated basic
/// VGA reports "Microsoft Basic Display Adapter" and is not matched.
#[cfg(any(target_os = "windows", test))]
pub(crate) fn is_virtual_display_adapter(description: &str) -> bool {
    let lowered = description.to_ascii_lowercase();
    lowered.contains("virtual display") || lowered.contains("virtualdisplay")
}

/// Pick the output to stream from an adapter-major candidate list.
///
/// - An explicit `name` selects the first attached output with that device
///   name (e.g. `\\.\DISPLAY2`), searching every adapter.
/// - With no name and the default index (`0`), prefer an attached output on a
///   virtual-display adapter, so premium streams the configurable-mode IDD
///   rather than a fixed-mode basic VGA that offers a single resolution.
/// - Otherwise keep the legacy index selection: the first attached output
///   exposing `output_index`.
#[cfg(any(target_os = "windows", test))]
pub(crate) fn select_output(
    candidates: &[OutputCandidate],
    output_index: u32,
    name: Option<&str>,
) -> Option<usize> {
    if let Some(wanted) = name {
        return candidates.iter().position(|candidate| {
            candidate.attached && candidate.name.eq_ignore_ascii_case(wanted)
        });
    }
    if output_index == 0 {
        if let Some(index) = candidates.iter().position(|candidate| {
            candidate.attached && is_virtual_display_adapter(&candidate.adapter_description)
        }) {
            return Some(index);
        }
    }
    candidates
        .iter()
        .position(|candidate| candidate.attached && candidate.output_index == output_index)
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

/// Shared selection for capture, modes and input. Explicit names search every
/// adapter; with no name the virtual-display output is preferred (see
/// [`select_output`]) and the legacy index selection remains the fallback.
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
    use windows::Win32::Graphics::Dxgi::DXGI_ADAPTER_DESC1;
    let mut candidates = Vec::new();
    let mut handles = Vec::new();
    for adapter_index in 0..32 {
        let adapter = match unsafe { factory.EnumAdapters1(adapter_index) } {
            Ok(adapter) => adapter,
            Err(_) => break,
        };
        let mut adapter_desc: DXGI_ADAPTER_DESC1 = unsafe { std::mem::zeroed() };
        let adapter_description = match unsafe { adapter.GetDesc1(&mut adapter_desc) } {
            Ok(()) => wide_to_string(&adapter_desc.Description),
            Err(_) => String::new(),
        };
        for index in 0..32 {
            let output = match unsafe { adapter.EnumOutputs(index) } {
                Ok(output) => output,
                Err(_) => break,
            };
            let mut desc = Default::default();
            unsafe { output.GetDesc(&mut desc) }
                .map_err(|e| crate::Error::Os(e.code().0 as u32))?;
            candidates.push(OutputCandidate {
                name: wide_to_string(&desc.DeviceName),
                adapter_description: adapter_description.clone(),
                attached: desc.AttachedToDesktop.as_bool(),
                output_index: index,
            });
            handles.push((adapter.clone(), output));
        }
    }
    match select_output(&candidates, output_index, name) {
        Some(index) => Ok(handles.swap_remove(index)),
        None => Err(crate::Error::Empty),
    }
}

#[cfg(target_os = "windows")]
fn wide_to_string(value: &[u16]) -> String {
    let length = value.iter().position(|c| *c == 0).unwrap_or(value.len());
    String::from_utf16_lossy(&value[..length])
}

#[cfg(test)]
mod tests {
    use super::*;

    fn candidate(name: &str, adapter: &str, attached: bool, index: u32) -> OutputCandidate {
        OutputCandidate {
            name: name.into(),
            adapter_description: adapter.into(),
            attached,
            output_index: index,
        }
    }

    const VGA: &str = "Microsoft Basic Display Adapter";
    const IDD: &str = "Virtual Display Driver";

    #[test]
    fn recognizes_virtual_display_adapters() {
        assert!(is_virtual_display_adapter(IDD));
        assert!(is_virtual_display_adapter("VirtualDisplayDriver"));
        assert!(!is_virtual_display_adapter(VGA));
        assert!(!is_virtual_display_adapter(""));
    }

    #[test]
    fn defaults_to_virtual_display_over_fixed_mode_vga() {
        // Basic VGA is adapter 0 (the historical default); the IDD is later.
        let candidates = [
            candidate(r"\\.\DISPLAY1", VGA, true, 0),
            candidate(r"\\.\DISPLAY2", IDD, true, 0),
        ];
        assert_eq!(select_output(&candidates, 0, None), Some(1));
    }

    #[test]
    fn falls_back_to_index_when_no_virtual_display() {
        let candidates = [
            candidate(r"\\.\DISPLAY1", VGA, true, 0),
            candidate(r"\\.\DISPLAY2", VGA, true, 1),
        ];
        assert_eq!(select_output(&candidates, 0, None), Some(0));
        assert_eq!(select_output(&candidates, 1, None), Some(1));
    }

    #[test]
    fn explicit_name_wins_and_searches_every_adapter() {
        let candidates = [
            candidate(r"\\.\DISPLAY1", VGA, true, 0),
            candidate(r"\\.\DISPLAY2", IDD, true, 0),
        ];
        assert_eq!(
            select_output(&candidates, 0, Some(r"\\.\DISPLAY1")),
            Some(0)
        );
        assert_eq!(
            select_output(&candidates, 0, Some(r"\\.\display2")),
            Some(1)
        );
        assert_eq!(select_output(&candidates, 0, Some(r"\\.\DISPLAY9")), None);
    }

    #[test]
    fn explicit_index_ignores_virtual_display_preference() {
        let candidates = [
            candidate(r"\\.\DISPLAY1", VGA, true, 0),
            candidate(r"\\.\DISPLAY2", IDD, true, 1),
        ];
        assert_eq!(select_output(&candidates, 1, None), Some(1));
    }

    #[test]
    fn unattached_outputs_are_never_selected() {
        let candidates = [
            candidate(r"\\.\DISPLAY1", VGA, false, 0),
            candidate(r"\\.\DISPLAY2", IDD, false, 0),
        ];
        assert_eq!(select_output(&candidates, 0, None), None);
        assert_eq!(select_output(&candidates, 0, Some(r"\\.\DISPLAY2")), None);
    }

    #[test]
    fn unattached_virtual_display_falls_back_to_attached_index() {
        let candidates = [
            candidate(r"\\.\DISPLAY1", VGA, true, 0),
            candidate(r"\\.\DISPLAY2", IDD, false, 0),
        ];
        assert_eq!(select_output(&candidates, 0, None), Some(0));
    }
}
