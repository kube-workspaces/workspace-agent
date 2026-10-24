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
    /// GDI display-device description for this output name. An IDD backed by
    /// a hardware render adapter reports the GPU's name through DXGI instead.
    pub display_description: String,
    /// DXGI software-adapter flag, used by software-backed IDD topologies.
    /// A hardware-backed IDD need not set this flag.
    pub software: bool,
    pub attached: bool,
    pub output_index: u32,
}

/// Whether an adapter description identifies a virtual/indirect display driver
/// (`\\.\DISPLAYn` whose mode list the host controls). Some builds report a
/// vendor name ("Virtual Display Driver"); the guest's IDD instead enumerates
/// as the generic `Microsoft Basic Render Driver`, so [`is_virtual_display`]
/// also accepts the software-adapter flag below.
#[cfg(any(target_os = "windows", test))]
pub(crate) fn is_virtual_display_adapter(description: &str) -> bool {
    let lowered = description.to_ascii_lowercase();
    lowered.contains("virtual display") || lowered.contains("virtualdisplay")
}

/// Recognize the display independently of its rendering adapter. An IDD can
/// use either WARP or a hardware GPU; GDI retains the display driver's name
/// even when DXGI reports the hardware GPU and clears the software flag.
#[cfg(any(target_os = "windows", test))]
pub(crate) fn is_virtual_display(candidate: &OutputCandidate) -> bool {
    candidate.software
        || is_virtual_display_adapter(&candidate.adapter_description)
        || is_virtual_display_adapter(&candidate.display_description)
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
        if let Some(index) = candidates
            .iter()
            .position(|candidate| candidate.attached && is_virtual_display(candidate))
        {
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

/// Make a virtual output the only active display.
///
/// Default selection streams a virtual display, but Windows can leave the
/// emulated console VGA active and primary beside it. Applications then reopen
/// saved placements on the console monitor even when the virtual display is
/// primary. Disabling every other path and promoting the selected output is
/// the only reliable way to keep those windows on the captured display.
///
/// This is a temporary topology change, not written to the display database.
/// Callers must use [`VirtualDisplaySession`] to restore paths on exit. Returns
/// `false` when the selected output is not virtual or is already alone.
pub fn isolate_virtual(name: &str) -> Result<bool, String> {
    platform::isolate_virtual(name)
}

/// A viewer-scoped topology change. Helpers never construct this guard. Restore
/// the original active paths before accepting another connection or exiting.
pub use platform::VirtualDisplaySession;

/// Recover a console path left detached by an interrupted worker. Only used by
/// the managed worker, before choosing its capture output; never by diagnostics.
pub fn recover_console_topology() -> Result<bool, String> {
    platform::recover_console_topology()
}

#[cfg(target_os = "linux")]
mod platform {
    use super::Size;
    use crate::linux;
    use serde_json::json;
    pub fn selected_name(index: u32, name: Option<&str>) -> Result<String, String> {
        linux::selected(index, name).map(|o| o.name)
    }
    pub fn modes(index: u32, name: Option<&str>) -> Vec<crate::DisplayMode> {
        linux::selected(index, name)
            .map(|o| o.modes)
            .unwrap_or_default()
    }
    pub fn resize(index: u32, name: Option<&str>, requested: Size) -> Result<Size, String> {
        let selected = selected_name(index, name)?;
        linux::desktop_for(Some(&selected))?
            .lock()
            .map_err(|_| "linux-desktop-lock")?
            .call(
                json!({"op":"resize", "width":requested.width, "height":requested.height}),
                &[],
            )?;
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(2);
        loop {
            let actual = linux::selected(0, Some(&selected))?;
            if actual.width == requested.width && actual.height == requested.height {
                return Ok(requested);
            }
            if std::time::Instant::now() >= deadline {
                return Err("display-readback-timeout".into());
            }
            std::thread::sleep(std::time::Duration::from_millis(50));
        }
    }
    pub fn isolate_virtual(_name: &str) -> Result<bool, String> {
        Ok(false)
    }
    pub struct VirtualDisplaySession;
    impl Drop for VirtualDisplaySession {
        fn drop(&mut self) {}
    }
    impl VirtualDisplaySession {
        pub fn begin(_name: &str) -> Result<Self, String> {
            Ok(Self)
        }
    }
    pub fn recover_console_topology() -> Result<bool, String> {
        Ok(false)
    }
}

#[cfg(not(any(target_os = "windows", target_os = "linux")))]
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
    pub fn isolate_virtual(_name: &str) -> Result<bool, String> {
        Ok(false)
    }
    pub struct VirtualDisplaySession;
    impl Drop for VirtualDisplaySession {
        fn drop(&mut self) {}
    }
    impl VirtualDisplaySession {
        pub fn begin(_name: &str) -> Result<Self, String> {
            Ok(Self)
        }
    }
    pub fn recover_console_topology() -> Result<bool, String> {
        Ok(false)
    }
}

#[cfg(target_os = "windows")]
mod platform {
    use super::Size;
    use windows::core::PCWSTR;
    use windows::Win32::Devices::Display::{
        DisplayConfigGetDeviceInfo, GetDisplayConfigBufferSizes, QueryDisplayConfig,
        SetDisplayConfig, DISPLAYCONFIG_DEVICE_INFO_GET_SOURCE_NAME,
        DISPLAYCONFIG_DEVICE_INFO_HEADER, DISPLAYCONFIG_MODE_INFO, DISPLAYCONFIG_PATH_INFO,
        DISPLAYCONFIG_SOURCE_DEVICE_NAME, QDC_ONLY_ACTIVE_PATHS, SDC_ALLOW_CHANGES, SDC_APPLY,
        SDC_TOPOLOGY_EXTEND, SDC_USE_SUPPLIED_DISPLAY_CONFIG,
    };
    use windows::Win32::Foundation::{ERROR_INSUFFICIENT_BUFFER, HWND, WIN32_ERROR};
    use windows::Win32::Graphics::Dxgi::{CreateDXGIFactory1, IDXGIFactory1};
    use windows::Win32::Graphics::Gdi::{
        ChangeDisplaySettingsExW, EnumDisplayDevicesW, EnumDisplaySettingsW, CDS_TEST, CDS_TYPE,
        DEVMODEW, DISPLAYCONFIG_PATH_ACTIVE, DISPLAY_DEVICEW, DISPLAY_DEVICE_ATTACHED_TO_DESKTOP,
        DISPLAY_DEVICE_PRIMARY_DEVICE, DISP_CHANGE_SUCCESSFUL, DM_PELSHEIGHT, DM_PELSWIDTH,
        ENUM_CURRENT_SETTINGS,
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

    pub fn isolate_virtual(name: &str) -> Result<bool, String> {
        let wide: Vec<u16> = name.encode_utf16().chain(std::iter::once(0)).collect();
        if !super::is_virtual_display_adapter(&super::display_description(&wide)) {
            return Ok(false);
        }
        let (paths, modes) = query_active_topology()?;
        let selected = paths.iter().position(|path| {
            path.flags & DISPLAYCONFIG_PATH_ACTIVE != 0
                && source_device_name(path).is_some_and(|source| source.eq_ignore_ascii_case(name))
        });
        let selected = selected.ok_or_else(|| "display-topology-output-not-found".to_string())?;
        if paths.len() == 1 {
            return Ok(false);
        }
        let mut path = paths[selected];
        // A subset of paths needs a subset of modes with rebased indices.
        // In particular, a formerly secondary source must move to (0,0) to
        // become the sole primary output. Passing its old offset and unrelated
        // modes makes SetDisplayConfig reject the topology (ERROR_INVALID_PARAMETER).
        let source_index = unsafe { path.sourceInfo.Anonymous.modeInfoIdx };
        let target_index = unsafe { path.targetInfo.Anonymous.modeInfoIdx };
        let mut selected_modes = Vec::new();
        if let Some(mode) = modes.get(source_index as usize) {
            let mut source = *mode;
            source.Anonymous.sourceMode.position.x = 0;
            source.Anonymous.sourceMode.position.y = 0;
            path.sourceInfo.Anonymous.modeInfoIdx = selected_modes.len() as u32;
            selected_modes.push(source);
        }
        if let Some(mode) = modes.get(target_index as usize) {
            path.targetInfo.Anonymous.modeInfoIdx = selected_modes.len() as u32;
            selected_modes.push(*mode);
        }
        let only = [path];
        let flags = SDC_USE_SUPPLIED_DISPLAY_CONFIG | SDC_ALLOW_CHANGES | SDC_APPLY;
        let result = unsafe { SetDisplayConfig(Some(&only), Some(&selected_modes), flags) };
        if result != 0 {
            return Err(format!("display-topology-isolate-failed:{result}"));
        }
        if !primary_display_name().is_some_and(|primary| primary.eq_ignore_ascii_case(name)) {
            return Err("display-primary-not-selected".into());
        }
        Ok(true)
    }

    pub struct VirtualDisplaySession {
        original: Option<(Vec<DISPLAYCONFIG_PATH_INFO>, Vec<DISPLAYCONFIG_MODE_INFO>)>,
    }

    impl VirtualDisplaySession {
        pub fn begin(name: &str) -> Result<Self, String> {
            let original = query_active_topology()?;
            let mut guard = Self {
                original: Some(original),
            };
            match isolate_virtual(name) {
                Ok(true) => {
                    println!("display: isolated virtual output for admitted viewer");
                    Ok(guard)
                }
                Ok(false) => {
                    guard.original = None;
                    Ok(guard)
                }
                Err(error) => {
                    // SetDisplayConfig may have applied a topology even if the
                    // subsequent primary-output verification failed.
                    drop(guard);
                    Err(error)
                }
            }
        }
    }

    impl Drop for VirtualDisplaySession {
        fn drop(&mut self) {
            if let Some((paths, modes)) = self.original.take() {
                let result = unsafe {
                    SetDisplayConfig(
                        Some(&paths),
                        Some(&modes),
                        SDC_USE_SUPPLIED_DISPLAY_CONFIG | SDC_ALLOW_CHANGES | SDC_APPLY,
                    )
                };
                if result != 0 {
                    eprintln!(
                        "display topology restore failed:{result}; attempting console recovery"
                    );
                    if let Err(error) = recover_console_topology() {
                        eprintln!("display console recovery failed:{error}");
                    }
                } else {
                    println!("display: restored console topology after viewer");
                }
            }
        }
    }

    pub fn recover_console_topology() -> Result<bool, String> {
        // GDI retains inactive display devices. A missing BasicDisplay path
        // after a worker crash is different from an absent console device.
        let mut detached_console = false;
        for index in 0..32 {
            let mut device = DISPLAY_DEVICEW {
                cb: std::mem::size_of::<DISPLAY_DEVICEW>() as u32,
                ..Default::default()
            };
            if !unsafe { EnumDisplayDevicesW(PCWSTR::null(), index, &mut device, 0) }.as_bool() {
                break;
            }
            let description = String::from_utf16_lossy(&device.DeviceString);
            let id = String::from_utf16_lossy(&device.DeviceID).to_ascii_uppercase();
            if description.trim_end_matches('\0') == "Microsoft Basic Display Adapter"
                && id.starts_with(r"PCI\VEN_1234&DEV_1111&")
                && device.StateFlags & DISPLAY_DEVICE_ATTACHED_TO_DESKTOP == 0
            {
                detached_console = true;
            }
        }
        if !detached_console {
            return Ok(false);
        }
        // A fresh extend topology accounts for current devices after crash or
        // driver recovery. It is not saved to the Windows display database.
        let result = unsafe { SetDisplayConfig(None, None, SDC_TOPOLOGY_EXTEND | SDC_APPLY) };
        if result != 0 {
            return Err(format!("display-console-extend-failed:{result}"));
        }
        Ok(true)
    }

    fn query_active_topology(
    ) -> Result<(Vec<DISPLAYCONFIG_PATH_INFO>, Vec<DISPLAYCONFIG_MODE_INFO>), String> {
        for _ in 0..4 {
            let mut path_count = 0;
            let mut mode_count = 0;
            unsafe {
                GetDisplayConfigBufferSizes(QDC_ONLY_ACTIVE_PATHS, &mut path_count, &mut mode_count)
            }
            .map_err(|error| format!("display-topology-buffer-query-failed:{}", error.code().0))?;
            let mut paths = vec![DISPLAYCONFIG_PATH_INFO::default(); path_count as usize];
            let mut modes = vec![DISPLAYCONFIG_MODE_INFO::default(); mode_count as usize];
            match unsafe {
                QueryDisplayConfig(
                    QDC_ONLY_ACTIVE_PATHS,
                    &mut path_count,
                    paths.as_mut_ptr(),
                    &mut mode_count,
                    modes.as_mut_ptr(),
                    None,
                )
            } {
                Ok(()) => {
                    paths.truncate(path_count as usize);
                    modes.truncate(mode_count as usize);
                    return Ok((paths, modes));
                }
                Err(error)
                    if WIN32_ERROR::from_error(&error) == Some(ERROR_INSUFFICIENT_BUFFER) =>
                {
                    continue;
                }
                Err(error) => {
                    return Err(format!("display-topology-query-failed:{}", error.code().0));
                }
            }
        }
        Err("display-topology-query-unstable".into())
    }

    fn source_device_name(path: &DISPLAYCONFIG_PATH_INFO) -> Option<String> {
        let mut request = DISPLAYCONFIG_SOURCE_DEVICE_NAME {
            header: DISPLAYCONFIG_DEVICE_INFO_HEADER {
                r#type: DISPLAYCONFIG_DEVICE_INFO_GET_SOURCE_NAME,
                size: std::mem::size_of::<DISPLAYCONFIG_SOURCE_DEVICE_NAME>() as u32,
                adapterId: path.sourceInfo.adapterId,
                id: path.sourceInfo.id,
            },
            ..Default::default()
        };
        if unsafe { DisplayConfigGetDeviceInfo(&mut request.header) } != 0 {
            return None;
        }
        Some(super::wide_to_string(&request.viewGdiDeviceName))
    }

    fn primary_display_name() -> Option<String> {
        for index in 0..32 {
            let mut device = DISPLAY_DEVICEW {
                cb: std::mem::size_of::<DISPLAY_DEVICEW>() as u32,
                ..Default::default()
            };
            if !unsafe { EnumDisplayDevicesW(PCWSTR::null(), index, &mut device, 0) }.as_bool() {
                break;
            }
            if device.StateFlags & DISPLAY_DEVICE_PRIMARY_DEVICE != 0 {
                return Some(super::wide_to_string(&device.DeviceName));
            }
        }
        None
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
    use windows::Win32::Graphics::Dxgi::{DXGI_ADAPTER_DESC1, DXGI_ADAPTER_FLAG_SOFTWARE};
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
        let software = adapter_desc.Flags & (DXGI_ADAPTER_FLAG_SOFTWARE.0 as u32) != 0;
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
                display_description: display_description(&desc.DeviceName),
                software,
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
fn display_description(output_name: &[u16]) -> String {
    use windows::core::PCWSTR;
    use windows::Win32::Graphics::Gdi::{EnumDisplayDevicesW, DISPLAY_DEVICEW};

    let wanted = wide_to_string(output_name);
    for index in 0..32 {
        let mut device = DISPLAY_DEVICEW {
            cb: std::mem::size_of::<DISPLAY_DEVICEW>() as u32,
            ..Default::default()
        };
        if !unsafe { EnumDisplayDevicesW(PCWSTR::null(), index, &mut device, 0) }.as_bool() {
            break;
        }
        if wide_to_string(&device.DeviceName).eq_ignore_ascii_case(&wanted) {
            return wide_to_string(&device.DeviceString);
        }
    }
    String::new()
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
            display_description: String::new(),
            software: false,
            attached,
            output_index: index,
        }
    }

    fn software_candidate(
        name: &str,
        adapter: &str,
        attached: bool,
        index: u32,
    ) -> OutputCandidate {
        OutputCandidate {
            software: true,
            ..candidate(name, adapter, attached, index)
        }
    }

    const VGA: &str = "Microsoft Basic Display Adapter";
    const IDD: &str = "Virtual Display Driver";
    // The guest's IDD enumerates with the same generic name as the emulated
    // VGA; only the DXGI software-adapter flag distinguishes them.
    const BASIC_RENDER: &str = "Microsoft Basic Render Driver";

    #[test]
    fn recognizes_virtual_display_adapters() {
        assert!(is_virtual_display_adapter(IDD));
        assert!(is_virtual_display_adapter("VirtualDisplayDriver"));
        assert!(!is_virtual_display_adapter(VGA));
        assert!(!is_virtual_display_adapter(BASIC_RENDER));
        assert!(!is_virtual_display_adapter(""));
    }

    #[test]
    fn software_adapter_is_a_virtual_display() {
        assert!(is_virtual_display(&software_candidate(
            r"\\.\DISPLAY2",
            BASIC_RENDER,
            true,
            0
        )));
        assert!(!is_virtual_display(&candidate(
            r"\\.\DISPLAY1",
            BASIC_RENDER,
            true,
            0
        )));
    }

    #[test]
    fn defaults_to_software_idd_with_generic_description() {
        // Both outputs report "Microsoft Basic Render Driver"; the IDD's
        // adapter is software-flagged, the basic VGA is not.
        let candidates = [
            candidate(r"\\.\DISPLAY1", BASIC_RENDER, true, 0),
            software_candidate(r"\\.\DISPLAY2", BASIC_RENDER, true, 0),
        ];
        assert_eq!(select_output(&candidates, 0, None), Some(1));
    }

    #[test]
    fn hardware_backed_idd_uses_display_identity_not_render_adapter() {
        let candidates = [
            candidate(r"\\.\DISPLAY1", BASIC_RENDER, true, 0),
            OutputCandidate {
                display_description: IDD.into(),
                ..candidate(r"\\.\DISPLAY4", "Intel(R) Graphics", true, 0)
            },
        ];
        assert_eq!(select_output(&candidates, 0, None), Some(1));
        assert_eq!(
            select_output(&candidates, 0, Some(r"\\.\DISPLAY1")),
            Some(0)
        );
        let mut detached = candidates.clone();
        detached[1].attached = false;
        assert_eq!(select_output(&detached, 0, None), Some(0));
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
            software_candidate(r"\\.\DISPLAY2", BASIC_RENDER, true, 0),
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
            software_candidate(r"\\.\DISPLAY2", BASIC_RENDER, true, 1),
        ];
        assert_eq!(select_output(&candidates, 1, None), Some(1));
    }

    #[test]
    fn unattached_outputs_are_never_selected() {
        let candidates = [
            candidate(r"\\.\DISPLAY1", VGA, false, 0),
            software_candidate(r"\\.\DISPLAY2", BASIC_RENDER, false, 0),
        ];
        assert_eq!(select_output(&candidates, 0, None), None);
        assert_eq!(select_output(&candidates, 0, Some(r"\\.\DISPLAY2")), None);
    }

    #[test]
    fn unattached_virtual_display_falls_back_to_attached_index() {
        let candidates = [
            candidate(r"\\.\DISPLAY1", VGA, true, 0),
            software_candidate(r"\\.\DISPLAY2", BASIC_RENDER, false, 0),
        ];
        assert_eq!(select_output(&candidates, 0, None), Some(0));
    }

    #[cfg(not(target_os = "windows"))]
    #[test]
    fn isolation_is_a_noop_off_windows() {
        assert_eq!(isolate_virtual(r"\\.\DISPLAY1"), Ok(false));
    }
}
