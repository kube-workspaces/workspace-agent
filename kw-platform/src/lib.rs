//! OS backends: capability inventory plus the Windows capture backend.
//! Capture, input, display-mode and audio-streaming backends beyond DXGI
//! duplication remain P0-gated and return [`Error::Gated`].
//!
//! [`inventory`] feeds the `hello` capability advertisement: real adapter,
//! output, audio-endpoint and encoder data from inbox OS APIs — no drivers
//! installed, no settings changed, no pixels saved.
//!
//! [`capture`] duplicates a desktop output into NV12 frames for the
//! encoder. Session loss is reported, never hidden.

pub mod capture;
pub mod clipboard;

use serde::{Deserialize, Serialize};

/// Backend unavailable reason. Never silently substitutes another source.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Error {
    /// Requested backend does not exist yet (P0-gated).
    Gated(&'static str),
    /// The OS call failed; carries the raw code, not a paraphrase.
    Os(u32),
    /// Expected data missing (e.g. no adapters enumerated at all).
    Empty,
    /// A held session was revoked (mode change, lock, UAC, device
    /// removal): rebuild the backend, do not end the session for it.
    SessionLost(&'static str),
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Error::Gated(what) => write!(f, "backend P0-gated: {what}"),
            Error::Os(code) => write!(f, "os call failed: 0x{code:08x}"),
            Error::Empty => write!(f, "no data enumerated"),
            Error::SessionLost(what) => write!(f, "session revoked, rebuild: {what}"),
        }
    }
}

impl std::error::Error for Error {}

/// One display mode from the OS mode list.
#[derive(Clone, Debug, PartialEq, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DisplayMode {
    pub width: u32,
    pub height: u32,
    pub refresh_hz: u32,
    pub bits_per_pixel: u32,
}

/// One attached output and its OS mode list.
#[derive(Clone, Debug, PartialEq, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct OutputInfo {
    pub name: String,
    pub attached: bool,
    pub width: u32,
    pub height: u32,
    pub modes: Vec<DisplayMode>,
}

/// One graphics adapter: identity, memory, D3D11 reachability, outputs.
#[derive(Clone, Debug, PartialEq, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AdapterInfo {
    pub description: String,
    pub vendor_id: u32,
    pub device_id: u32,
    pub dedicated_vram_bytes: u64,
    pub software: bool,
    pub d3d11_ok: bool,
    pub d3d11_level: u32,
    pub outputs: Vec<OutputInfo>,
}

/// Capability inventory for `hello`. Matches the spec's hello fields that
/// are measurable without enrollment or streaming.
#[derive(Clone, Debug, PartialEq, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Inventory {
    pub agent_version: String,
    pub platform: String,
    pub d3d11_warp_ok: bool,
    pub adapters: Vec<AdapterInfo>,
    /// Stable endpoint ids (`IMMDevice::GetId`). Friendly names arrive with
    /// the full audio backend; ids establish presence, not labels.
    pub audio_render_endpoints: Vec<String>,
    pub software_h264_encoders: Vec<String>,
}

/// Enumerate local capabilities. Read-only; changes nothing.
pub fn inventory() -> Result<Inventory, Error> {
    inner::inventory()
}

#[cfg(target_os = "windows")]
mod inner {
    use super::*;
    use windows::core::{ComInterface, HRESULT};
    use windows::Win32::Foundation::HMODULE;
    use windows::Win32::Graphics::Direct3D::{D3D_DRIVER_TYPE_UNKNOWN, D3D_DRIVER_TYPE_WARP};
    use windows::Win32::Graphics::Direct3D11::{
        D3D11CreateDevice, ID3D11Device, D3D11_CREATE_DEVICE_BGRA_SUPPORT, D3D11_SDK_VERSION,
    };
    use windows::Win32::Graphics::Dxgi::{
        CreateDXGIFactory1, IDXGIAdapter, IDXGIAdapter1, IDXGIFactory1, IDXGIOutput,
        DXGI_ADAPTER_DESC1, DXGI_ADAPTER_FLAG_SOFTWARE, DXGI_OUTPUT_DESC,
    };
    use windows::Win32::Graphics::Gdi::{
        EnumDisplaySettingsW, DEVMODEW, ENUM_DISPLAY_SETTINGS_MODE,
    };
    use windows::Win32::Media::Audio::{
        eRender, IMMDeviceEnumerator, MMDeviceEnumerator, DEVICE_STATE_ACTIVE,
    };
    use windows::Win32::Media::MediaFoundation::{
        IMFActivate, MFMediaType_Video, MFShutdown, MFStartup, MFTEnumEx,
        MFT_FRIENDLY_NAME_Attribute, MFVideoFormat_H264, MFSTARTUP_NOSOCKET,
        MFT_CATEGORY_VIDEO_ENCODER, MFT_ENUM_FLAG_ASYNCMFT, MFT_ENUM_FLAG_LOCALMFT,
        MFT_ENUM_FLAG_SORTANDFILTER, MFT_ENUM_FLAG_SYNCMFT, MF_VERSION,
    };
    use windows::Win32::System::Com::{
        CoCreateInstance, CoInitializeEx, CoTaskMemFree, CoUninitialize, CLSCTX_INPROC_SERVER,
        COINIT_MULTITHREADED,
    };

    fn wide_to_string(value: &[u16]) -> String {
        let end = value.iter().position(|&c| c == 0).unwrap_or(value.len());
        String::from_utf16_lossy(&value[..end])
    }

    fn hr(hr: HRESULT) -> u32 {
        hr.0 as u32
    }

    fn display_modes(device_name: &str) -> Vec<DisplayMode> {
        let wide: Vec<u16> = device_name
            .encode_utf16()
            .chain(std::iter::once(0))
            .collect();
        let mut modes = Vec::new();
        let mut mode = DEVMODEW {
            dmSize: std::mem::size_of::<DEVMODEW>() as u16,
            ..Default::default()
        };
        for index in 0..512u32 {
            let ok = unsafe {
                EnumDisplaySettingsW(
                    windows::core::PCWSTR(wide.as_ptr()),
                    ENUM_DISPLAY_SETTINGS_MODE(index),
                    &mut mode,
                )
            };
            if !ok.as_bool() {
                break;
            }
            modes.push(DisplayMode {
                width: mode.dmPelsWidth,
                height: mode.dmPelsHeight,
                refresh_hz: mode.dmDisplayFrequency,
                bits_per_pixel: mode.dmBitsPerPel,
            });
        }
        modes
    }

    fn adapters(factory: &IDXGIFactory1) -> Vec<AdapterInfo> {
        // Single unsafe region: every call below is a read-only COM query
        // against inbox OS objects. No writes, no raw-pointer escape.
        unsafe { adapters_inner(factory) }
    }

    unsafe fn adapters_inner(factory: &IDXGIFactory1) -> Vec<AdapterInfo> {
        let mut out = Vec::new();
        for index in 0..32u32 {
            let adapter: IDXGIAdapter1 = match factory.EnumAdapters1(index) {
                Ok(adapter) => adapter,
                Err(_) => break,
            };
            let mut desc: DXGI_ADAPTER_DESC1 = unsafe { std::mem::zeroed() };
            if adapter.GetDesc1(&mut desc).is_err() {
                continue;
            }
            let base: IDXGIAdapter = match adapter.cast() {
                Ok(base) => base,
                Err(_) => continue,
            };
            let mut device: Option<ID3D11Device> = None;
            let mut level = windows::Win32::Graphics::Direct3D::D3D_FEATURE_LEVEL(0);
            let created = unsafe {
                D3D11CreateDevice(
                    Some(&base),
                    D3D_DRIVER_TYPE_UNKNOWN,
                    HMODULE::default(),
                    D3D11_CREATE_DEVICE_BGRA_SUPPORT,
                    None,
                    D3D11_SDK_VERSION,
                    Some(&mut device),
                    Some(&mut level),
                    None,
                )
            };
            let mut outputs = Vec::new();
            for output_index in 0..32u32 {
                let output = match adapter.EnumOutputs(output_index) {
                    Ok(output) => output,
                    Err(_) => break,
                };
                let desc_out = {
                    let mut raw: DXGI_OUTPUT_DESC = unsafe { std::mem::zeroed() };
                    match IDXGIOutput::GetDesc(&output, &mut raw) {
                        Ok(()) => raw,
                        Err(_) => continue,
                    }
                };
                let name = wide_to_string(&desc_out.DeviceName);
                outputs.push(OutputInfo {
                    modes: display_modes(&name),
                    name,
                    attached: desc_out.AttachedToDesktop.as_bool(),
                    width: desc_out
                        .DesktopCoordinates
                        .right
                        .saturating_sub(desc_out.DesktopCoordinates.left)
                        as u32,
                    height: desc_out
                        .DesktopCoordinates
                        .bottom
                        .saturating_sub(desc_out.DesktopCoordinates.top)
                        as u32,
                });
            }
            out.push(AdapterInfo {
                description: wide_to_string(&desc.Description),
                vendor_id: desc.VendorId,
                device_id: desc.DeviceId,
                dedicated_vram_bytes: desc.DedicatedVideoMemory as u64,
                software: (desc.Flags & DXGI_ADAPTER_FLAG_SOFTWARE.0 as u32) != 0,
                d3d11_ok: created.is_ok(),
                d3d11_level: level.0 as u32,
                outputs,
            });
        }
        out
    }

    fn audio_endpoints() -> Vec<String> {
        let mut ids = Vec::new();
        let enumerator: IMMDeviceEnumerator =
            match unsafe { CoCreateInstance(&MMDeviceEnumerator, None, CLSCTX_INPROC_SERVER) } {
                Ok(enumerator) => enumerator,
                Err(_) => return ids,
            };
        let collection =
            match unsafe { enumerator.EnumAudioEndpoints(eRender, DEVICE_STATE_ACTIVE) } {
                Ok(collection) => collection,
                Err(_) => return ids,
            };
        let count = unsafe { collection.GetCount().unwrap_or(0) };
        for index in 0..count.min(64) {
            let device = match unsafe { collection.Item(index) } {
                Ok(device) => device,
                Err(_) => continue,
            };
            let id = match unsafe { device.GetId() } {
                Ok(id) => id,
                Err(_) => continue,
            };
            let text = unsafe { id.to_string().unwrap_or_default() };
            ids.push(text);
        }
        ids
    }

    fn software_h264() -> Vec<String> {
        let mut names = Vec::new();
        if unsafe { MFStartup(MF_VERSION, MFSTARTUP_NOSOCKET) }.is_err() {
            return names;
        }
        let output = windows::Win32::Media::MediaFoundation::MFT_REGISTER_TYPE_INFO {
            guidMajorType: MFMediaType_Video,
            guidSubtype: MFVideoFormat_H264,
        };
        let mut mdevs: *mut Option<IMFActivate> = std::ptr::null_mut();
        let mut count = 0u32;
        if unsafe {
            MFTEnumEx(
                MFT_CATEGORY_VIDEO_ENCODER,
                MFT_ENUM_FLAG_SYNCMFT
                    | MFT_ENUM_FLAG_ASYNCMFT
                    | MFT_ENUM_FLAG_LOCALMFT
                    | MFT_ENUM_FLAG_SORTANDFILTER,
                None,
                Some(&output),
                &mut mdevs,
                &mut count,
            )
        }
        .is_ok()
        {
            let activates: &[Option<IMFActivate>] =
                unsafe { std::slice::from_raw_parts(mdevs, count as usize) };
            for (index, activate) in activates.iter().flatten().enumerate().take(64) {
                let mut name = windows::core::PWSTR::null();
                let mut len = 0u32;
                let display = if unsafe {
                    activate.GetAllocatedString(&MFT_FRIENDLY_NAME_Attribute, &mut name, &mut len)
                }
                .is_ok()
                {
                    let text = unsafe { name.to_string().unwrap_or_default() };
                    unsafe { CoTaskMemFree(Some(name.as_ptr() as *const core::ffi::c_void)) };
                    format!("{index}:{text}")
                } else {
                    format!("{index}:unnamed")
                };
                names.push(display);
            }
            unsafe { CoTaskMemFree(Some(mdevs as *const core::ffi::c_void)) };
        }
        let _ = unsafe { MFShutdown() };
        names
    }

    pub fn inventory() -> Result<Inventory, Error> {
        let _ = unsafe { CoInitializeEx(None, COINIT_MULTITHREADED) };
        let factory: IDXGIFactory1 =
            unsafe { CreateDXGIFactory1().map_err(|e| Error::Os(hr(e.code())))? };
        let adapters = adapters(&factory);
        if adapters.is_empty() {
            unsafe { CoUninitialize() };
            return Err(Error::Empty);
        }
        let mut warp: Option<ID3D11Device> = None;
        let warp_ok = unsafe {
            D3D11CreateDevice(
                None,
                D3D_DRIVER_TYPE_WARP,
                HMODULE::default(),
                D3D11_CREATE_DEVICE_BGRA_SUPPORT,
                None,
                D3D11_SDK_VERSION,
                Some(&mut warp),
                None,
                None,
            )
        }
        .is_ok();
        let result = Inventory {
            agent_version: env!("CARGO_PKG_VERSION").into(),
            platform: "windows-amd64".into(),
            d3d11_warp_ok: warp_ok,
            adapters,
            audio_render_endpoints: audio_endpoints(),
            software_h264_encoders: software_h264(),
        };
        unsafe { CoUninitialize() };
        Ok(result)
    }
}

#[cfg(not(target_os = "windows"))]
mod inner {
    use super::*;

    pub fn inventory() -> Result<Inventory, Error> {
        // Linux adapters (X11/PipeWire/PulseAudio) are P5 work, after Windows
        // delivery. Report the gate instead of returning host guesses.
        Err(Error::Gated("linux capture/audio/display adapters (P5)"))
    }
}

#[cfg(test)]
mod tests {
    #[cfg(not(target_os = "windows"))]
    #[test]
    fn linux_inventory_reports_its_gate() {
        assert_eq!(
            super::inventory(),
            Err(super::Error::Gated(
                "linux capture/audio/display adapters (P5)"
            ))
        );
    }

    #[test]
    fn inventory_serializes_camel_case() {
        // The wire spec uses camelCase (sessionId, vendorId, ...). A rename
        // regression here would fork the protocol silently.
        let value = serde_json::to_value(super::Inventory {
            agent_version: "x".into(),
            platform: "windows-amd64".into(),
            d3d11_warp_ok: true,
            adapters: vec![super::AdapterInfo {
                description: "Intel".into(),
                vendor_id: 0x8086,
                device_id: 0x3ea5,
                dedicated_vram_bytes: 1,
                software: false,
                d3d11_ok: true,
                d3d11_level: 0xb000,
                outputs: vec![],
            }],
            audio_render_endpoints: vec![],
            software_h264_encoders: vec![],
        })
        .expect("serializes");
        assert_eq!(
            value["vendorId"],
            serde_json::Value::Null,
            "top level has no vendorId"
        );
        assert_eq!(value["adapters"][0]["vendorId"], 0x8086);
        assert_eq!(value["adapters"][0]["deviceId"], 0x3ea5);
        assert_eq!(value["adapters"][0]["d3d11Ok"], true);
        assert!(value["adapters"][0].get("vendor_id").is_none());
    }
}
