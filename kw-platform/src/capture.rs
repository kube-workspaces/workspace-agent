//! Desktop Duplication capture (Windows): DXGI frames → NV12.
//!
//! One [`Duplicator`] per output: acquire → GPU→staging copy → map →
//! BT.601 NV12 with macroblock padding for the encoder. Session loss
//! (mode change, lock/unlock, UAC, device removal) surfaces as
//! [`Error::SessionLost`] so the host rebuilds instead of failing the
//! session; an expired wait is `Ok(None)`, not an error.
//!
//! Only Windows is implemented; other platforms report [`Error::Gated`].
//! Cursor shape, dirty-rect pacing and move-rect composition are later
//! milestones — this ships full frames honestly, never partial updates
//! mislabeled as complete.
/// One captured desktop frame: mod-16-padded NV12 plus the true desktop
/// dimensions (the viewer crops to actual size; the encoder needs the
/// padded size — see the alignment contract on [`kw_encode::Settings`]).
#[derive(Clone, Debug)]
pub struct CapturedFrame {
    pub width: u32,
    pub height: u32,
    pub padded_width: u32,
    pub padded_height: u32,
    pub nv12: Vec<u8>,
    /// Presents accumulated since the previous acquire (0 still means a
    /// fresh snapshot; mouse-only updates count).
    pub accumulated: u32,
}

/// Round up to the H.264 macroblock grid.
pub fn pad16(value: u32) -> u32 {
    value.next_multiple_of(16)
}

/// BGRA (byte order B,G,R,A per pixel, `stride` bytes per row) → NV12 with
/// black padding to the mod-16 grid. Integer BT.601; chroma is 2x2-box
/// averaged. Pure function: unit-tested on every platform.
pub fn bgra_to_nv12_padded(bgra: &[u8], width: u32, height: u32, stride: usize) -> Vec<u8> {
    let (w, h) = (width as usize, height as usize);
    let (pw, ph) = (pad16(width) as usize, pad16(height) as usize);
    let mut nv12 = vec![0u8; pw * ph * 3 / 2];
    // Broadcast video-range black first so padding is legal pixels.
    nv12[..pw * ph].fill(16);
    nv12[pw * ph..].fill(128);
    for y in 0..h {
        let src_row = y * stride;
        for x in 0..w {
            let i = src_row + x * 4;
            if i + 2 >= bgra.len() {
                break;
            }
            let (b, g, r) = (bgra[i] as i32, bgra[i + 1] as i32, bgra[i + 2] as i32);
            let y_val = ((66 * r + 129 * g + 25 * b + 128) >> 8) + 16;
            nv12[y * pw + x] = y_val.clamp(0, 255) as u8;
            // Chroma at even sites only, averaged over the 2x2 block below.
            if x % 2 == 0 && y % 2 == 0 {
                let (mut sum_u, mut sum_v, mut n) = (0i32, 0i32, 0i32);
                for dy in 0..2 {
                    for dx in 0..2 {
                        if x + dx >= w || y + dy >= h {
                            continue;
                        }
                        let j = src_row + dy * stride + (x + dx) * 4;
                        if j + 2 >= bgra.len() {
                            continue;
                        }
                        let (sb, sg, sr) = (bgra[j] as i32, bgra[j + 1] as i32, bgra[j + 2] as i32);
                        sum_u += -38 * sr - 74 * sg + 112 * sb;
                        sum_v += 112 * sr - 94 * sg - 18 * sb;
                        n += 1;
                    }
                }
                if n > 0 {
                    let u = (sum_u / (n * 256)) + 128;
                    let v = (sum_v / (n * 256)) + 128;
                    let uv_row = ph + (y / 2);
                    nv12[uv_row * pw + (x / 2) * 2] = u.clamp(0, 255) as u8;
                    nv12[uv_row * pw + (x / 2) * 2 + 1] = v.clamp(0, 255) as u8;
                }
            }
        }
    }
    nv12
}

#[cfg(target_os = "windows")]
pub use self::platform::{Duplicator, DXGI_TIMEOUT_DEFAULT_MS};

#[cfg(not(target_os = "windows"))]
pub use self::platform::{Duplicator, DXGI_TIMEOUT_DEFAULT_MS};

#[cfg(target_os = "windows")]
mod platform {
    use super::super::Error;
    use super::{bgra_to_nv12_padded, pad16, CapturedFrame};
    use windows::core::ComInterface as _;
    use windows::Win32::Foundation::HMODULE;
    use windows::Win32::Graphics::Direct3D::{D3D_DRIVER_TYPE_UNKNOWN, D3D_FEATURE_LEVEL_11_0};
    use windows::Win32::Graphics::Direct3D11::{
        D3D11CreateDevice, ID3D11Device, ID3D11DeviceContext, ID3D11Texture2D,
        D3D11_CPU_ACCESS_READ, D3D11_CREATE_DEVICE_BGRA_SUPPORT, D3D11_SDK_VERSION,
        D3D11_TEXTURE2D_DESC, D3D11_USAGE_STAGING,
    };
    use windows::Win32::Graphics::Dxgi::Common::{DXGI_FORMAT_B8G8R8A8_UNORM, DXGI_SAMPLE_DESC};
    use windows::Win32::Graphics::Dxgi::{
        CreateDXGIFactory1, IDXGIAdapter, IDXGIAdapter1, IDXGIOutput, IDXGIOutput1,
        IDXGIOutputDuplication, IDXGIResource, IDXGISurface, DXGI_ERROR_ACCESS_LOST,
        DXGI_ERROR_WAIT_TIMEOUT, DXGI_MAPPED_RECT, DXGI_MAP_READ, DXGI_OUTDUPL_FRAME_INFO,
        DXGI_OUTPUT_DESC,
    };
    use windows::Win32::System::Com::{CoInitializeEx, CoUninitialize, COINIT_MULTITHREADED};

    /// Default acquire wait: returns regularly so session loss and shutdown
    /// are noticed promptly even on a static screen.
    pub const DXGI_TIMEOUT_DEFAULT_MS: u32 = 100;

    fn os(error: windows::core::Error) -> Error {
        Error::Os(error.code().0 as u32)
    }

    /// One duplicated desktop output. Owns D3D objects on the constructing
    /// thread; COM is MTA-initialized per instance like the encoder.
    pub struct Duplicator {
        _device: ID3D11Device,
        context: ID3D11DeviceContext,
        duplication: IDXGIOutputDuplication,
        staging: ID3D11Texture2D,
        width: u32,
        height: u32,
        padded_width: u32,
        padded_height: u32,
    }

    impl Duplicator {
        /// Duplicate `output_index` (usually 0: the primary console output).
        /// No enumerated outputs (session 0, headless, RDP-disconnected)
        /// returns [`Error::Empty`] — never a fake frame.
        pub fn new(output_index: u32) -> Result<Self, Error> {
            let _ = unsafe { CoInitializeEx(None, COINIT_MULTITHREADED) };
            let built = unsafe { Self::build(output_index) };
            if built.is_err() {
                unsafe { CoUninitialize() };
            }
            built
        }

        unsafe fn build(output_index: u32) -> Result<Self, Error> {
            let factory: windows::Win32::Graphics::Dxgi::IDXGIFactory1 =
                CreateDXGIFactory1().map_err(os)?;
            let mut chosen: Option<(IDXGIAdapter1, IDXGIOutput)> = None;
            for adapter_index in 0..32u32 {
                let adapter: IDXGIAdapter1 = match factory.EnumAdapters1(adapter_index) {
                    Ok(adapter) => adapter,
                    Err(_) => break,
                };
                match adapter.EnumOutputs(output_index) {
                    Ok(output) => {
                        chosen = Some((adapter, output));
                        break;
                    }
                    Err(_) => continue,
                }
            }
            let (adapter, output) = chosen.ok_or(Error::Empty)?;
            let base: windows::Win32::Graphics::Dxgi::IDXGIAdapter = adapter.cast().map_err(os)?;
            let mut device: Option<ID3D11Device> = None;
            let mut context: Option<ID3D11DeviceContext> = None;
            let mut level = windows::Win32::Graphics::Direct3D::D3D_FEATURE_LEVEL(0);
            D3D11CreateDevice(
                Some(&base),
                D3D_DRIVER_TYPE_UNKNOWN,
                HMODULE::default(),
                D3D11_CREATE_DEVICE_BGRA_SUPPORT,
                Some(&[D3D_FEATURE_LEVEL_11_0]),
                D3D11_SDK_VERSION,
                Some(&mut device),
                Some(&mut level),
                Some(&mut context),
            )
            .map_err(os)?;
            let device = device.ok_or(Error::Empty)?;
            let context = context.ok_or(Error::Empty)?;
            let output1: IDXGIOutput1 = output.cast().map_err(os)?;
            let mut desc = std::mem::zeroed::<windows::Win32::Graphics::Dxgi::DXGI_OUTPUT_DESC>();
            IDXGIOutput::GetDesc(&output, &mut desc).map_err(os)?;
            let width =
                (desc.DesktopCoordinates.right - desc.DesktopCoordinates.left).max(0) as u32;
            let height =
                (desc.DesktopCoordinates.bottom - desc.DesktopCoordinates.top).max(0) as u32;
            if width == 0 || height == 0 {
                return Err(Error::Empty);
            }
            let duplication = output1.DuplicateOutput(&device).map_err(os)?;
            let (padded_width, padded_height) = (pad16(width), pad16(height));
            let staging_desc = D3D11_TEXTURE2D_DESC {
                Width: padded_width,
                Height: padded_height,
                MipLevels: 1,
                ArraySize: 1,
                Format: DXGI_FORMAT_B8G8R8A8_UNORM,
                SampleDesc: DXGI_SAMPLE_DESC {
                    Count: 1,
                    Quality: 0,
                },
                Usage: D3D11_USAGE_STAGING,
                BindFlags: 0,
                CPUAccessFlags: D3D11_CPU_ACCESS_READ.0 as u32,
                MiscFlags: 0,
            };
            let mut staging: Option<ID3D11Texture2D> = None;
            device
                .CreateTexture2D(&staging_desc, None, Some(&mut staging))
                .map_err(os)?;
            let staging = staging.ok_or(Error::Empty)?;
            Ok(Self {
                _device: device,
                context,
                duplication,
                staging,
                width,
                height,
                padded_width,
                padded_height,
            })
        }

        pub fn size(&self) -> (u32, u32) {
            (self.width, self.height)
        }

        pub fn padded_size(&self) -> (u32, u32) {
            (self.padded_width, self.padded_height)
        }

        /// Acquire one present. `Ok(None)` on wait timeout (static screen);
        /// [`Error::SessionLost`] when Windows revokes the duplication
        /// (caller rebuilds); [`Error::Os`] for genuine failures.
        pub fn capture(&mut self, timeout_ms: u32) -> Result<Option<CapturedFrame>, Error> {
            unsafe { self.capture_inner(timeout_ms) }
        }

        unsafe fn capture_inner(
            &mut self,
            timeout_ms: u32,
        ) -> Result<Option<CapturedFrame>, Error> {
            let mut info = std::mem::zeroed::<DXGI_OUTDUPL_FRAME_INFO>();
            let mut resource: Option<IDXGIResource> = None;
            match self
                .duplication
                .AcquireNextFrame(timeout_ms, &mut info, &mut resource)
            {
                Ok(()) => {}
                Err(error) if error.code() == DXGI_ERROR_WAIT_TIMEOUT => return Ok(None),
                Err(error) if error.code() == DXGI_ERROR_ACCESS_LOST => {
                    return Err(Error::SessionLost("duplication access lost"))
                }
                Err(error) => return Err(os(error)),
            }
            let resource = resource.ok_or(Error::Empty)?;
            let desktop: ID3D11Texture2D = resource.cast().map_err(os)?;
            self.context
                .CopySubresourceRegion(&self.staging, 0, 0, 0, 0, &desktop, 0, None);
            // Release promptly: the GPU copy is done; holding the frame
            // stalls the compositor.
            self.duplication.ReleaseFrame().map_err(os)?;
            let surface: IDXGISurface = self.staging.cast().map_err(os)?;
            let mut mapped = std::mem::zeroed::<DXGI_MAPPED_RECT>();
            surface.Map(&mut mapped, DXGI_MAP_READ).map_err(os)?;
            let pitch = mapped.Pitch.max(0) as usize;
            let rows =
                std::slice::from_raw_parts(mapped.pBits, pitch * self.height as usize).to_vec();
            surface.Unmap().map_err(os)?;
            let nv12 = bgra_to_nv12_padded(
                &rows,
                self.width,
                self.height,
                pitch.max(self.width as usize * 4),
            );
            Ok(Some(CapturedFrame {
                width: self.width,
                height: self.height,
                padded_width: self.padded_width,
                padded_height: self.padded_height,
                nv12,
                accumulated: info.AccumulatedFrames,
            }))
        }
    }

    impl Drop for Duplicator {
        fn drop(&mut self) {
            unsafe { CoUninitialize() };
        }
    }
}

#[cfg(not(target_os = "windows"))]
mod platform {
    use super::super::Error;
    use super::CapturedFrame;

    #[allow(dead_code)]
    pub const DXGI_TIMEOUT_DEFAULT_MS: u32 = 100;

    // Wired by the serve capture source (next increment); until then the
    // stub exists so shared code compiles on every platform.
    #[allow(dead_code)]
    pub struct Duplicator;

    #[allow(dead_code)]
    impl Duplicator {
        pub fn new(_output_index: u32) -> Result<Self, Error> {
            Err(Error::Gated("non-Windows capture backends (P5)"))
        }

        pub fn size(&self) -> (u32, u32) {
            (0, 0)
        }

        pub fn padded_size(&self) -> (u32, u32) {
            (0, 0)
        }

        pub fn capture(&mut self, _timeout_ms: u32) -> Result<Option<CapturedFrame>, Error> {
            Err(Error::Gated("non-Windows capture backends (P5)"))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 2x2 BGRA: red, green / blue, white. Hand-computed BT.601.
    fn tiny_bgra() -> (Vec<u8>, usize) {
        // Row 0: red (0,0,255), green (0,255,0). Row 1: blue (255,0,0), white.
        let pixels = [(0u8, 0u8, 255u8), (0, 255, 0), (255, 0, 0), (255, 255, 255)];
        let mut bgra = Vec::with_capacity(16);
        for (b, g, r) in pixels {
            bgra.extend_from_slice(&[b, g, r, 255]);
        }
        (bgra, 8)
    }

    #[test]
    fn luma_matches_bt601_spots() {
        let (bgra, stride) = tiny_bgra();
        let nv12 = bgra_to_nv12_padded(&bgra, 2, 2, stride);
        // Padded to 16x16: Y plane first.
        // red Y = (66*255+128)>>8+16 = 82; green = (129*255+128)>>8+16 = 144;
        // blue = (25*255+128)>>8+16 = 41; white = (220*255+128)>>8+16 = 235.
        assert_eq!(nv12[0], 82, "red luma");
        assert_eq!(nv12[1], 144, "green luma");
        assert_eq!(nv12[16], 41, "blue luma");
        assert_eq!(nv12[17], 235, "white luma");
    }

    #[test]
    fn padding_is_video_black_and_sized() {
        let (bgra, stride) = tiny_bgra();
        let nv12 = bgra_to_nv12_padded(&bgra, 2, 2, stride);
        assert_eq!(nv12.len(), 16 * 16 * 3 / 2, "mod-16 padded buffer");
        // Far corner (untouched by the 2x2 source) must stay black.
        assert_eq!(nv12[15 * 16 + 15], 16, "padded Y is black");
        assert_eq!(nv12[16 * 16], 128, "padded U is black");
    }

    #[test]
    fn odd_sizes_pad_without_overrun() {
        // 3x5 source with tight stride: exercises edge clamping + padding.
        let (w, h) = (3u32, 5u32);
        let mut bgra = vec![0u8; 3 * 4 * 5];
        for (i, px) in bgra.chunks_exact_mut(4).enumerate() {
            px[0] = (i & 0xff) as u8;
            px[1] = 128;
            px[2] = 64;
        }
        let nv12 = bgra_to_nv12_padded(&bgra, w, h, 12);
        assert_eq!(nv12.len(), 16 * 16 * 3 / 2);
        // First pixel converted, no panic on ragged chroma edges.
        assert_ne!(nv12[0], 16);
    }

    #[test]
    fn stride_gaps_are_skipped() {
        // 2-pixel rows with 4 bytes of trailing gap each.
        let mut bgra = vec![0u8; (8 + 4) * 2];
        bgra[0..8].copy_from_slice(&[0, 0, 255, 255, 0, 255, 0, 255]);
        bgra[12..20].copy_from_slice(&[255, 0, 0, 255, 255, 255, 255, 255]);
        let nv12 = bgra_to_nv12_padded(&bgra, 2, 2, 12);
        assert_eq!(nv12[0], 82, "red survives stride gap");
        assert_eq!(nv12[16], 41, "blue survives stride gap");
    }

    /// Headless CI runners have no console outputs: opening must fail
    /// honestly (Empty/Gated/SessionLost/Os) — never crash, never fake a
    /// frame. Runners WITH a virtual display may genuinely capture; both
    /// outcomes are accepted, fabrication is not.
    #[cfg(target_os = "windows")]
    #[test]
    fn duplicator_open_is_honest_headless() {
        match super::Duplicator::new(0) {
            Ok(mut duplicator) => {
                let (w, h) = duplicator.size();
                assert!(w > 0 && h > 0, "a claimed output must have dimensions");
                // One short acquire: a frame or a timeout, both honest.
                let _ = duplicator.capture(50);
            }
            Err(error) => {
                let message = format!("{error}");
                assert!(
                    matches!(
                        error,
                        super::super::Error::Empty
                            | super::super::Error::Gated(_)
                            | super::super::Error::SessionLost(_)
                            | super::super::Error::Os(_)
                    ),
                    "honest open failure: {message}"
                );
            }
        }
    }
}
