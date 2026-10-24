//! Bounded repair of the emulated QEMU VGA's known post-start failure. This is
//! machine supervision, never an operation available through the wire protocol.
//! Healthy, disabled, absent and unrelated graphics devices are left alone.

#[derive(Default)]
pub struct Recovery {
    attempts: u32,
    next_check: u64,
}

impl Recovery {
    pub fn due(&mut self, now: u64) -> bool {
        if now < self.next_check {
            return false;
        }
        self.next_check = now.saturating_add(15);
        true
    }

    fn allow_restart(&mut self, instance: &str, service: &str, problem: u32) -> bool {
        if self.attempts >= 3
            || !instance
                .to_ascii_uppercase()
                .starts_with(r"PCI\VEN_1234&DEV_1111&")
            || !service.eq_ignore_ascii_case("BasicDisplay")
            || problem != 43
        {
            return false;
        }
        self.attempts += 1;
        true
    }
}

#[cfg(windows)]
impl Recovery {
    /// Uses SetupAPI's restart operation, not disable/enable, driver removal,
    /// installation, a shell, or a reboot. At most three attempts per service run.
    pub fn check(&mut self) -> Result<(), String> {
        use windows::{
            core::{GUID, PCWSTR},
            Win32::{
                Devices::DeviceAndDriverInstallation::*,
                Foundation::{ERROR_NO_MORE_ITEMS, HWND},
            },
        };
        struct Devices(HDEVINFO);
        impl Drop for Devices {
            fn drop(&mut self) {
                unsafe {
                    let _ = SetupDiDestroyDeviceInfoList(self.0);
                }
            }
        }
        let class = GUID::from_u128(0x4d36e968_e325_11ce_bfc1_08002be10318);
        let devices = Devices(
            unsafe {
                SetupDiGetClassDevsW(Some(&class), PCWSTR::null(), HWND::default(), DIGCF_PRESENT)
            }
            .map_err(|error| format!("console display enumeration: {error}"))?,
        );
        for index in 0..32 {
            let mut device = SP_DEVINFO_DATA {
                cbSize: std::mem::size_of::<SP_DEVINFO_DATA>() as u32,
                ..Default::default()
            };
            if let Err(error) = unsafe { SetupDiEnumDeviceInfo(devices.0, index, &mut device) } {
                if error.code() == ERROR_NO_MORE_ITEMS.to_hresult() {
                    break;
                }
                return Err(format!("console display enumeration: {error}"));
            }
            let mut instance = [0u16; 512];
            unsafe { SetupDiGetDeviceInstanceIdW(devices.0, &device, Some(&mut instance), None) }
                .map_err(|error| format!("console display identity: {error}"))?;
            let instance = String::from_utf16_lossy(
                &instance[..instance
                    .iter()
                    .position(|c| *c == 0)
                    .unwrap_or(instance.len())],
            );
            // Reject unrelated devices before reading their service or status.
            if !instance
                .to_ascii_uppercase()
                .starts_with(r"PCI\VEN_1234&DEV_1111&")
            {
                continue;
            }
            let mut bytes = [0u8; 256];
            unsafe {
                SetupDiGetDeviceRegistryPropertyW(
                    devices.0,
                    &device,
                    SPDRP_SERVICE,
                    None,
                    Some(&mut bytes),
                    None,
                )
            }
            .map_err(|error| format!("console display service: {error}"))?;
            let service: Vec<u16> = bytes
                .chunks_exact(2)
                .map(|b| u16::from_le_bytes([b[0], b[1]]))
                .take_while(|c| *c != 0)
                .collect();
            let service = String::from_utf16_lossy(&service);
            let mut status = CM_DEVNODE_STATUS_FLAGS::default();
            let mut problem = CM_PROB::default();
            let result =
                unsafe { CM_Get_DevNode_Status(&mut status, &mut problem, device.DevInst, 0) };
            if result != CR_SUCCESS {
                return Err(format!("console display status: {}", result.0));
            }
            if status.0 & DN_HAS_PROBLEM.0 == 0 {
                continue;
            }
            if !self.allow_restart(&instance, &service, problem.0) {
                if service.eq_ignore_ascii_case("BasicDisplay")
                    && problem.0 == 43
                    && self.attempts >= 3
                {
                    return Err(
                        "console VGA restart budget exhausted; post-start failure persists".into(),
                    );
                }
                continue;
            }
            eprintln!(
                "console VGA post-start failure; bounded restart attempt {} of 3",
                self.attempts
            );
            let params = SP_PROPCHANGE_PARAMS {
                ClassInstallHeader: SP_CLASSINSTALL_HEADER {
                    cbSize: std::mem::size_of::<SP_CLASSINSTALL_HEADER>() as u32,
                    InstallFunction: DIF_PROPERTYCHANGE,
                },
                StateChange: DICS_PROPCHANGE,
                Scope: DICS_FLAG_GLOBAL,
                HwProfile: 0,
            };
            unsafe {
                SetupDiSetClassInstallParamsW(
                    devices.0,
                    Some(&device),
                    Some(&params.ClassInstallHeader),
                    std::mem::size_of_val(&params) as u32,
                )
                .and_then(|()| {
                    SetupDiCallClassInstaller(DIF_PROPERTYCHANGE, devices.0, Some(&device))
                })
            }
            .map_err(|error| format!("console VGA restart failed: {error}"))?;
            // Readback is performed at the next check; an accepted restart is
            // not reported as proof of a working display.
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    const VGA: &str = r"PCI\VEN_1234&DEV_1111&SUBSYS_11001AF4\3&1&0&08";

    #[test]
    fn only_the_known_post_start_failure_can_restart() {
        let mut recovery = Recovery::default();
        for (instance, service, problem) in [
            (VGA, "BasicDisplay", 0),
            (VGA, "BasicDisplay", 22), // administratively disabled
            (VGA, "OtherDriver", 43),
            (r"ROOT\MTTVDD\0000", "BasicDisplay", 43),
            (r"PCI\VEN_8086&DEV_7DD1", "BasicDisplay", 43),
            (r"PCI\VEN_1234&DEV_11110&OTHER", "BasicDisplay", 43),
        ] {
            assert!(!recovery.allow_restart(instance, service, problem));
        }
        assert!(recovery.allow_restart(VGA, "basicdisplay", 43));
        assert!(recovery.allow_restart(VGA, "BasicDisplay", 43));
        assert!(recovery.allow_restart(VGA, "BasicDisplay", 43));
        assert!(!recovery.allow_restart(VGA, "BasicDisplay", 43));
        // Healthy observations cannot reset a flapping device's budget.
        assert!(!recovery.allow_restart(VGA, "BasicDisplay", 0));
        assert!(!recovery.allow_restart(VGA, "BasicDisplay", 43));
    }

    #[test]
    fn checks_are_paced_including_at_startup() {
        let mut recovery = Recovery::default();
        assert!(recovery.due(0));
        assert!(!recovery.due(1));
        assert!(!recovery.due(14));
        assert!(recovery.due(15));
    }
}
