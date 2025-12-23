#[cfg(windows)]
use windows::Win32::System::Diagnostics::Debug::IsDebuggerPresent;
use winreg::RegKey;
use winreg::enums::HKEY_LOCAL_MACHINE;

pub fn is_vm() -> bool {
    let hklm = RegKey::predef(HKEY_LOCAL_MACHINE);
    if let Ok(key) = hklm.open_subkey("HARDWARE\\DESCRIPTION\\System") {
        if let Ok(bios) = key.get_value::<String, _>("SystemBiosVersion") {
            if bios.contains("VMware") || bios.contains("VirtualBox") || bios.contains("QEMU") {
                return true;
            }
        }
    }
    false
}

pub fn perform_security_checks() {
    #[cfg(windows)]
    {
        if unsafe { IsDebuggerPresent() }.as_bool() {
            std::process::exit(0);
        }
    }
    if is_vm() {
        std::process::exit(0);
    }
}