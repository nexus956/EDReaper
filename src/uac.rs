//! UAC elevation check – no bypass (public bypasses are patched on modern Windows)
//!
//! On fully patched Windows 10/11, all public UAC bypasses (fodhelper, eventvwr, cmstp, sdclt, AppInfo RPC)
//! are mitigated. This module only checks elevation status.
//!
//! For automated elevation, you need a private/0day bypass or kernel exploit.
//! Standard practice: run the tool from an elevated shell manually.

use std::mem;

use windows::Win32::Foundation::{CloseHandle, HANDLE};
use windows::Win32::Security::{
    GetTokenInformation, TokenElevation, TOKEN_ELEVATION, TOKEN_QUERY,
};
use windows::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};

/// Returns `true` if the current process token is elevated (high-IL).
pub fn is_elevated() -> bool {
    unsafe {
        let mut token = HANDLE::default();
        if OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token).is_err() {
            return false;
        }
        let mut elev = TOKEN_ELEVATION { TokenIsElevated: 0 };
        let mut ret_len: u32 = 0;
        let ok = GetTokenInformation(
            token,
            TokenElevation,
            Some(&mut elev as *mut _ as *mut _),
            mem::size_of::<TOKEN_ELEVATION>() as u32,
            &mut ret_len,
        );
        let _ = CloseHandle(token);
        ok.is_ok() && elev.TokenIsElevated != 0
    }
}

/// Call at the very top of `main()`.
/// If not elevated, prints a clear message and exits.
pub fn ensure_elevated() {
    if is_elevated() {
        return;
    }
    eprintln!("[uac] Not running as Administrator.");
    eprintln!("[uac] Public UAC bypasses are patched on modern Windows 10/11.");
    eprintln!("[uac] Please run from an elevated shell (Right-click PowerShell → 'Run as Administrator').");
    eprintln!("[uac] Or re-run with: sudo nexus.exe ..."); // Windows 11 24H2+ sudo support
    std::process::exit(1);
}