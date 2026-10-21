// SPDX-License-Identifier: GPL-3.0-or-later
//! Thin adapter to the installed Sandboxie runtime. No driver code is replaced.
//!
//! ABI references: Sandboxie/core/dll/{sbieapi.h,sbiedll.h}, drv/{api_defs.h,
//! api_flags.h,session.c}, and apps/ini/update.c. MonitorGet2 is an IOCTL API,
//! not an exported function named SbieApi_MonitorGet2. Its stream is destructive
//! and shared by the Windows session; acquire it only when no monitor is active.

use serde::Serialize;
use std::collections::BTreeMap;

#[derive(Debug, Clone, Serialize)]
pub struct RuntimeStatus {
    pub available: bool,
    pub install_path: Option<String>,
    pub driver_version: Option<String>,
    pub service_running: bool,
    pub monitoring: bool,
    pub security_features_available: bool,
    pub force_rules_disabled: bool,
    pub error: Option<String>,
}

#[derive(Debug, Clone)]
pub struct CompiledPolicy {
    pub box_name: String,
    pub settings: BTreeMap<String, Vec<String>>,
    pub requires_specificity: bool,
}

#[derive(Debug, Clone, Serialize)]
pub struct MonitorRecord {
    pub timestamp_ms: u64,
    pub pid: u32,
    pub tid: u32,
    pub box_name: String,
    pub process_name: String,
    pub path: String,
    pub operation: String,
    pub result: String,
    pub raw_type: u32,
    pub raw_details: Vec<String>,
}

const FILETIME_EPOCH: u64 = 116_444_736_000_000_000;
const MANAGED_KEYS: &[&str] = &[
    "Enabled",
    "ConfigLevel",
    "FileTrace",
    "ClosedFilePath",
    "NormalFilePath",
    "ForceProcess",
    "ForceChildren",
    "UseRuleSpecificity",
];

fn valid_box(name: &str) -> Result<(), String> {
    if !name.starts_with("DiskGuard_")
        || name.len() > 32
        || name.len() <= 10
        || !name.bytes().all(|c| c.is_ascii_alphanumeric() || c == b'_')
    {
        return Err("Only DiskGuard_ sandbox names containing ASCII letters, digits and underscores (up to 32 characters) may be managed".into());
    }
    Ok(())
}

fn validate_policy(policy: &CompiledPolicy) -> Result<(), String> {
    valid_box(&policy.box_name)?;
    for (key, values) in &policy.settings {
        if !MANAGED_KEYS.contains(&key.as_str()) {
            return Err(format!("Unsupported Sandboxie setting: {key}"));
        }
        for value in values {
            if value.is_empty()
                || value.encode_utf16().count() > 1900
                || value.contains(['\0', '\r', '\n'])
            {
                return Err(format!("Invalid value for Sandboxie setting {key}"));
            }
        }
    }
    let specificity_enabled = policy
        .settings
        .get("UseRuleSpecificity")
        .is_some_and(|values| values.iter().any(|v| v.eq_ignore_ascii_case("y")));
    if specificity_enabled && !policy.requires_specificity {
        return Err("UseRuleSpecificity requires an explicit runtime capability check".into());
    }
    Ok(())
}

/// Rule-specificity allows inherited paths to outrank a broad closed rule.
/// Verify the effective rule collection before calling a profile a whitelist.
fn check_whitelist_effective(
    explicit_normal: &[String],
    effective_normal: &[String],
    other_allow: &BTreeMap<String, Vec<String>>,
) -> Result<(), String> {
    for (key, values) in other_allow {
        if !values.is_empty() {
            return Err(format!("Whitelist mode cannot safely coexist with effective {key} rules from this sandbox, GlobalSettings or templates. Remove those exceptions in a clean runtime configuration before applying whitelist mode"));
        }
    }
    let mut inherited = effective_normal.to_vec();
    for explicit in explicit_normal {
        let Some(index) = inherited.iter().position(|value| value == explicit) else {
            return Err("Cannot verify this sandbox's explicit NormalFilePath rules against its effective configuration".into());
        };
        inherited.remove(index);
    }
    if !inherited.is_empty() {
        return Err("Whitelist mode found inherited NormalFilePath exceptions in GlobalSettings or templates. Use a clean runtime configuration before applying whitelist mode".into());
    }
    Ok(())
}

fn check_isolation_effective(settings: &BTreeMap<String, Vec<String>>) -> Result<(), String> {
    for key in ["BreakoutProcess", "BreakoutFolder", "BreakoutDocument"] {
        if settings.get(key).is_some_and(|values| !values.is_empty()) {
            return Err(format!("Cannot apply protection while effective {key} rules permit leaving the sandbox. Remove the conflicting sandbox/global/template rules first; DiskGuard does not modify unrelated runtime configuration"));
        }
    }
    for key in ["NoSecurityIsolation", "DisableFileFilter"] {
        if let Some(values) = settings.get(key) {
            for value in values {
                if !value.trim().eq_ignore_ascii_case("n") {
                    return Err(format!("Cannot verify protection with effective {key}={value}. This setting must be absent or explicitly n; inspect the sandbox/global/template configuration"));
                }
            }
        }
    }
    Ok(())
}

fn check_intrinsic_whitelist_paths(paths: &[String]) -> Result<(), String> {
    // Kernel-applied TemplateDefaultPaths is independent of per-box template
    // inheritance. Only known pipe/console/network device namespaces are safe
    // exceptions for a disk allowlist; volume, UNC, spool macros and unknown
    // device paths can expose host files and must conservatively refuse it.
    const NON_DISK_DEVICES: &[&str] = &[
        r"\device\namedpipe",
        r"\device\mailslot",
        r"\device\afd",
        r"\device\nsi",
        r"\device\tcp",
        r"\device\tcp6",
        r"\device\udp",
        r"\device\udp6",
        r"\device\ip",
        r"\device\ip6",
        r"\device\rawip",
        r"\device\rawip6",
        r"\device\http",
        r"\device\ws2ifsl",
        r"\device\condrv",
    ];
    for value in paths {
        let path = value
            .split_once(',')
            .map_or(value.as_str(), |(_, p)| p)
            .trim()
            .trim_start_matches('|')
            .to_lowercase();
        if !NON_DISK_DEVICES
            .iter()
            .any(|prefix| path == *prefix || path.starts_with(&format!("{prefix}\\")))
        {
            return Err(format!("Whitelist mode cannot certify the runtime's intrinsic TemplateDefaultPaths exception {value}. It may allow host disk access outside the selected directories. Use a runtime template configuration without this disk exception; DiskGuard does not rewrite upstream templates"));
        }
    }
    Ok(())
}

/// Bounds-checked parser for the exact MonitorGet2 wire format. Lengths are
/// bytes, timestamps are FILETIME, and trailing tags must never become paths.
fn parse_monitor_buffer(buffer: &[u8]) -> Result<Vec<MonitorRecord>, String> {
    let mut offset = 0usize;
    let mut records = Vec::new();
    while offset + 4 <= buffer.len() {
        let size = u32::from_le_bytes(buffer[offset..offset + 4].try_into().unwrap()) as usize;
        offset += 4;
        if size == 0 {
            if offset != buffer.len() {
                return Err("Unexpected bytes after monitor stream terminator".into());
            }
            return Ok(records);
        }
        let end = offset
            .checked_add(size)
            .ok_or("Monitor record length overflow")?;
        if size < 20 || end > buffer.len() {
            return Err("Truncated Sandboxie monitor record".into());
        }
        let entry = &buffer[offset..end];
        let stamp = u64::from_le_bytes(entry[..8].try_into().unwrap());
        let kind = u32::from_le_bytes(entry[8..12].try_into().unwrap());
        let pid = u32::from_le_bytes(entry[12..16].try_into().unwrap());
        let tid = u32::from_le_bytes(entry[16..20].try_into().unwrap());
        let mut pos = 20;
        let mut details = Vec::new();
        while pos < entry.len() {
            if pos + 2 > entry.len() {
                return Err("Unaligned Sandboxie monitor string".into());
            }
            if u16::from_le_bytes([entry[pos], entry[pos + 1]]) == 0xffff {
                pos += 2;
                // Stack-trace tags are opaque, but validate all declared lengths.
                while pos < entry.len() {
                    if pos + 8 > entry.len() {
                        return Err("Truncated Sandboxie monitor tag".into());
                    }
                    let len =
                        u32::from_le_bytes(entry[pos + 4..pos + 8].try_into().unwrap()) as usize;
                    pos = pos
                        .checked_add(8 + len)
                        .ok_or("Monitor tag length overflow")?;
                    if pos > entry.len() {
                        return Err("Truncated Sandboxie monitor tag data".into());
                    }
                }
                break;
            }
            let mut text = Vec::new();
            loop {
                if pos + 2 > entry.len() {
                    return Err("Unterminated Sandboxie monitor string".into());
                }
                let unit = u16::from_le_bytes([entry[pos], entry[pos + 1]]);
                pos += 2;
                if unit == 0 {
                    break;
                }
                text.push(unit);
            }
            details.push(String::from_utf16_lossy(&text));
        }
        let (path, operation, result) = describe_record(kind, &details);
        records.push(MonitorRecord {
            timestamp_ms: stamp.saturating_sub(FILETIME_EPOCH) / 10_000,
            pid,
            tid,
            box_name: String::new(),
            process_name: String::new(),
            path,
            operation,
            result,
            raw_type: kind,
            raw_details: details,
        });
        offset = end;
    }
    Err("Sandboxie monitor stream is missing its terminator".into())
}

fn describe_record(kind: u32, details: &[String]) -> (String, String, String) {
    let first = details.first().map(String::as_str).unwrap_or("");
    let mut result = match kind & 0x000f_0000 {
        0x0002_0000 => "denied",
        0x0001_0000 => "allowed",
        _ => "unknown",
    }
    .to_owned();
    // The flags describe policy disposition; they are NOT bytes-read evidence.
    let (path, operation) = match kind & 0xff {
        0x0a => {
            let trace = details.get(1).map(String::as_str).unwrap_or("");
            if trace.starts_with("(FA)") {
                result = "allowed".into();
            } else if trace.starts_with("(FD)") && result != "denied" {
                // FD means a failing open access check; the status might be
                // object-not-found rather than an intentional policy denial.
                result = "unknown".into();
            }
            let op = if trace.starts_with("(FA)") || trace.starts_with("(FD)") {
                "file_open"
            } else {
                "file_policy_check"
            };
            (first.to_owned(), op)
        }
        0x01 => {
            let name = first.trim_start_matches("Nt");
            let op = match name {
                "CreateFile" | "OpenFile" => "file_open",
                "QueryDirectoryFile" | "QueryDirectoryFileEx" => "directory_enumeration",
                "ReadFile" => "read_request",
                "QueryFullAttributesFile" | "QueryInformationFile" => "file_metadata",
                _ => "syscall",
            };
            // Generic syscall traces do not supply a reliable handle-to-path
            // mapping. Preserve an absent path, even for a read request.
            let path = details
                .get(2)
                .filter(|p| p.starts_with('\\'))
                .cloned()
                .unwrap_or_default();
            if let Some(status) = details.get(1).and_then(|s| s.split("status = 0x").nth(1)) {
                let digits: String = status
                    .chars()
                    .take_while(|c| c.is_ascii_hexdigit())
                    .collect();
                if let Ok(code) = u32::from_str_radix(&digits, 16) {
                    result = if code == 0xc000_0022 {
                        "denied"
                    } else if (code as i32) < 0 {
                        "unknown"
                    } else {
                        "allowed"
                    }
                    .into();
                }
            }
            (path, op)
        }
        // FileTrace=y emits an entry and return separately. They are not
        // correlated here; do not manufacture a final access result.
        0x0f if first.starts_with("File_NtCreateFileImpl ") && !first.contains("status =") => {
            result = "unknown".into();
            let path = first
                .trim_start_matches("File_NtCreateFileImpl ")
                .split(" DesiredAccess=")
                .next()
                .unwrap_or("")
                .to_owned();
            (path, "file_open_request")
        }
        _ => (String::new(), "runtime_event"),
    };
    (path, operation.into(), result)
}

#[cfg(windows)]
mod platform {
    use super::*;
    use libloading::os::windows::Library;
    use std::os::windows::process::CommandExt;
    use std::{
        ffi::c_void,
        path::{Path, PathBuf},
        process::Command,
        ptr,
    };
    use windows_sys::Win32::Foundation::{
        CloseHandle, GetLastError, ERROR_NO_MORE_FILES, INVALID_HANDLE_VALUE,
    };
    use windows_sys::Win32::System::{
        Diagnostics::ToolHelp::{
            CreateToolhelp32Snapshot, Process32FirstW, Process32NextW, PROCESSENTRY32W,
            TH32CS_SNAPPROCESS,
        },
        LibraryLoader::{LOAD_LIBRARY_SEARCH_DLL_LOAD_DIR, LOAD_LIBRARY_SEARCH_SYSTEM32},
        Registry::{RegGetValueW, HKEY_LOCAL_MACHINE, RRF_RT_REG_EXPAND_SZ, RRF_RT_REG_SZ},
        Services::{
            CloseServiceHandle, OpenSCManagerW, OpenServiceW, QueryServiceStatus,
            SC_MANAGER_CONNECT, SERVICE_QUERY_STATUS, SERVICE_RUNNING, SERVICE_STATUS,
        },
        Threading::{OpenProcess, QueryFullProcessImageNameW, PROCESS_QUERY_LIMITED_INFORMATION},
    };

    type GetVersion = unsafe extern "system" fn(*mut u16) -> i32;
    type Ioctl = unsafe extern "system" fn(*mut u64) -> i32;
    type MonitorControl = unsafe extern "system" fn(*const u32, *mut u32) -> i32;
    type QueryProcess = unsafe extern "system" fn(
        *mut c_void,
        u32,
        *mut u16,
        *mut u16,
        *mut u16,
        *mut u32,
        *mut u64,
    ) -> i32;
    type EnumProcess = unsafe extern "system" fn(*const u16, u8, u32, *mut u32, *mut u32) -> i32;
    type QueryConf = unsafe extern "system" fn(*const u16, *const u16, u32, *mut u16, u32) -> i32;
    type UpdateConf =
        unsafe extern "system" fn(u16, *const u16, *const u16, *const u16, *const u16) -> u32;
    type ReloadConf = unsafe extern "system" fn(u32, u32) -> i32;
    type QueryDrvInfo = unsafe extern "system" fn(u32, *mut c_void, u32) -> i32;

    pub struct Runtime {
        _library: Library,
        install: PathBuf,
        get_version: GetVersion,
        ioctl: Ioctl,
        monitor_control: MonitorControl,
        query_process: QueryProcess,
        enum_process: EnumProcess,
        query_conf: QueryConf,
        update_conf: UpdateConf,
        reload_conf: ReloadConf,
        query_driver_info: QueryDrvInfo,
        disable_force: MonitorControl,
        owns_monitor: bool,
        monitor_requested: bool,
        buffer: Vec<u8>,
    }

    fn wide(text: &str) -> Vec<u16> {
        let mut encoded: Vec<u16> = text.encode_utf16().chain(Some(0)).collect();
        // EnumProcess's driver boundary probes a fixed BOXNAME_COUNT buffer.
        // Also satisfy QueryConf's documented WCHAR[66] contract.
        encoded.resize(encoded.len().max(66), 0);
        encoded
    }
    fn unwide(text: &[u16]) -> String {
        String::from_utf16_lossy(&text[..text.iter().position(|c| *c == 0).unwrap_or(text.len())])
    }

    fn normalized_executable(path: &Path) -> Result<String, String> {
        let absolute = path
            .canonicalize()
            .map_err(|e| format!("Cannot verify executable path {}: {e}", path.display()))?;
        let text = absolute.to_string_lossy().replace('/', "\\");
        let text = if let Some(unc) = text.strip_prefix(r"\\?\UNC\") {
            format!(r"\\{unc}")
        } else {
            text.strip_prefix(r"\\?\").unwrap_or(&text).to_owned()
        };
        Ok(text.to_lowercase())
    }
    fn nt_check(status: i32, action: &str) -> Result<(), String> {
        if status < 0 {
            Err(format!("{action}: NTSTATUS 0x{:08X}", status as u32))
        } else {
            Ok(())
        }
    }

    fn service_running() -> bool {
        unsafe {
            let manager = OpenSCManagerW(ptr::null(), ptr::null(), SC_MANAGER_CONNECT);
            if manager.is_null() {
                return false;
            }
            let service = OpenServiceW(manager, wide("SbieSvc").as_ptr(), SERVICE_QUERY_STATUS);
            let running = if service.is_null() {
                false
            } else {
                let mut status: SERVICE_STATUS = std::mem::zeroed();
                let running = QueryServiceStatus(service, &mut status) != 0
                    && status.dwCurrentState == SERVICE_RUNNING;
                CloseServiceHandle(service);
                running
            };
            CloseServiceHandle(manager);
            running
        }
    }

    fn installed_directory() -> Result<PathBuf, String> {
        let mut buffer = vec![0u16; 32_768];
        let mut size = (buffer.len() * 2) as u32;
        // HKLM service configuration is written by the administrator-installed
        // runtime. Never load a DLL discovered in PATH, cwd, HKCU or a user form.
        let status = unsafe {
            RegGetValueW(
                HKEY_LOCAL_MACHINE,
                wide(r"SYSTEM\CurrentControlSet\Services\SbieSvc").as_ptr(),
                wide("ImagePath").as_ptr(),
                RRF_RT_REG_SZ | RRF_RT_REG_EXPAND_SZ,
                ptr::null_mut(),
                buffer.as_mut_ptr().cast(),
                &mut size,
            )
        };
        if status != 0 {
            return Err(format!(
                "Sandboxie SbieSvc installation not found (registry error {status})"
            ));
        }
        let command = unwide(&buffer);
        let executable = if let Some(quoted) = command.strip_prefix('"') {
            quoted
                .split_once('"')
                .map(|v| v.0)
                .ok_or("Malformed SbieSvc ImagePath")?
        } else {
            let end = command
                .to_ascii_lowercase()
                .find("sbiesvc.exe")
                .ok_or("SbieSvc ImagePath does not refer to SbieSvc.exe")?
                + "sbiesvc.exe".len();
            &command[..end]
        };
        let path = Path::new(executable);
        if !path.is_absolute()
            || executable.starts_with(r"\\")
            || !path
                .file_name()
                .is_some_and(|n| n.to_string_lossy().eq_ignore_ascii_case("SbieSvc.exe"))
        {
            return Err("SbieSvc must be installed at an absolute local SbieSvc.exe path".into());
        }
        let parent = path
            .parent()
            .ok_or("SbieSvc directory missing")?
            .canonicalize()
            .map_err(|e| format!("Cannot resolve Sandboxie install directory: {e}"))?;
        for name in ["SbieSvc.exe", "SbieDll.dll", "Start.exe"] {
            let candidate = parent.join(name);
            let resolved = candidate
                .canonicalize()
                .map_err(|e| format!("Missing Sandboxie runtime file {name}: {e}"))?;
            if !resolved.is_file() || resolved.parent() != Some(parent.as_path()) {
                return Err(format!(
                    "Sandboxie runtime file {name} is outside its installation directory"
                ));
            }
        }
        Ok(parent)
    }

    impl Runtime {
        pub fn connect() -> Result<Self, String> {
            if !cfg!(target_pointer_width = "64") {
                return Err("DiskGuard requires the x64 Sandboxie runtime".into());
            }
            let install = installed_directory()?;
            unsafe {
                let library = Library::load_with_flags(
                    install.join("SbieDll.dll"),
                    LOAD_LIBRARY_SEARCH_DLL_LOAD_DIR | LOAD_LIBRARY_SEARCH_SYSTEM32,
                )
                .map_err(|e| format!("Cannot load installed Sandboxie API: {e}"))?;
                macro_rules! symbol {
                    ($name:literal, $kind:ty) => {
                        *library
                            .get::<$kind>(concat!($name, "\0").as_bytes())
                            .map_err(|e| format!("Sandboxie API {} unavailable: {e}", $name))?
                    };
                }
                let runtime = Self {
                    get_version: symbol!("SbieApi_GetVersion", GetVersion),
                    ioctl: symbol!("SbieApi_Ioctl", Ioctl),
                    monitor_control: symbol!("SbieApi_MonitorControl", MonitorControl),
                    query_process: symbol!("SbieApi_QueryProcessEx2", QueryProcess),
                    enum_process: symbol!("SbieApi_EnumProcessEx", EnumProcess),
                    query_conf: symbol!("SbieApi_QueryConf", QueryConf),
                    update_conf: symbol!("SbieDll_UpdateConf", UpdateConf),
                    reload_conf: symbol!("SbieApi_ReloadConf", ReloadConf),
                    query_driver_info: symbol!("SbieApi_QueryDrvInfo", QueryDrvInfo),
                    disable_force: symbol!("SbieApi_DisableForceProcess", MonitorControl),
                    _library: library,
                    install,
                    owns_monitor: false,
                    monitor_requested: false,
                    buffer: vec![0; 1_048_576],
                };
                let status = runtime.status();
                if !status.available {
                    return Err(status
                        .error
                        .unwrap_or_else(|| "Sandboxie runtime is unavailable".into()));
                }
                Ok(runtime)
            }
        }

        pub fn status(&self) -> RuntimeStatus {
            let mut version = [0u16; 16];
            let mut monitoring = 0;
            let mut force_disabled = 0;
            let mut features = 0u32;
            let service = service_running();
            let mut errors = Vec::new();
            unsafe {
                if let Err(e) = nt_check(
                    (self.get_version)(version.as_mut_ptr()),
                    "Query Sandboxie driver",
                ) {
                    errors.push(e);
                }
                if let Err(e) = nt_check(
                    (self.monitor_control)(ptr::null(), &mut monitoring),
                    "Query monitor",
                ) {
                    errors.push(e);
                }
                if let Err(e) = nt_check(
                    (self.disable_force)(ptr::null(), &mut force_disabled),
                    "Query force rules",
                ) {
                    errors.push(e);
                }
                if let Err(e) = nt_check(
                    (self.query_driver_info)(0, (&mut features as *mut u32).cast(), 4),
                    "Query runtime capabilities",
                ) {
                    errors.push(e);
                }
            }
            if !service {
                errors.push("Sandboxie SbieSvc service is not running".into());
            }
            let available = errors.is_empty();
            if monitoring != 0 && !self.owns_monitor {
                errors.push("Another Sandboxie monitor is active in this Windows session; DiskGuard logging has not acquired its shared queue".into());
            }
            let version = unwide(&version);
            RuntimeStatus {
                available,
                install_path: Some(self.install.to_string_lossy().into_owned()),
                driver_version: (!version.is_empty()).then_some(version),
                service_running: service,
                monitoring: self.owns_monitor && monitoring != 0,
                force_rules_disabled: force_disabled != 0,
                security_features_available: features & 0x8000_0040 == 0x8000_0040,
                error: (!errors.is_empty()).then(|| errors.join("; ")),
            }
        }

        pub fn set_monitoring(&mut self, enabled: bool) -> Result<(), String> {
            self.monitor_requested = enabled;
            let mut current = 0;
            nt_check(
                unsafe { (self.monitor_control)(ptr::null(), &mut current) },
                "Query monitor state",
            )?;
            if enabled && !self.owns_monitor && current != 0 {
                return Err("A Sandboxie monitor is already active in this Windows session. Close its trace monitor before starting DiskGuard logging; the runtime has one shared destructive queue".into());
            }
            if !enabled && !self.owns_monitor {
                return Ok(());
            }
            let flag = u32::from(enabled);
            nt_check(
                unsafe { (self.monitor_control)(&flag, ptr::null_mut()) },
                "Change Sandboxie monitor state",
            )?;
            self.owns_monitor = enabled;
            Ok(())
        }

        pub fn poll(&mut self) -> Result<Vec<MonitorRecord>, String> {
            if !self.owns_monitor {
                if !self.monitor_requested {
                    return Ok(Vec::new());
                }
                let mut current = 0;
                nt_check(
                    unsafe { (self.monitor_control)(ptr::null(), &mut current) },
                    "Query monitor state",
                )?;
                if current != 0 {
                    return Ok(Vec::new());
                }
                self.set_monitoring(true)?;
            }
            let mut records = Vec::new();
            // Bound a polling turn so a busy process cannot starve commands.
            for _ in 0..4 {
                let mut len = self.buffer.len() as u32;
                let mut args = [0u64; 8];
                args[0] = 0x1234_0048; // API_MONITOR_GET2; eight 64-bit ABI slots.
                args[1] = self.buffer.as_mut_ptr() as u64;
                args[2] = (&mut len as *mut u32) as u64;
                let status = unsafe { (self.ioctl)(args.as_mut_ptr()) };
                if status as u32 == 0x8000_001a {
                    break;
                } // STATUS_NO_MORE_ENTRIES
                nt_check(
                    status,
                    "Read Sandboxie monitor (MonitorGet2, runtime >= 1.6.6)",
                )?;
                if len as usize > self.buffer.len() {
                    return Err("Sandboxie returned an invalid monitor buffer length".into());
                }
                if len != 0 {
                    records.extend(parse_monitor_buffer(&self.buffer[..len as usize])?);
                }
                if status != 0x0000_0105 {
                    break;
                } // STATUS_MORE_ENTRIES
            }
            for record in &mut records {
                let mut box_name = [0u16; 34];
                let mut image = [0u16; 1024];
                let mut created = 0u64;
                let status = unsafe {
                    (self.query_process)(
                        record.pid as usize as *mut c_void,
                        image.len() as u32,
                        box_name.as_mut_ptr(),
                        image.as_mut_ptr(),
                        ptr::null_mut(),
                        ptr::null_mut(),
                        &mut created,
                    )
                };
                // A PID may have been reused before retrieval. Do not attach
                // another process's name or box to an older record.
                if status >= 0
                    && created.saturating_sub(FILETIME_EPOCH) / 10_000 <= record.timestamp_ms
                {
                    record.box_name = unwide(&box_name);
                    record.process_name = unwide(&image);
                }
            }
            Ok(records)
        }

        /// Avoid forwarding a single-instance launch (QQ/WeChat in particular)
        /// to an existing unprotected instance. This is a launch-time check;
        /// forcing remains the driver's responsibility and concurrent external
        /// starts cannot be made atomic with a ToolHelp snapshot.
        pub fn ensure_no_unboxed_process(
            &self,
            exe: &str,
            expected_box: &str,
        ) -> Result<(), String> {
            valid_box(expected_box)?;
            let expected_path = normalized_executable(Path::new(exe))?;
            let basename = Path::new(exe)
                .file_name()
                .ok_or("Executable filename missing")?
                .to_string_lossy()
                .to_lowercase();
            struct OwnedHandle(*mut c_void);
            impl Drop for OwnedHandle {
                fn drop(&mut self) {
                    unsafe {
                        CloseHandle(self.0);
                    }
                }
            }
            unsafe {
                let raw_snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
                if raw_snapshot == INVALID_HANDLE_VALUE {
                    return Err(format!(
                        "Cannot inspect running programs (Windows error {})",
                        GetLastError()
                    ));
                }
                let snapshot = OwnedHandle(raw_snapshot);
                let mut process: PROCESSENTRY32W = std::mem::zeroed();
                process.dwSize = std::mem::size_of::<PROCESSENTRY32W>() as u32;
                if Process32FirstW(snapshot.0, &mut process) == 0 {
                    let code = GetLastError();
                    return if code == ERROR_NO_MORE_FILES {
                        Ok(())
                    } else {
                        Err(format!(
                            "Cannot enumerate running programs (Windows error {code})"
                        ))
                    };
                }
                loop {
                    if unwide(&process.szExeFile).to_lowercase() == basename {
                        let pid = process.th32ProcessID;
                        let raw_process = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, pid);
                        if raw_process.is_null() {
                            return Err(format!("Cannot verify running {basename} (PID {pid}, Windows error {}). Close it before applying protection", GetLastError()));
                        }
                        let handle = OwnedHandle(raw_process);
                        let mut image = vec![0u16; 32_768];
                        let mut length = image.len() as u32;
                        if QueryFullProcessImageNameW(handle.0, 0, image.as_mut_ptr(), &mut length)
                            == 0
                        {
                            return Err(format!("Cannot inspect executable path of {basename} (PID {pid}, Windows error {}). Close it before applying protection", GetLastError()));
                        }
                        let image = String::from_utf16_lossy(&image[..length as usize]);
                        if normalized_executable(Path::new(&image))? == expected_path {
                            let mut box_name = [0u16; 34];
                            let status = (self.query_process)(
                                pid as usize as *mut c_void,
                                0,
                                box_name.as_mut_ptr(),
                                ptr::null_mut(),
                                ptr::null_mut(),
                                ptr::null_mut(),
                                ptr::null_mut(),
                            );
                            if status < 0 || !unwide(&box_name).eq_ignore_ascii_case(expected_box) {
                                return Err(format!("{basename} (PID {pid}) is already running outside {expected_box}. Close that instance and its background processes before applying or launching protection"));
                            }
                        }
                    }
                    if Process32NextW(snapshot.0, &mut process) == 0 {
                        let code = GetLastError();
                        if code != ERROR_NO_MORE_FILES {
                            return Err(format!(
                                "Running-process verification interrupted (Windows error {code})"
                            ));
                        }
                        break;
                    }
                }
            }
            Ok(())
        }

        fn ensure_stopped(&self, box_name: &str) -> Result<(), String> {
            let mut count = 0u32;
            nt_check(
                unsafe {
                    (self.enum_process)(
                        wide(box_name).as_ptr(),
                        1,
                        u32::MAX,
                        ptr::null_mut(),
                        &mut count,
                    )
                },
                "Enumerate sandbox processes",
            )?;
            if count != 0 {
                return Err(format!("Close all {count} processes in {box_name} before changing its policy. Existing processes cache Sandboxie settings"));
            }
            Ok(())
        }

        fn read_setting(&self, box_name: &str, key: &str) -> Result<Vec<String>, String> {
            self.read_setting_flags(box_name, key, 0x7000_0000)
        }

        fn read_setting_flags(
            &self,
            box_name: &str,
            key: &str,
            flags: u32,
        ) -> Result<Vec<String>, String> {
            let box_name = wide(box_name);
            let key = wide(key);
            let mut values = Vec::new();
            for index in 0..4096u32 {
                let mut buffer = [0u16; 2048];
                let status = unsafe {
                    (self.query_conf)(
                        box_name.as_ptr(),
                        key.as_ptr(),
                        index | flags,
                        buffer.as_mut_ptr(),
                        (buffer.len() * 2) as u32,
                    )
                };
                // QueryConf returns RESOURCE_NAME_NOT_FOUND when absent/end.
                if status as u32 == 0xc000_008b || status as u32 == 0x8000_001a {
                    return Ok(values);
                }
                nt_check(status, "Read Sandboxie configuration")?;
                values.push(unwide(&buffer));
            }
            Err("Sandboxie configuration contains too many values".into())
        }

        fn ensure_clean_whitelist(
            &self,
            box_name: &str,
            explicit_normal: &[String],
        ) -> Result<(), String> {
            // NO_EXPAND only: unlike managed-setting readback, include both
            // global and template rules that are actually used by the driver.
            let effective_normal =
                self.read_setting_flags(box_name, "NormalFilePath", 0x2000_0000)?;
            let mut allow = BTreeMap::new();
            for key in [
                "OpenFilePath",
                "ReadFilePath",
                "WriteFilePath",
                "OpenPipePath",
            ] {
                allow.insert(
                    key.to_string(),
                    self.read_setting_flags(box_name, key, 0x2000_0000)?,
                );
            }
            check_whitelist_effective(explicit_normal, &effective_normal, &allow)?;
            for key in [
                "OpenFilePath",
                "ReadFilePath",
                "WriteFilePath",
                "NormalFilePath",
                "OpenPipePath",
            ] {
                let intrinsic =
                    self.read_setting_flags("TemplateDefaultPaths", key, 0x6000_0000)?;
                check_intrinsic_whitelist_paths(&intrinsic)?;
            }
            Ok(())
        }

        fn ensure_isolation_settings(&self, box_name: &str) -> Result<(), String> {
            let mut settings = BTreeMap::new();
            for key in [
                "BreakoutProcess",
                "BreakoutFolder",
                "BreakoutDocument",
                "NoSecurityIsolation",
                "DisableFileFilter",
            ] {
                settings.insert(
                    key.into(),
                    self.read_setting_flags(box_name, key, 0x2000_0000)?,
                );
            }
            check_isolation_effective(&settings)
        }

        fn update(
            &self,
            op: u16,
            box_name: &str,
            key: &str,
            value: Option<&str>,
        ) -> Result<(), String> {
            let value = value.map(wide);
            nt_check(
                unsafe {
                    (self.update_conf)(
                        op,
                        ptr::null(),
                        wide(box_name).as_ptr(),
                        wide(key).as_ptr(),
                        value.as_ref().map_or(ptr::null(), |v| v.as_ptr()),
                    )
                } as i32,
                &format!("Update Sandboxie {box_name}/{key}"),
            )
        }

        fn write_setting(
            &self,
            box_name: &str,
            key: &str,
            values: &[String],
        ) -> Result<(), String> {
            self.update(
                b's' as u16,
                box_name,
                key,
                values.first().map(String::as_str),
            )?;
            for value in values.iter().skip(1) {
                self.update(b'a' as u16, box_name, key, Some(value))?;
            }
            Ok(())
        }

        pub fn apply_policy(&mut self, policy: &CompiledPolicy) -> Result<(), String> {
            validate_policy(policy)?;
            let status = self.status();
            if !status.available {
                return Err(status
                    .error
                    .unwrap_or_else(|| "Sandboxie unavailable".into()));
            }
            if policy.requires_specificity && !status.security_features_available {
                return Err("Whitelist mode requires an active Sandboxie certificate with security features (UseRuleSpecificity). This runtime does not advertise that capability; no configuration was changed".into());
            }
            self.ensure_isolation_settings(&policy.box_name)?;
            let mut previous = BTreeMap::new();
            for key in MANAGED_KEYS {
                previous.insert(*key, self.read_setting(&policy.box_name, key)?);
            }
            if policy.requires_specificity {
                self.ensure_clean_whitelist(&policy.box_name, &previous["NormalFilePath"])?;
            }
            if MANAGED_KEYS.iter().all(|key| {
                previous[key].as_slice()
                    == policy.settings.get(*key).map(Vec::as_slice).unwrap_or(&[])
            }) {
                return Ok(());
            }
            self.ensure_stopped(&policy.box_name)?;
            let apply = (|| {
                // Keep an existing box and its forcing rules enabled during
                // updates. Disabling it would create an unprotected launch gap.
                // The upstream per-setting API is not an atomic transaction.
                if previous["Enabled"].is_empty() {
                    self.write_setting(&policy.box_name, "Enabled", &["n".into()])?;
                }
                for key in MANAGED_KEYS
                    .iter()
                    .filter(|k| !["Enabled", "ForceProcess", "ForceChildren"].contains(k))
                {
                    let expected = policy.settings.get(*key).map(Vec::as_slice).unwrap_or(&[]);
                    if previous[key] != expected {
                        self.write_setting(&policy.box_name, key, expected)?;
                    }
                }
                for key in ["ForceProcess", "ForceChildren", "Enabled"] {
                    let expected = policy.settings.get(key).map(Vec::as_slice).unwrap_or(&[]);
                    if previous[key] != expected {
                        self.write_setting(&policy.box_name, key, expected)?;
                    }
                }
                nt_check(
                    unsafe { (self.reload_conf)(u32::MAX, 0) },
                    "Reload Sandboxie configuration",
                )?;
                for key in MANAGED_KEYS {
                    let expected = policy.settings.get(*key).map(Vec::as_slice).unwrap_or(&[]);
                    if self.read_setting(&policy.box_name, key)? != expected {
                        return Err(format!(
                            "Sandboxie configuration verification failed for {key}"
                        ));
                    }
                }
                self.ensure_isolation_settings(&policy.box_name)?;
                if policy.requires_specificity {
                    self.ensure_clean_whitelist(
                        &policy.box_name,
                        policy
                            .settings
                            .get("NormalFilePath")
                            .map(Vec::as_slice)
                            .unwrap_or(&[]),
                    )?;
                }
                Ok(())
            })();
            if let Err(error) = apply {
                let mut rollback_errors = Vec::new();
                for key in MANAGED_KEYS.iter().filter(|k| **k != "Enabled") {
                    if let Err(e) = self.write_setting(&policy.box_name, key, &previous[key]) {
                        rollback_errors.push(e);
                    }
                }
                if let Err(e) =
                    self.write_setting(&policy.box_name, "Enabled", &previous["Enabled"])
                {
                    rollback_errors.push(e);
                }
                for key in MANAGED_KEYS {
                    match self.read_setting(&policy.box_name, key) {
                        Ok(actual) if actual == previous[key] => (),
                        Ok(_) => rollback_errors
                            .push(format!("Restored {key} failed readback verification")),
                        Err(e) => rollback_errors.push(e),
                    }
                }
                if !rollback_errors.is_empty() {
                    return Err(format!("{error}; rollback incomplete: {}. Inspect Sandboxie.ini before launching the application", rollback_errors.join("; ")));
                }
                return Err(format!("{error}; previous managed settings restored"));
            }
            Ok(())
        }

        pub fn remove_policy(&mut self, box_name: &str) -> Result<(), String> {
            valid_box(box_name)?;
            self.ensure_stopped(box_name)?;
            // Removing configuration never deletes sandbox contents/user files.
            self.update(b's' as u16, box_name, "*", None)?;
            nt_check(
                unsafe { (self.reload_conf)(u32::MAX, 0) },
                "Reload Sandboxie configuration",
            )?;
            if !self.read_setting(box_name, "Enabled")?.is_empty() {
                return Err("Sandboxie configuration removal could not be verified".into());
            }
            Ok(())
        }

        pub fn launch(&mut self, box_name: &str, exe: &str, args: &[String]) -> Result<(), String> {
            valid_box(box_name)?;
            let path = Path::new(exe);
            if !path.is_absolute()
                || !path.is_file()
                || !path
                    .extension()
                    .is_some_and(|extension| extension.eq_ignore_ascii_case("exe"))
                || exe.contains(['\0', '\r', '\n', '"'])
                || args.iter().any(|a| a.contains(['\0', '\r', '\n']))
            {
                return Err("Choose an existing absolute EXE path and valid arguments".into());
            }
            self.ensure_no_unboxed_process(exe, box_name)?;
            self.ensure_isolation_settings(box_name)?;
            let enabled = self.read_setting(box_name, "Enabled")?;
            if !enabled.first().is_some_and(|v| v.starts_with(['y', 'Y'])) {
                return Err(
                    "Apply and enable this application's sandbox policy before launching it".into(),
                );
            }
            // Start's custom command parser recognises /wait; wait for the
            // launcher itself, not the long-running protected application.
            let result = Command::new(self.install.join("Start.exe"))
                .arg(format!("/box:{box_name}"))
                .arg("/silent")
                .arg(exe)
                .args(args)
                .current_dir(path.parent().unwrap_or(&self.install))
                .creation_flags(0x0800_0000) // CREATE_NO_WINDOW
                .status()
                .map_err(|e| format!("Cannot launch through Sandboxie Start.exe: {e}"))?;
            if !result.success() {
                return Err(format!("Sandboxie Start.exe failed: {result}"));
            }
            Ok(())
        }
    }

    impl Drop for Runtime {
        fn drop(&mut self) {
            if self.owns_monitor {
                let _ = self.set_monitoring(false);
            }
        }
    }
}

#[cfg(not(windows))]
mod platform {
    use super::*;
    pub struct Runtime;
    const ERROR: &str = "Sandboxie runtime integration is available only on Windows x64";
    impl Runtime {
        pub fn connect() -> Result<Self, String> {
            Err(ERROR.into())
        }
        pub fn status(&self) -> RuntimeStatus {
            RuntimeStatus {
                available: false,
                install_path: None,
                driver_version: None,
                service_running: false,
                monitoring: false,
                security_features_available: false,
                force_rules_disabled: false,
                error: Some(ERROR.into()),
            }
        }
        pub fn set_monitoring(&mut self, _: bool) -> Result<(), String> {
            Err(ERROR.into())
        }
        pub fn poll(&mut self) -> Result<Vec<MonitorRecord>, String> {
            Err(ERROR.into())
        }
        pub fn ensure_no_unboxed_process(&self, _: &str, _: &str) -> Result<(), String> {
            Err(ERROR.into())
        }
        pub fn apply_policy(&mut self, policy: &CompiledPolicy) -> Result<(), String> {
            validate_policy(policy)?;
            Err(ERROR.into())
        }
        pub fn remove_policy(&mut self, name: &str) -> Result<(), String> {
            valid_box(name)?;
            Err(ERROR.into())
        }
        pub fn launch(&mut self, _: &str, _: &str, _: &[String]) -> Result<(), String> {
            Err(ERROR.into())
        }
    }
}

pub use platform::Runtime;

#[cfg(test)]
mod tests {
    use super::*;
    fn wire(kind: u32, strings: &[&str]) -> Vec<u8> {
        let mut entry = Vec::new();
        entry.extend_from_slice(&(FILETIME_EPOCH + 12_340_000).to_le_bytes());
        entry.extend_from_slice(&kind.to_le_bytes());
        entry.extend_from_slice(&42u32.to_le_bytes());
        entry.extend_from_slice(&43u32.to_le_bytes());
        for text in strings {
            for unit in text.encode_utf16().chain(Some(0)) {
                entry.extend_from_slice(&unit.to_le_bytes());
            }
        }
        let mut buffer = (entry.len() as u32).to_le_bytes().to_vec();
        buffer.extend(entry);
        buffer.extend(0u32.to_le_bytes());
        buffer
    }
    #[test]
    fn parses_real_file_open_shape_without_claiming_read() {
        let records = parse_monitor_buffer(&wire(
            0x4000000a,
            &[
                r"\Device\HarddiskVolume3\private",
                "(FD) 00100001.01.00000040",
            ],
        ))
        .unwrap();
        assert_eq!(records[0].timestamp_ms, 1234);
        assert_eq!(records[0].operation, "file_open");
        assert_eq!(records[0].result, "unknown");
        assert_eq!(records[0].pid, 42);
    }
    #[test]
    fn plain_policy_record_does_not_infer_completed_open_or_read() {
        let records =
            parse_monitor_buffer(&wire(0x0002000a, &[r"\Device\HarddiskVolume3\private"])).unwrap();
        assert_eq!(records[0].operation, "file_policy_check");
        assert_eq!(records[0].result, "denied");
    }
    #[test]
    fn truncated_or_unterminated_records_fail_closed() {
        let good = wire(0x0a, &["path"]);
        for end in 1..good.len() {
            assert!(parse_monitor_buffer(&good[..end]).is_err());
        }
        assert!(parse_monitor_buffer(&[255, 255, 255, 255]).is_err());
    }
    #[test]
    fn handles_multiple_records_and_ignores_bounded_stack_tags() {
        let mut first = wire(0x0a, &["path"]);
        first.truncate(first.len() - 4);
        let entry_len = u32::from_le_bytes(first[..4].try_into().unwrap());
        first.extend_from_slice(&0xffffu16.to_le_bytes());
        first.extend_from_slice(&0x5354434bu32.to_le_bytes());
        first.extend_from_slice(&8u32.to_le_bytes());
        first.extend_from_slice(&0u64.to_le_bytes());
        first[..4].copy_from_slice(&(entry_len + 18).to_le_bytes());
        first.extend(wire(0x0a, &["second"]));
        let parsed = parse_monitor_buffer(&first).unwrap();
        assert_eq!(parsed.len(), 2);
        assert_eq!(parsed[0].raw_details, ["path"]);
        assert_eq!(parsed[1].path, "second");
    }
    #[test]
    fn syscall_enumeration_and_read_requests_keep_missing_path_unknown() {
        let records =
            parse_monitor_buffer(&wire(1, &["QueryDirectoryFile", "status = 0xC0000022"])).unwrap();
        assert_eq!(records[0].operation, "directory_enumeration");
        assert_eq!(records[0].result, "denied");
        assert!(records[0].path.is_empty());
        let records = parse_monitor_buffer(&wire(1, &["ReadFile", "status = 0x0"])).unwrap();
        assert_eq!(records[0].operation, "read_request");
    }
    #[test]
    fn rejects_foreign_boxes_and_config_injection() {
        assert!(valid_box("DefaultBox").is_err());
        assert!(valid_box("DiskGuard_QQ").is_ok());
        let policy = CompiledPolicy {
            box_name: "DiskGuard_QQ".into(),
            requires_specificity: false,
            settings: BTreeMap::from([("ClosedFilePath".into(), vec!["path\nEnabled=n".into()])]),
        };
        assert!(validate_policy(&policy).is_err());
    }
    #[test]
    fn whitelist_checks_effective_inheritance_as_a_multiset() {
        let own = vec![r"|C:\Apps".to_string(), r"C:\Apps\*".to_string()];
        let no_allow = BTreeMap::new();
        assert!(check_whitelist_effective(&own, &own, &no_allow).is_ok());
        let mut inherited = own.clone();
        inherited.push(r"C:\Private\*".into());
        assert!(check_whitelist_effective(&own, &inherited, &no_allow).is_err());
        // Even duplicate inherited exceptions must not disappear via set math.
        let mut duplicate = own.clone();
        duplicate.extend(own.clone());
        assert!(check_whitelist_effective(&own, &duplicate, &no_allow).is_err());
        assert!(check_whitelist_effective(&own, &[], &no_allow).is_err());
        for key in [
            "OpenFilePath",
            "ReadFilePath",
            "WriteFilePath",
            "OpenPipePath",
        ] {
            let allow = BTreeMap::from([(key.into(), vec![r"C:\Private\*".into()])]);
            assert!(check_whitelist_effective(&own, &own, &allow).is_err());
        }
    }
    #[test]
    fn inherited_breakout_and_filter_disabling_settings_refuse_protection() {
        assert!(check_isolation_effective(&BTreeMap::new()).is_ok());
        for key in ["BreakoutProcess", "BreakoutFolder", "BreakoutDocument"] {
            assert!(check_isolation_effective(&BTreeMap::from([(
                key.into(),
                vec!["client.exe".into()]
            )]))
            .is_err());
        }
        for key in ["NoSecurityIsolation", "DisableFileFilter"] {
            assert!(
                check_isolation_effective(&BTreeMap::from([(key.into(), vec!["n".into()])]))
                    .is_ok()
            );
            for value in ["y", "client.exe,n", "unknown", ""] {
                assert!(check_isolation_effective(&BTreeMap::from([(
                    key.into(),
                    vec![value.into()]
                )]))
                .is_err());
            }
        }
    }
    #[test]
    fn intrinsic_disk_exceptions_refuse_whitelist_but_known_non_disk_devices_do_not() {
        for path in [
            r"\Device\NamedPipe\AudioSrv",
            r"\Device\Afd\Endpoint",
            r"\Device\MailSlot\",
            r"client.exe,\Device\NamedPipe\spoolss",
        ] {
            assert!(check_intrinsic_whitelist_paths(&[path.into()]).is_ok());
        }
        for path in [
            r"%DefaultSpoolDirectory%\*",
            r"C:\Spool\*",
            r"\\server\share\*",
            r"\Device\Mup\server\share\*",
            r"\Device\HarddiskVolume3\*",
            r"\Device\NamedPipeSibling\Disk",
            r"\Device\Unknown",
            r"client.exe,C:\Private,\Device\NamedPipe\Spoof",
        ] {
            assert!(check_intrinsic_whitelist_paths(&[path.into()]).is_err());
        }
    }
}
