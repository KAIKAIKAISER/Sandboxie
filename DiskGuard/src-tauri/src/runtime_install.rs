// SPDX-License-Identifier: GPL-3.0-or-later
//! Installs only the hash-pinned, bundled official runtime. The controller is
//! never elevated: Windows elevates the verified official installer itself.

use serde::{Deserialize, Serialize};
use std::{
    path::{Path, PathBuf},
    sync::atomic::{AtomicBool, Ordering},
};

static INSTALLING: AtomicBool = AtomicBool::new(false);
static REBOOT_REQUIRED: AtomicBool = AtomicBool::new(false);
const LOCK_SOURCE: &str = include_str!("../../scripts/runtime.lock.json");

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RuntimeInstallation {
    pub installed: bool,
    pub bundled: bool,
    pub installing: bool,
    pub reboot_required: bool,
    pub message: String,
    pub can_install: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct InstallResult {
    pub outcome: String,
    pub message: String,
    pub exit_code: Option<u32>,
    pub runtime_version: String,
    pub driver_available: bool,
    pub reboot_required: bool,
}

impl InstallResult {
    pub fn failure(message: String) -> Self {
        Self {
            outcome: "failed".into(),
            message,
            exit_code: None,
            runtime_version: pinned_lock().map(|l| l.classic_version).unwrap_or_default(),
            driver_available: false,
            reboot_required: false,
        }
    }

    pub fn process_exit_code(&self) -> i32 {
        match self.outcome.as_str() {
            "installed" | "alreadyInstalled" => 0,
            "rebootRequired" => 3010,
            "cancelled" => 1223,
            _ => 1,
        }
    }
}

#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct RuntimeLock {
    repository: String,
    release_tag: String,
    classic_version: String,
    asset: String,
    sha256: String,
    url: String,
    provenance: String,
}

fn pinned_lock() -> Result<RuntimeLock, String> {
    let lock: RuntimeLock =
        serde_json::from_str(LOCK_SOURCE).map_err(|e| format!("内置运行时版本清单无效：{e}"))?;
    if lock.repository != "sandboxie-plus/Sandboxie"
        || lock.asset.contains(['/', '\\', ':'])
        || !lock.asset.ends_with(".exe")
        || lock.sha256.len() != 64
        || !lock.sha256.bytes().all(|b| b.is_ascii_hexdigit())
    {
        return Err("内置运行时信任清单无效，请重新安装 DiskGuard".into());
    }
    Ok(lock)
}

fn verify_lock(bytes: &[u8]) -> Result<RuntimeLock, String> {
    let bundled: RuntimeLock =
        serde_json::from_slice(bytes).map_err(|e| format!("附带的运行时清单损坏：{e}"))?;
    let pinned = pinned_lock()?;
    if bundled != pinned {
        return Err("附带的运行时清单与程序固定版本不一致，已拒绝安装".into());
    }
    Ok(pinned)
}

pub fn resource_roots(resource_dir: Option<PathBuf>) -> Vec<PathBuf> {
    let mut roots = Vec::new();
    if let Some(directory) = resource_dir {
        roots.push(directory.join("runtime"));
    }
    if let Ok(exe) = std::env::current_exe() {
        if let Some(parent) = exe.parent() {
            let directory = parent.join("runtime");
            if !roots.contains(&directory) {
                roots.push(directory);
            }
        }
    }
    roots
}

fn bundle_directory(roots: &[PathBuf]) -> Result<PathBuf, String> {
    let lock = pinned_lock()?;
    roots.iter().find(|directory| directory.join(&lock.asset).is_file()
        && directory.join("runtime.lock.json").is_file()).cloned()
        .ok_or_else(|| "未找到附带的官方运行时安装包。请保持便携版 runtime 文件夹与 DiskGuard.exe 同目录，或重新安装完整安装包".into())
}

fn default_report_path() -> Option<PathBuf> {
    std::env::var_os("LOCALAPPDATA")
        .map(PathBuf::from)
        .filter(|p| p.is_absolute())
        .map(|p| p.join("DiskGuard").join("runtime-install.json"))
}

fn remember_result(result: &InstallResult) {
    let mut report = result.clone();
    // An unsuccessful retry must not erase a previous explicit restart request.
    // A successfully connected installation is the only non-restart outcome
    // that clears it; status also ignores an old persisted request once healthy.
    if !report.driver_available && !report.reboot_required {
        report.reboot_required = REBOOT_REQUIRED.load(Ordering::Acquire)
            || default_report_path()
                .and_then(|path| diskguard::store::read_json::<InstallResult>(&path).ok())
                .is_some_and(|prior| prior.reboot_required);
    }
    REBOOT_REQUIRED.store(report.reboot_required, Ordering::Release);
    if let Some(path) = default_report_path() {
        let _ = diskguard::store::write_json(&path, &report);
    }
}

pub fn install(roots: &[PathBuf]) -> Result<InstallResult, String> {
    if INSTALLING
        .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
        .is_err()
    {
        return Err("官方运行时安装正在进行，请等待当前操作完成".into());
    }
    struct Busy;
    impl Drop for Busy {
        fn drop(&mut self) {
            INSTALLING.store(false, Ordering::Release);
        }
    }
    let _busy = Busy;
    let outcome = platform::install(roots);
    match &outcome {
        Ok(result) => remember_result(result),
        Err(error) => remember_result(&InstallResult::failure(error.clone())),
    }
    outcome
}

pub fn status(roots: &[PathBuf]) -> RuntimeInstallation {
    platform::status(roots)
}

#[cfg(windows)]
mod platform {
    use super::*;
    use diskguard::sandboxie::Runtime;
    use sha2::{Digest, Sha256};
    use std::{
        fs::{File, OpenOptions},
        io::{Read, Seek, SeekFrom},
        os::windows::{ffi::OsStrExt, fs::OpenOptionsExt, io::AsRawHandle},
        ptr,
        time::Duration,
    };
    use windows_sys::Win32::{
        Foundation::{
            CloseHandle, GetLastError, ERROR_CANCELLED, ERROR_FILE_NOT_FOUND, ERROR_PATH_NOT_FOUND,
            WAIT_ABANDONED, WAIT_OBJECT_0, WAIT_TIMEOUT,
        },
        Security::WinTrust::{
            WinVerifyTrust, WINTRUST_ACTION_GENERIC_VERIFY_V2, WINTRUST_DATA, WINTRUST_DATA_0,
            WINTRUST_FILE_INFO, WTD_CACHE_ONLY_URL_RETRIEVAL, WTD_CHOICE_FILE, WTD_REVOKE_NONE,
            WTD_STATEACTION_CLOSE, WTD_STATEACTION_VERIFY, WTD_UI_NONE,
        },
        System::{
            Com::{
                CoInitializeEx, CoUninitialize, COINIT_APARTMENTTHREADED, COINIT_DISABLE_OLE1DDE,
            },
            Registry::{
                RegCloseKey, RegGetValueW, RegOpenKeyExW, HKEY_LOCAL_MACHINE, KEY_READ,
                RRF_RT_REG_MULTI_SZ,
            },
            Threading::{
                CreateMutexW, GetExitCodeProcess, ReleaseMutex, WaitForSingleObject, INFINITE,
            },
        },
        UI::{
            Shell::{
                ShellExecuteExW, SEE_MASK_FLAG_NO_UI, SEE_MASK_NOASYNC, SEE_MASK_NOCLOSEPROCESS,
                SHELLEXECUTEINFOW,
            },
            WindowsAndMessaging::SW_HIDE,
        },
    };

    fn wide(text: &str) -> Vec<u16> {
        text.encode_utf16().chain(Some(0)).collect()
    }
    fn path_wide(path: &Path) -> Vec<u16> {
        path.as_os_str().encode_wide().chain(Some(0)).collect()
    }

    fn installed_markers() -> Result<bool, String> {
        for name in ["SbieSvc", "SbieDrv"] {
            let mut key = ptr::null_mut();
            let code = unsafe {
                RegOpenKeyExW(
                    HKEY_LOCAL_MACHINE,
                    wide(&format!(r"SYSTEM\CurrentControlSet\Services\{name}")).as_ptr(),
                    0,
                    KEY_READ,
                    &mut key,
                )
            };
            if code == 0 {
                unsafe {
                    RegCloseKey(key);
                }
                return Ok(true);
            }
            if code != ERROR_FILE_NOT_FOUND && code != ERROR_PATH_NOT_FOUND {
                return Err(format!("无法可靠检查已有 Sandboxie 安装（Windows {code}）。请检查服务或修复已有安装；不会覆盖运行时"));
            }
        }
        Ok(false)
    }

    fn available() -> Result<String, String> {
        Runtime::connect().map(|runtime| runtime.status().driver_version.unwrap_or_default())
    }

    fn persisted_reboot(healthy: bool) -> bool {
        if REBOOT_REQUIRED.load(Ordering::Acquire) {
            return true;
        }
        if healthy {
            return false;
        }
        default_report_path()
            .and_then(|path| diskguard::store::read_json::<InstallResult>(&path).ok())
            .is_some_and(|report| report.reboot_required)
    }

    pub fn status(roots: &[PathBuf]) -> RuntimeInstallation {
        let registered = installed_markers();
        let installed = registered.as_ref().copied().unwrap_or(false);
        let bundled = bundle_directory(roots).is_ok();
        let installing = INSTALLING.load(Ordering::Acquire);
        let healthy = installed && available().is_ok();
        let reboot_required = persisted_reboot(healthy);
        let message = if installing {
            "正在验证并安装附带的官方运行时。Windows 可能显示管理员授权提示，请等待完成".into()
        } else if let Err(error) = &registered {
            error.clone()
        } else if reboot_required {
            "运行时安装要求重新启动 Windows。请保存工作并重启；DiskGuard 不会自动重启电脑".into()
        } else if installed && healthy {
            "已检测到可用的 Sandboxie 运行时，将继续使用现有安装，不会覆盖 Plus 或 Classic".into()
        } else if installed {
            "已检测到 Sandboxie 服务或驱动注册，但运行时当前不可用。请启动服务、完成系统重启或修复原安装；DiskGuard 不会覆盖已有配置".into()
        } else if bundled {
            "已附带固定版本的官方 Classic 运行时。点击安装后完成 Windows 管理员授权，即可启用磁盘保护".into()
        } else {
            "完整运行时安装包缺失。请重新解压含 runtime 文件夹的便携版，或重新安装 DiskGuard".into()
        };
        RuntimeInstallation {
            installed,
            bundled,
            installing,
            reboot_required,
            can_install: registered.is_ok()
                && !installed
                && bundled
                && !installing
                && !reboot_required,
            message,
        }
    }

    struct InstallMutex(*mut std::ffi::c_void);
    impl Drop for InstallMutex {
        fn drop(&mut self) {
            unsafe {
                ReleaseMutex(self.0);
                CloseHandle(self.0);
            }
        }
    }
    fn lock_machine_install() -> Result<InstallMutex, String> {
        let handle = unsafe {
            CreateMutexW(
                ptr::null(),
                0,
                wide(r"Global\DiskGuard_BundledRuntime_Install").as_ptr(),
            )
        };
        if handle.is_null() {
            return Err(format!(
                "无法锁定运行时安装操作（Windows {}）",
                unsafe { GetLastError() }
            ));
        }
        let wait = unsafe { WaitForSingleObject(handle, 0) };
        if wait == WAIT_OBJECT_0 || wait == WAIT_ABANDONED {
            return Ok(InstallMutex(handle));
        }
        unsafe {
            CloseHandle(handle);
        }
        Err(if wait == WAIT_TIMEOUT {
            "另一个 DiskGuard 进程正在安装官方运行时，请等待完成".into()
        } else {
            "无法确认当前运行时安装状态，请稍后重试".into()
        })
    }

    fn locked_file(path: &Path) -> Result<File, String> {
        OpenOptions::new()
            .read(true)
            .share_mode(1)
            .open(path)
            .map_err(|e| format!("无法安全读取安装资源 {}：{e}", path.display()))
    }

    fn verified_installer(roots: &[PathBuf]) -> Result<(PathBuf, File), String> {
        let directory = bundle_directory(roots)?
            .canonicalize()
            .map_err(|e| format!("无法解析运行时资源目录：{e}"))?;
        let prefix = directory.to_string_lossy();
        if prefix.starts_with(r"\\?\UNC\")
            || (prefix.starts_with(r"\\") && !prefix.starts_with(r"\\?\"))
        {
            return Err(
                "请将 DiskGuard 完整包复制到本地磁盘后安装运行时，不从网络共享执行提权安装".into(),
            );
        }
        let lock_path = directory
            .join("runtime.lock.json")
            .canonicalize()
            .map_err(|e| e.to_string())?;
        let pinned = pinned_lock()?;
        let installer = directory
            .join(&pinned.asset)
            .canonicalize()
            .map_err(|e| e.to_string())?;
        if lock_path.parent() != Some(directory.as_path())
            || installer.parent() != Some(directory.as_path())
        {
            return Err("运行时资源指向安装目录外部，已拒绝执行".into());
        }
        let mut manifest = locked_file(&lock_path)?;
        if manifest.metadata().map_err(|e| e.to_string())?.len() > 32_768 {
            return Err("运行时清单过大，已拒绝安装".into());
        }
        let mut bytes = Vec::new();
        manifest
            .read_to_end(&mut bytes)
            .map_err(|e| e.to_string())?;
        let lock = verify_lock(&bytes)?;
        let mut file = locked_file(&installer)?;
        let mut digest = Sha256::new();
        let mut buffer = [0u8; 65_536];
        loop {
            let len = file.read(&mut buffer).map_err(|e| e.to_string())?;
            if len == 0 {
                break;
            }
            digest.update(&buffer[..len]);
        }
        if format!("{:x}", digest.finalize()) != lock.sha256.to_ascii_lowercase() {
            return Err("官方运行时安装包 SHA-256 与固定版本不一致，已拒绝安装。请重新安装完整 DiskGuard 包".into());
        }
        file.seek(SeekFrom::Start(0)).map_err(|e| e.to_string())?;
        verify_authenticode(&installer, &file)?;
        // Retain this read-only, no-write/no-delete-sharing handle until the
        // elevated installer exits, preventing ordinary payload replacement.
        Ok((installer, file))
    }

    fn verify_authenticode(path: &Path, file: &File) -> Result<(), String> {
        let name = path_wide(path);
        let mut info = WINTRUST_FILE_INFO {
            cbStruct: std::mem::size_of::<WINTRUST_FILE_INFO>() as u32,
            pcwszFilePath: name.as_ptr(),
            hFile: file.as_raw_handle(),
            pgKnownSubject: ptr::null_mut(),
        };
        let mut data = WINTRUST_DATA {
            cbStruct: std::mem::size_of::<WINTRUST_DATA>() as u32,
            dwUIChoice: WTD_UI_NONE,
            fdwRevocationChecks: WTD_REVOKE_NONE,
            dwUnionChoice: WTD_CHOICE_FILE,
            Anonymous: WINTRUST_DATA_0 { pFile: &mut info },
            dwStateAction: WTD_STATEACTION_VERIFY,
            dwProvFlags: WTD_CACHE_ONLY_URL_RETRIEVAL,
            ..Default::default()
        };
        let mut action = WINTRUST_ACTION_GENERIC_VERIFY_V2;
        let result = unsafe {
            WinVerifyTrust(
                ptr::null_mut(),
                &mut action,
                (&mut data as *mut WINTRUST_DATA).cast(),
            )
        };
        data.dwStateAction = WTD_STATEACTION_CLOSE;
        unsafe {
            WinVerifyTrust(
                ptr::null_mut(),
                &mut action,
                (&mut data as *mut WINTRUST_DATA).cast(),
            );
        }
        if result != 0 {
            return Err(format!("Windows 无法信任官方安装包的 Authenticode 签名（0x{:08X}）。已停止安装，不会更改驱动签名要求", result as u32));
        }
        Ok(())
    }

    fn run_elevated(installer: &Path) -> Result<Option<u32>, String> {
        let initialized = unsafe {
            CoInitializeEx(
                ptr::null(),
                COINIT_APARTMENTTHREADED as u32 | COINIT_DISABLE_OLE1DDE as u32,
            )
        };
        struct ComGuard(bool);
        impl Drop for ComGuard {
            fn drop(&mut self) {
                if self.0 {
                    unsafe {
                        CoUninitialize();
                    }
                }
            }
        }
        let _com = ComGuard(initialized >= 0);
        // ShellExecute uses shell paths, whereas canonicalize returns an NT
        // extended DOS prefix. Strip only that prefix for this shell call.
        let shell_path = installer
            .to_str()
            .ok_or("安装目录含无法传递给 Windows Shell 的字符")?;
        let shell_path = Path::new(shell_path.strip_prefix(r"\\?\").unwrap_or(shell_path));
        let name = path_wide(shell_path);
        let directory = path_wide(shell_path.parent().ok_or("安装包目录无效")?);
        let verb = wide("runas");
        let arguments = wide("/install /S");
        let mut info = SHELLEXECUTEINFOW {
            cbSize: std::mem::size_of::<SHELLEXECUTEINFOW>() as u32,
            fMask: SEE_MASK_NOCLOSEPROCESS | SEE_MASK_NOASYNC | SEE_MASK_FLAG_NO_UI,
            lpVerb: verb.as_ptr(),
            lpFile: name.as_ptr(),
            lpParameters: arguments.as_ptr(),
            lpDirectory: directory.as_ptr(),
            nShow: SW_HIDE,
            ..Default::default()
        };
        if unsafe { ShellExecuteExW(&mut info) } == 0 {
            let code = unsafe { GetLastError() };
            return if code == ERROR_CANCELLED {
                Ok(None)
            } else {
                Err(format!(
                    "无法启动官方安装程序（Windows {code}）。未更改驱动签名设置"
                ))
            };
        }
        if info.hProcess.is_null() {
            return Err(
                "Windows 未返回官方安装进程，无法可靠确认安装结果，请检查现有安装状态".into(),
            );
        }
        let wait = unsafe { WaitForSingleObject(info.hProcess, INFINITE) };
        let mut exit = 0;
        let queried = if wait == WAIT_OBJECT_0 {
            unsafe { GetExitCodeProcess(info.hProcess, &mut exit) }
        } else {
            0
        };
        let code = unsafe { GetLastError() };
        unsafe {
            CloseHandle(info.hProcess);
        }
        if wait != WAIT_OBJECT_0 || queried == 0 {
            return Err(format!(
                "无法读取官方安装进程结果（Windows {code}），请检查服务后再操作"
            ));
        }
        Ok(Some(exit))
    }

    fn pending_runtime_rename() -> bool {
        let mut bytes = 0;
        let key = wide(r"SYSTEM\CurrentControlSet\Control\Session Manager");
        let value = wide("PendingFileRenameOperations");
        let code = unsafe {
            RegGetValueW(
                HKEY_LOCAL_MACHINE,
                key.as_ptr(),
                value.as_ptr(),
                RRF_RT_REG_MULTI_SZ,
                ptr::null_mut(),
                ptr::null_mut(),
                &mut bytes,
            )
        };
        if code != 0 || bytes == 0 || bytes > 1_048_576 {
            return false;
        }
        let mut buffer = vec![0u16; (bytes as usize).div_ceil(2)];
        if unsafe {
            RegGetValueW(
                HKEY_LOCAL_MACHINE,
                key.as_ptr(),
                value.as_ptr(),
                RRF_RT_REG_MULTI_SZ,
                ptr::null_mut(),
                buffer.as_mut_ptr().cast(),
                &mut bytes,
            )
        } != 0
        {
            return false;
        }
        buffer.split(|unit| *unit == 0).any(|path| {
            let path = String::from_utf16_lossy(path).to_ascii_lowercase();
            path.ends_with(r"\sbiedrv.sys")
                || path.ends_with(r"\sbiesvc.exe")
                || path.ends_with(r"\sbiedll.dll")
        })
    }

    pub fn install(roots: &[PathBuf]) -> Result<InstallResult, String> {
        let _machine_lock = lock_machine_install()?;
        let version = pinned_lock()?.classic_version;
        if installed_markers()? {
            return match available() {
                Ok(actual) => Ok(InstallResult { outcome: "alreadyInstalled".into(),
                    message: "已有可用的 Sandboxie 运行时，已继续使用；没有运行安装器或覆盖现有配置".into(),
                    exit_code: None, runtime_version: actual, driver_available: true, reboot_required: false }),
                Err(error) => Err(format!("已检测到 Sandboxie 服务或驱动，但现有安装不可用。为保护 Plus/Classic 和配置，已拒绝覆盖；请修复原安装或完成重启。诊断：{error}")),
            };
        }
        let (installer, _locked_payload) = verified_installer(roots)?;
        // A second process or installer could have registered a runtime while
        // validation was in progress. Never upgrade it from this UI flow.
        if installed_markers()? {
            return Err(
                "验证期间检测到新出现的 Sandboxie 安装。为避免覆盖，已停止操作，请刷新状态".into(),
            );
        }
        let exit = run_elevated(&installer)?;
        if exit.is_none() {
            return Ok(InstallResult {
                outcome: "cancelled".into(),
                message: "已取消 Windows 管理员授权，未启动运行时安装".into(),
                exit_code: Some(1223),
                runtime_version: version,
                driver_available: false,
                reboot_required: false,
            });
        }
        let exit = exit.unwrap();
        if exit == 3010 || exit == 1641 {
            return Ok(InstallResult {
                outcome: "rebootRequired".into(),
                message:
                    "官方安装程序要求重新启动 Windows。请保存工作后重启；DiskGuard 不会自动重启电脑"
                        .into(),
                exit_code: Some(exit),
                runtime_version: version,
                driver_available: available().is_ok(),
                reboot_required: true,
            });
        }
        if exit != 0 {
            return Ok(InstallResult { outcome: "failed".into(), message: format!("官方运行时安装程序退出码为 {exit}。如已有部分服务注册，请修复原安装，不会重复覆盖"), exit_code: Some(exit), runtime_version: version, driver_available: false, reboot_required: false });
        }
        for _ in 0..30 {
            if available().is_ok() {
                return Ok(InstallResult {
                    outcome: "installed".into(),
                    message: "官方 Classic 运行时已安装，服务和驱动已连接，可以应用磁盘保护策略"
                        .into(),
                    exit_code: Some(0),
                    runtime_version: version,
                    driver_available: true,
                    reboot_required: false,
                });
            }
            std::thread::sleep(Duration::from_millis(500));
        }
        if pending_runtime_rename() {
            return Ok(InstallResult { outcome: "rebootRequired".into(), message: "官方安装已完成，检测到 Sandboxie 组件等待重启替换。请保存工作并重新启动 Windows".into(), exit_code: Some(0), runtime_version: version, driver_available: false, reboot_required: true });
        }
        Ok(InstallResult { outcome: "failed".into(), message: "官方安装程序已退出，但尚未验证到可用服务和驱动。请检查 Windows 服务和系统日志或修复安装；不要关闭驱动签名验证".into(), exit_code: Some(0), runtime_version: version, driver_available: false, reboot_required: false })
    }
}

#[cfg(not(windows))]
mod platform {
    use super::*;
    pub fn install(_: &[PathBuf]) -> Result<InstallResult, String> {
        Err("内置运行时仅支持 Windows x64".into())
    }
    pub fn status(roots: &[PathBuf]) -> RuntimeInstallation {
        RuntimeInstallation {
            installed: false,
            bundled: bundle_directory(roots).is_ok(),
            installing: false,
            reboot_required: false,
            message: "运行时安装仅支持 Windows x64".into(),
            can_install: false,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn sidecar_manifest_cannot_change_the_embedded_trust_anchor() {
        assert!(verify_lock(LOCK_SOURCE.as_bytes()).is_ok());
        let mut manifest: serde_json::Value = serde_json::from_str(LOCK_SOURCE).unwrap();
        manifest["sha256"] = "00".repeat(32).into();
        assert!(verify_lock(&serde_json::to_vec(&manifest).unwrap()).is_err());
        manifest = serde_json::from_str(LOCK_SOURCE).unwrap();
        manifest["asset"] = "other.exe".into();
        assert!(verify_lock(&serde_json::to_vec(&manifest).unwrap()).is_err());
    }
    #[test]
    fn cli_exit_codes_preserve_reboot_and_consent_results() {
        let mut result = InstallResult::failure("test".into());
        for (outcome, expected) in [
            ("installed", 0),
            ("alreadyInstalled", 0),
            ("rebootRequired", 3010),
            ("cancelled", 1223),
            ("failed", 1),
        ] {
            result.outcome = outcome.into();
            assert_eq!(result.process_exit_code(), expected);
        }
    }
}
