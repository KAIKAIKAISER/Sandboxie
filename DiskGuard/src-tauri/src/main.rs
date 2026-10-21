#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

use chrono::{DateTime, Utc};
use diskguard::{
    model::*,
    policy,
    sandboxie::{Runtime, RuntimeStatus},
    store,
};
use serde::Serialize;
use std::{
    collections::{BTreeMap, VecDeque},
    path::{Path, PathBuf},
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc, Mutex,
    },
    time::Duration,
};
use tauri::{
    menu::{Menu, MenuItem},
    tray::{MouseButton, MouseButtonState, TrayIconBuilder, TrayIconEvent},
    Manager, State,
};
use tauri_plugin_autostart::ManagerExt;

const LOG_LIMIT: usize = 10_000;
const LOG_NOTICE: &str = "来源为 Sandboxie 实时追踪。允许/拒绝表示路径策略或打开请求判定，不证明内容已读取。目录枚举与实际读取事件不可用。日志仅在本 UI 运行且监控已连接时采集；会话缓冲可能丢失事件，不是完整审计。";

#[derive(Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct Status {
    driver_available: bool,
    service_running: bool,
    runtime_path: Option<String>,
    version: Option<String>,
    message: String,
    monitor_supported: bool,
    monitoring: bool,
    security_features_available: bool,
    force_rules_disabled: bool,
}
impl Status {
    fn unavailable(message: impl Into<String>) -> Self {
        Self {
            driver_available: false,
            service_running: false,
            runtime_path: None,
            version: None,
            message: message.into(),
            monitor_supported: false,
            monitoring: false,
            security_features_available: false,
            force_rules_disabled: false,
        }
    }
    fn from_runtime(r: RuntimeStatus) -> Self {
        Self { driver_available: r.available, service_running: r.service_running,
            runtime_path: r.install_path, version: r.driver_version,
            message: r.error.unwrap_or_else(|| if r.force_rules_disabled {
                "Sandboxie 强制沙箱规则已被全局禁用，自动保护失效。请在 Sandboxie 中恢复后重试。".into()
            } else { "运行时已连接；沙箱策略在应用后持久生效，日志仅在此界面运行时采集。".into() }),
            monitor_supported: r.available, monitoring: r.monitoring,
            security_features_available: r.security_features_available, force_rules_disabled: r.force_rules_disabled }
    }
}

#[derive(Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct ViewState {
    config: Config,
    runtime: Status,
    applied_app_ids: Vec<String>,
    pending_app_ids: Vec<String>,
}
#[derive(Serialize)]
struct LogPage {
    entries: Vec<LogEntry>,
    notice: String,
    dropped: u64,
}
#[derive(Serialize)]
struct ActionResult {
    message: String,
}
#[derive(Serialize)]
struct ExportResult {
    path: String,
    count: usize,
}

struct Inner {
    config: Config,
    applied: BTreeMap<String, ManagedApp>,
    runtime: Status,
    logs: VecDeque<LogEntry>,
    sequence: u64,
    dropped: u64,
}
struct Backend {
    inner: Mutex<Inner>,
    runtime: Mutex<Option<Runtime>>,
    mutation: Mutex<()>,
    directory: PathBuf,
    shutting_down: AtomicBool,
}
impl Backend {
    fn new(directory: PathBuf) -> Result<Self, String> {
        let config = store::read_config(&directory.join("config.json"))?;
        let applied_path = directory.join("applied.json");
        let applied: BTreeMap<String, ManagedApp> = if applied_path.exists() {
            store::read_json(&applied_path)?
        } else {
            BTreeMap::new()
        };
        for a in applied.values() {
            policy::validate_box(&a.sandbox)?;
        }
        Ok(Self {
            inner: Mutex::new(Inner {
                config,
                applied,
                runtime: Status::unavailable("正在检测已安装的 Sandboxie 运行时…"),
                logs: VecDeque::new(),
                sequence: 0,
                dropped: 0,
            }),
            runtime: Mutex::new(None),
            mutation: Mutex::new(()),
            directory,
            shutting_down: AtomicBool::new(false),
        })
    }
    fn view(&self) -> ViewState {
        let inner = self.inner.lock().unwrap_or_else(|p| p.into_inner());
        ViewState {
            config: inner.config.clone(),
            runtime: inner.runtime.clone(),
            applied_app_ids: inner.applied.keys().cloned().collect(),
            pending_app_ids: inner
                .config
                .apps
                .iter()
                .filter(|a| inner.applied.get(&a.id) != Some(*a))
                .map(|a| a.id.clone())
                .collect(),
        }
    }
    fn apply(&self, id: &str, launch: bool) -> Result<ActionResult, String> {
        let _mutation = self.mutation.lock().map_err(|_| "后台状态锁错误")?;
        let app = self
            .inner
            .lock()
            .map_err(|_| "配置锁错误")?
            .config
            .apps
            .iter()
            .find(|a| a.id == id)
            .cloned()
            .ok_or("找不到软件")?;
        if !app.enabled {
            return Err("请先启用并保存此软件".into());
        }
        if !Path::new(&app.executable).is_file() {
            return Err("EXE 文件不存在，请重新选择并保存".into());
        }
        let mut runtime = self.runtime.lock().map_err(|_| "运行时锁错误")?;
        let runtime = runtime
            .as_mut()
            .ok_or("未连接 Sandboxie，请安装官方已签名运行时并等待连接")?;
        runtime.ensure_no_unboxed_process(&app.executable, &app.sandbox)?;
        if app.auto_protect && runtime.status().force_rules_disabled {
            return Err("Sandboxie 已全局禁用强制规则；恢复强制沙箱后才能应用自动保护".into());
        }
        runtime.apply_policy(&policy::compile(&app)?)?;
        let mut inner = self.inner.lock().map_err(|_| "配置锁错误")?;
        inner.applied.insert(id.into(), app.clone());
        store::write_json(&self.directory.join("applied.json"), &inner.applied)?;
        drop(inner);
        if launch {
            runtime.launch(&app.sandbox, &app.executable, &[])?;
        }
        Ok(ActionResult {
            message: if launch {
                "沙箱启动请求已提交；请通过真实追踪记录确认目标进程已运行。".into()
            } else {
                "策略已写入、读回验证并重载。自动保护适用于后续启动；现有进程需要退出后重新启动。"
                    .into()
            },
        })
    }
    fn save(&self, config: Config) -> Result<ActionResult, String> {
        policy::validate_config(&config)?;
        let _mutation = self.mutation.lock().map_err(|_| "后台状态锁错误")?;
        let applied = self.inner.lock().map_err(|_| "配置锁错误")?.applied.clone();
        let retired: Vec<_> = applied
            .values()
            .filter(|old| {
                !config
                    .apps
                    .iter()
                    .any(|new| new.id == old.id && new.enabled && new.sandbox == old.sandbox)
            })
            .cloned()
            .collect();
        for old in &retired {
            let mut runtime = self.runtime.lock().map_err(|_| "运行时锁错误")?;
            runtime
                .as_mut()
                .ok_or("尚有已应用的沙箱。请连接运行时后再禁用、删除或重命名，防止残留强制规则。")?
                .remove_policy(&old.sandbox)?;
            let mut inner = self.inner.lock().map_err(|_| "配置锁错误")?;
            inner.applied.remove(&old.id);
            store::write_json(&self.directory.join("applied.json"), &inner.applied)?;
        }
        store::write_json(&self.directory.join("config.json"), &config)?;
        self.inner.lock().map_err(|_| "配置锁错误")?.config = config;
        Ok(ActionResult { message: "配置已保存。修改后的目录策略需点击「应用策略」；删除、禁用软件时旧强制规则已清除，沙箱内文件保留。".into() })
    }
    fn monitor(self: Arc<Self>) {
        std::thread::spawn(move || {
            let mut retry = 0u32;
            while !self.shutting_down.load(Ordering::Acquire) {
                let mut runtime = self.runtime.lock().unwrap_or_else(|p| p.into_inner());
                if runtime.is_none() && retry == 0 {
                    match Runtime::connect() {
                        Ok(mut connected) => {
                            let result = connected.set_monitoring(true);
                            let mut status = Status::from_runtime(connected.status());
                            if let Err(error) = result {
                                status.message = format!("监控启动失败：{error}");
                            }
                            self.inner.lock().unwrap_or_else(|p| p.into_inner()).runtime = status;
                            *runtime = Some(connected);
                        }
                        Err(error) => {
                            self.inner.lock().unwrap_or_else(|p| p.into_inner()).runtime =
                                Status::unavailable(error);
                            retry = 20;
                        }
                    }
                }
                retry = retry.saturating_sub(1);
                if let Some(connected) = runtime.as_mut() {
                    match connected.poll() {
                        Ok(records) => {
                            let status = Status::from_runtime(connected.status());
                            let mut inner = self.inner.lock().unwrap_or_else(|p| p.into_inner());
                            inner.runtime = status;
                            for r in records {
                                let app = inner
                                    .applied
                                    .values()
                                    .find(|a| a.sandbox.eq_ignore_ascii_case(&r.box_name))
                                    .cloned();
                                let Some(app) = app else { continue };
                                inner.sequence += 1;
                                let id = inner.sequence;
                                let timestamp =
                                    DateTime::<Utc>::from_timestamp_millis(r.timestamp_ms as i64)
                                        .map(|t| {
                                            t.to_rfc3339_opts(chrono::SecondsFormat::Millis, true)
                                        })
                                        .unwrap_or_else(|| "未知时间".into());
                                if inner.logs.len() == LOG_LIMIT {
                                    inner.logs.pop_front();
                                    inner.dropped += 1;
                                }
                                inner.logs.push_back(LogEntry {
                                    id,
                                    timestamp,
                                    app_id: app.id,
                                    app_name: if r.process_name.is_empty() {
                                        app.name
                                    } else {
                                        r.process_name
                                    },
                                    pid: r.pid,
                                    path: r.path,
                                    operation: r.operation,
                                    result: r.result,
                                    source: "Sandboxie MonitorGet2".into(),
                                    detail: format!(
                                        "tid={} flags=0x{:08x} {}",
                                        r.tid,
                                        r.raw_type,
                                        r.raw_details.join(" | ")
                                    ),
                                });
                            }
                        }
                        Err(error) => {
                            self.inner.lock().unwrap_or_else(|p| p.into_inner()).runtime =
                                Status::unavailable(format!("监控中断，将重试：{error}"));
                            *runtime = None;
                            retry = 20;
                        }
                    }
                }
                drop(runtime);
                std::thread::sleep(Duration::from_millis(500));
            }
        });
    }
}

#[tauri::command]
fn get_state(state: State<'_, Arc<Backend>>) -> ViewState {
    state.view()
}
#[tauri::command]
fn runtime_status(state: State<'_, Arc<Backend>>) -> Status {
    state.view().runtime
}
#[tauri::command]
async fn save_config(
    state: State<'_, Arc<Backend>>,
    config: Config,
) -> Result<ActionResult, String> {
    let backend = state.inner().clone();
    tauri::async_runtime::spawn_blocking(move || backend.save(config))
        .await
        .map_err(|e| e.to_string())?
}
#[tauri::command]
async fn apply_policy(
    state: State<'_, Arc<Backend>>,
    app_id: String,
) -> Result<ActionResult, String> {
    let backend = state.inner().clone();
    tauri::async_runtime::spawn_blocking(move || backend.apply(&app_id, false))
        .await
        .map_err(|e| e.to_string())?
}
#[tauri::command]
async fn launch_app(
    state: State<'_, Arc<Backend>>,
    app_id: String,
) -> Result<ActionResult, String> {
    let backend = state.inner().clone();
    tauri::async_runtime::spawn_blocking(move || backend.apply(&app_id, true))
        .await
        .map_err(|e| e.to_string())?
}
#[tauri::command]
fn get_logs(state: State<'_, Arc<Backend>>, filter: LogFilter) -> LogPage {
    let inner = state.inner.lock().unwrap_or_else(|p| p.into_inner());
    LogPage {
        entries: inner
            .logs
            .iter()
            .filter(|e| filter.matches(e))
            .cloned()
            .collect(),
        notice: LOG_NOTICE.into(),
        dropped: inner.dropped,
    }
}
fn csv_safe(s: &str) -> String {
    if s.trim_start().starts_with(['=', '+', '-', '@', '\t', '\r']) {
        format!("'{s}")
    } else {
        s.into()
    }
}
#[tauri::command]
async fn export_logs(
    state: State<'_, Arc<Backend>>,
    filter: LogFilter,
    destination: String,
) -> Result<ExportResult, String> {
    let entries: Vec<LogEntry> = state
        .inner
        .lock()
        .map_err(|_| "日志锁错误")?
        .logs
        .iter()
        .filter(|e| filter.matches(e))
        .cloned()
        .collect();
    tauri::async_runtime::spawn_blocking(move || {
        let path = PathBuf::from(&destination);
        if !path.is_absolute() || path.extension().and_then(|s| s.to_str()) != Some("csv") {
            return Err("导出位置必须为绝对路径的 .csv 文件".into());
        }
        let mut tmp = tempfile::NamedTempFile::new_in(path.parent().ok_or("导出目录无效")?)
            .map_err(|e| e.to_string())?;
        use std::io::Write;
        tmp.write_all(&[0xef, 0xbb, 0xbf])
            .map_err(|e| e.to_string())?;
        {
            let mut writer = csv::Writer::from_writer(tmp.as_file_mut());
            writer
                .write_record([
                    "time_utc",
                    "app",
                    "pid",
                    "path",
                    "operation",
                    "result",
                    "source",
                    "detail",
                ])
                .map_err(|e| e.to_string())?;
            for e in &entries {
                writer
                    .write_record([
                        csv_safe(&e.timestamp),
                        csv_safe(&e.app_name),
                        e.pid.to_string(),
                        csv_safe(&e.path),
                        csv_safe(&e.operation),
                        csv_safe(&e.result),
                        csv_safe(&e.source),
                        csv_safe(&e.detail),
                    ])
                    .map_err(|e| e.to_string())?;
            }
            writer.flush().map_err(|e| e.to_string())?;
        }
        tmp.as_file().sync_all().map_err(|e| e.to_string())?;
        tmp.persist(&path).map_err(|e| e.to_string())?;
        Ok(ExportResult {
            path: destination,
            count: entries.len(),
        })
    })
    .await
    .map_err(|e| e.to_string())?
}
#[tauri::command]
fn set_autostart(
    app: tauri::AppHandle,
    state: State<'_, Arc<Backend>>,
    enabled: bool,
) -> Result<ActionResult, String> {
    if enabled {
        app.autolaunch().enable()
    } else {
        app.autolaunch().disable()
    }
    .map_err(|e| e.to_string())?;
    let mut inner = state.inner.lock().map_err(|_| "配置锁错误")?;
    inner.config.settings.autostart = enabled;
    store::write_json(&state.directory.join("config.json"), &inner.config)?;
    Ok(ActionResult {
        message: if enabled {
            "已启用当前用户登录启动".into()
        } else {
            "已关闭登录启动".into()
        },
    })
}

/// Headless adapter smoke test for the disposable CI VM. It exercises this
/// binary's exact ABI/config/monitor code, not a parallel mock implementation.
fn runtime_diagnostics(destination: &str) -> bool {
    let mut report = serde_json::json!({"success":false,"status":null,"monitor_enabled":false,"poll_ok":false,"records":0,"error":null});
    let outcome = (|| -> Result<(), String> {
        let mut runtime = Runtime::connect()?;
        report["status"] = serde_json::to_value(runtime.status()).map_err(|e| e.to_string())?;
        runtime.set_monitoring(true)?;
        report["monitor_enabled"] = true.into();
        let mut app = ManagedApp::preset("diag", "Adapter diagnostics");
        app.sandbox = format!("DiskGuard_Diag_{}", std::process::id());
        app.executable = format!(
            "{}\\System32\\cmd.exe",
            std::env::var("SystemRoot").map_err(|e| e.to_string())?
        );
        app.enabled = true;
        app.auto_protect = false;
        app.include_children = false;
        app.mode = Mode::Monitor;
        runtime.apply_policy(&policy::compile(&app)?)?;
        let result = (|| -> Result<(), String> {
            runtime.launch(
                &app.sandbox,
                &app.executable,
                &["/d".into(), "/c".into(), "dir %SystemRoot% > nul".into()],
            )?;
            let mut records = Vec::new();
            for _ in 0..30 {
                records.extend(runtime.poll()?);
                std::thread::sleep(Duration::from_millis(100));
            }
            report["poll_ok"] = true.into();
            report["records"] = records.len().into();
            report["sample"] = serde_json::to_value(records.iter().take(10).collect::<Vec<_>>())
                .map_err(|e| e.to_string())?;
            if records.is_empty() {
                return Err(
                    "No real monitor events were received during the sandboxed file access probe"
                        .into(),
                );
            }
            Ok(())
        })();
        // A short-lived helper may still be exiting; retry cleanup without
        // killing any process or deleting sandbox contents.
        let mut cleanup = runtime.remove_policy(&app.sandbox);
        for _ in 0..30 {
            if cleanup.is_ok() {
                break;
            }
            std::thread::sleep(Duration::from_millis(100));
            cleanup = runtime.remove_policy(&app.sandbox);
        }
        result?;
        cleanup?;
        report["success"] = true.into();
        Ok(())
    })();
    if let Err(error) = outcome {
        report["error"] = error.into();
    }
    let success = report["success"] == true;
    if let Err(error) = store::write_json(Path::new(destination), &report) {
        eprintln!("Cannot write diagnostics: {error}");
        return false;
    }
    success
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args
        .get(1)
        .is_some_and(|arg| arg == "--runtime-diagnostics")
    {
        std::process::exit(
            if args.get(2).is_some_and(|path| runtime_diagnostics(path)) {
                0
            } else {
                1
            },
        );
    }
    tauri::Builder::default()
        .plugin(tauri_plugin_single_instance::init(|app, _, _| {
            if let Some(w) = app.get_webview_window("main") {
                let _ = w.show();
                let _ = w.set_focus();
            }
        }))
        .plugin(tauri_plugin_dialog::init())
        .plugin(
            tauri_plugin_autostart::Builder::new()
                .args(["--background"])
                .build(),
        )
        .setup(|app| {
            let backend = Arc::new(
                Backend::new(app.path().app_config_dir()?).map_err(std::io::Error::other)?,
            );
            backend.clone().monitor();
            app.manage(backend);
            let show = MenuItem::with_id(app, "show", "打开 DiskGuard", true, None::<&str>)?;
            let quit = MenuItem::with_id(
                app,
                "quit",
                "退出（已应用策略继续生效）",
                true,
                None::<&str>,
            )?;
            let menu = Menu::with_items(app, &[&show, &quit])?;
            let icon = app
                .default_window_icon()
                .cloned()
                .ok_or("Missing application icon")?;
            TrayIconBuilder::new()
                .icon(icon)
                .tooltip("DiskGuard · 磁盘访问保护")
                .menu(&menu)
                .show_menu_on_left_click(false)
                .on_menu_event(|app, event| match event.id.as_ref() {
                    "show" => {
                        if let Some(w) = app.get_webview_window("main") {
                            let _ = w.show();
                            let _ = w.set_focus();
                        }
                    }
                    "quit" => app.exit(0),
                    _ => (),
                })
                .on_tray_icon_event(|tray, event| {
                    if matches!(
                        event,
                        TrayIconEvent::Click {
                            button: MouseButton::Left,
                            button_state: MouseButtonState::Up,
                            ..
                        }
                    ) {
                        if let Some(w) = tray.app_handle().get_webview_window("main") {
                            let _ = w.show();
                            let _ = w.set_focus();
                        }
                    }
                })
                .build(app)?;
            if std::env::args().any(|a| a == "--background") {
                if let Some(w) = app.get_webview_window("main") {
                    w.hide()?;
                }
            }
            Ok(())
        })
        .on_window_event(|window, event| {
            if let tauri::WindowEvent::CloseRequested { api, .. } = event {
                let state = window.state::<Arc<Backend>>();
                if state
                    .inner
                    .lock()
                    .unwrap_or_else(|p| p.into_inner())
                    .config
                    .settings
                    .close_to_tray
                {
                    api.prevent_close();
                    let _ = window.hide();
                }
            }
        })
        .invoke_handler(tauri::generate_handler![
            get_state,
            runtime_status,
            save_config,
            apply_policy,
            launch_app,
            get_logs,
            export_logs,
            set_autostart
        ])
        .build(tauri::generate_context!())
        .expect("DiskGuard failed to initialize")
        .run(|app, event| {
            if let tauri::RunEvent::Exit = event {
                let backend = app.state::<Arc<Backend>>();
                backend.shutting_down.store(true, Ordering::Release);
                if let Ok(mut runtime) = backend.runtime.lock() {
                    if let Some(runtime) = runtime.as_mut() {
                        let _ = runtime.set_monitoring(false);
                    }
                };
            }
        });
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn csv_export_prevents_spreadsheet_formulas() {
        for s in ["=HYPERLINK(\"x\")", "+cmd", "-1+2", "@test", "  =x"] {
            assert!(csv_safe(s).starts_with('\''));
        }
        assert_eq!(csv_safe(r"C:\file"), r"C:\file");
    }
}
