// SPDX-License-Identifier: GPL-3.0-or-later
//! Explicit disposable-hosted-VM harness. Calls the same Backend save/apply
//! implementation as Tauri commands, with a separate fixture state directory.
use super::*;
use serde::Deserialize;

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Request {
    directory: PathBuf,
    action: Action,
    config: Option<Config>,
    app_id: Option<String>,
}
#[derive(Deserialize)]
#[serde(rename_all = "lowercase")]
enum Action {
    Inspect,
    Save,
    Apply,
}

pub(super) fn run(request: &str, destination: &str) -> bool {
    let mut report = serde_json::json!({"success":false,"error":null,"state":null});
    let result = (|| -> Result<(), String> {
        if std::env::var("GITHUB_ACTIONS").as_deref() != Ok("true")
            || std::env::var("RUNNER_ENVIRONMENT").as_deref() != Ok("github-hosted")
            || std::env::var("RUNNER_OS").as_deref() != Ok("Windows")
        {
            return Err(
                "Product policy harness is restricted to disposable GitHub-hosted Windows VMs"
                    .into(),
            );
        }
        let request: Request = store::read_json(Path::new(request))?;
        let temporary =
            PathBuf::from(std::env::var_os("RUNNER_TEMP").ok_or("Missing RUNNER_TEMP")?)
                .canonicalize()
                .map_err(|e| e.to_string())?;
        let directory = request
            .directory
            .canonicalize()
            .map_err(|e| e.to_string())?;
        if directory.parent() != Some(temporary.as_path())
            || !directory.file_name().is_some_and(|name| {
                name.to_string_lossy()
                    .starts_with("DiskGuard-product-test-")
            })
        {
            return Err("Product harness requires a dedicated direct child of RUNNER_TEMP".into());
        }
        let backend = Backend::new(directory);
        backend.require_configuration()?;
        if !matches!(request.action, Action::Inspect) {
            *backend.runtime.lock().map_err(|_| "Runtime lock error")? = Some(Runtime::connect()?);
            backend.save(request.config.ok_or("Missing fixture configuration")?)?;
            if matches!(request.action, Action::Apply) {
                backend.apply(
                    &request.app_id.ok_or("Missing fixture application ID")?,
                    false,
                )?;
            }
        }
        report["state"] = serde_json::to_value(backend.view()).map_err(|e| e.to_string())?;
        report["success"] = true.into();
        Ok(())
    })();
    if let Err(error) = result {
        report["error"] = error.into();
    }
    let success = report["success"] == true;
    store::write_json(Path::new(destination), &report).is_ok() && success
}
