// SPDX-License-Identifier: GPL-3.0-or-later
//! Recoverable saves across local files and the non-transactional runtime API.
//! The journal is durable before a policy is removed. Failures block editing
//! until the same idempotent operation is resumed; they never claim rollback.
use crate::{model::*, policy, store};
use serde::{Deserialize, Serialize};
use std::{collections::BTreeMap, path::Path};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct Snapshot {
    pub config: Config,
    pub applied: BTreeMap<String, ManagedApp>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PendingSave {
    version: u32,
    before: Snapshot,
    after: Snapshot,
}

fn validate(snapshot: &Snapshot) -> Result<(), String> {
    for size in [
        serde_json::to_vec_pretty(&snapshot.config)
            .map_err(|e| e.to_string())?
            .len(),
        serde_json::to_vec_pretty(&snapshot.applied)
            .map_err(|e| e.to_string())?
            .len(),
    ] {
        if size > 4 * 1024 * 1024 {
            return Err("配置或已应用状态超过 4 MiB，已拒绝保存".into());
        }
    }
    policy::validate_config(&snapshot.config)?;
    let applied_config = Config {
        apps: snapshot.applied.values().cloned().collect(),
        ..Config::default()
    };
    policy::validate_config(&applied_config)?;
    if snapshot.applied.iter().any(|(id, app)| id != &app.id) {
        return Err("已应用状态的 ID 不匹配".into());
    }
    Ok(())
}

pub fn load(directory: &Path) -> Result<Snapshot, String> {
    let applied_path = directory.join("applied.json");
    let snapshot = Snapshot {
        config: store::read_config(&directory.join("config.json"))
            .map_err(|e| format!("config.json: {e}"))?,
        applied: if applied_path.exists() {
            store::read_json(&applied_path).map_err(|e| format!("applied.json: {e}"))?
        } else {
            BTreeMap::new()
        },
    };
    validate(&snapshot)?;
    Ok(snapshot)
}

fn plan(before: &Snapshot, config: Config) -> Snapshot {
    let applied = before
        .applied
        .iter()
        .filter(|(_, old)| {
            config
                .apps
                .iter()
                .any(|new| new.id == old.id && new.enabled && new.sandbox == old.sandbox)
        })
        .map(|(id, app)| (id.clone(), app.clone()))
        .collect();
    Snapshot { config, applied }
}

pub fn prepare(directory: &Path, before: Snapshot, config: Config) -> Result<PendingSave, String> {
    if directory.join("pending-save.json").exists() {
        return Err("存在未完成保存，请先恢复，不能覆盖操作日志".into());
    }
    validate(&before)?;
    policy::validate_config(&config)?;
    let transaction = PendingSave {
        version: 1,
        after: plan(&before, config),
        before,
    };
    validate(&transaction.after)?;
    if serde_json::to_vec_pretty(&transaction)
        .map_err(|e| e.to_string())?
        .len()
        > 20 * 1024 * 1024
    {
        return Err("保存日志过大，已拒绝修改运行时策略".into());
    }
    // Keep the last valid state, not the potentially half-written target.
    store::write_json(
        &directory.join("config.last-good.json"),
        &transaction.before.config,
    )?;
    store::write_json(
        &directory.join("applied.last-good.json"),
        &transaction.before.applied,
    )?;
    store::write_json(&directory.join("pending-save.json"), &transaction)?;
    Ok(transaction)
}

pub fn pending(directory: &Path) -> Result<Option<PendingSave>, String> {
    let path = directory.join("pending-save.json");
    if !path.exists() {
        return Ok(None);
    }
    let transaction: PendingSave = store::read_json_with_limit(&path, 20 * 1024 * 1024)
        .map_err(|e| format!("pending-save.json: {e}"))?;
    validate(&transaction.before)?;
    validate(&transaction.after)?;
    if transaction.version != 1
        || plan(&transaction.before, transaction.after.config.clone()) != transaction.after
    {
        return Err("未完成保存日志无效，请保留文件并按恢复指南处理".into());
    }
    Ok(Some(transaction))
}

pub fn finish(
    directory: &Path,
    transaction: &PendingSave,
    mut remove_policy: impl FnMut(&str) -> Result<(), String>,
) -> Result<Snapshot, String> {
    for (id, old) in &transaction.before.applied {
        if !transaction.after.applied.contains_key(id) {
            remove_policy(&old.sandbox)?;
        }
    }
    store::write_json(&directory.join("config.json"), &transaction.after.config)?;
    store::write_json(&directory.join("applied.json"), &transaction.after.applied)?;
    std::fs::remove_file(directory.join("pending-save.json")).map_err(|e| e.to_string())?;
    Ok(transaction.after.clone())
}

#[cfg(test)]
mod tests {
    use super::*;
    fn fixture() -> Snapshot {
        let mut app = ManagedApp::preset("test", "Test");
        app.enabled = true;
        app.executable = r"C:\Apps\test.exe".into();
        Snapshot {
            config: Config {
                apps: vec![app.clone()],
                ..Config::default()
            },
            applied: [(app.id.clone(), app)].into(),
        }
    }
    fn empty() -> Config {
        Config {
            apps: vec![],
            ..Config::default()
        }
    }

    #[test]
    fn removal_failure_keeps_journal_and_last_good_state() {
        let dir = tempfile::tempdir().unwrap();
        let before = fixture();
        let tx = prepare(dir.path(), before.clone(), empty()).unwrap();
        assert!(finish(dir.path(), &tx, |_| Err("service stopped".into())).is_err());
        assert!(pending(dir.path()).unwrap().is_some());
        let backup: Config = store::read_json(&dir.path().join("config.last-good.json")).unwrap();
        assert_eq!(backup, before.config);
        assert!(prepare(dir.path(), before, empty()).is_err());
        let after = finish(dir.path(), &tx, |_| Ok(())).unwrap();
        assert!(after.applied.is_empty());
        assert_eq!(load(dir.path()).unwrap(), after);
        assert!(pending(dir.path()).unwrap().is_none());
    }

    #[test]
    fn disk_failure_after_runtime_change_can_be_resumed() {
        let dir = tempfile::tempdir().unwrap();
        let tx = prepare(dir.path(), fixture(), empty()).unwrap();
        // A directory at the target path deterministically injects a write error.
        std::fs::create_dir(dir.path().join("config.json")).unwrap();
        let mut removals = 0;
        assert!(finish(dir.path(), &tx, |_| {
            removals += 1;
            Ok(())
        })
        .is_err());
        assert_eq!(removals, 1);
        let tx = pending(dir.path()).unwrap().unwrap();
        std::fs::remove_dir(dir.path().join("config.json")).unwrap();
        finish(dir.path(), &tx, |_| {
            removals += 1;
            Ok(())
        })
        .unwrap();
        assert_eq!(removals, 2); // Runtime removal must be idempotent.
        assert!(load(dir.path()).unwrap().applied.is_empty());
    }

    #[test]
    fn editing_rules_keeps_previous_applied_snapshot_pending() {
        let dir = tempfile::tempdir().unwrap();
        let before = fixture();
        let mut edited = before.config.clone();
        edited.apps[0].mode = Mode::Monitor;
        let tx = prepare(dir.path(), before.clone(), edited.clone()).unwrap();
        let after = finish(dir.path(), &tx, |_| panic!("no retirement expected")).unwrap();
        assert_eq!(after.applied, before.applied);
        assert_eq!(after.config, edited);
    }

    #[test]
    fn invalid_journal_and_corrupt_config_are_not_discarded() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("pending-save.json");
        std::fs::write(&path, b"{broken").unwrap();
        assert!(pending(dir.path()).is_err());
        assert!(path.exists());
        std::fs::write(dir.path().join("config.json"), b"{broken").unwrap();
        assert!(load(dir.path()).is_err());
    }

    #[test]
    fn partial_retirement_is_resumed_without_losing_remaining_operations() {
        let dir = tempfile::tempdir().unwrap();
        let mut before = fixture();
        let mut second = before.config.apps[0].clone();
        second.id = "two".into();
        second.sandbox = "DiskGuard_two".into();
        second.executable = r"C:\Apps\two.exe".into();
        before.config.apps.push(second.clone());
        before.applied.insert(second.id.clone(), second);
        let tx = prepare(dir.path(), before, empty()).unwrap();
        let mut attempted = Vec::new();
        assert!(finish(dir.path(), &tx, |sandbox| {
            attempted.push(sandbox.to_owned());
            if attempted.len() == 2 {
                Err("service stopped after the first removal".into())
            } else {
                Ok(())
            }
        })
        .is_err());
        assert_eq!(attempted.len(), 2);
        let journal = pending(dir.path()).unwrap().unwrap();
        finish(dir.path(), &journal, |sandbox| {
            attempted.push(sandbox.to_owned());
            Ok(())
        })
        .unwrap();
        assert_eq!(&attempted[..2], &attempted[2..]);
        assert!(load(dir.path()).unwrap().applied.is_empty());
    }
}
