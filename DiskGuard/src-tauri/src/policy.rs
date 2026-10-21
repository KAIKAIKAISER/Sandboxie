use crate::model::{Config, ManagedApp, Mode};
use crate::sandboxie::CompiledPolicy;
use std::collections::{BTreeMap, HashSet};

pub fn validate_box(name: &str) -> Result<(), String> {
    if !name.starts_with("DiskGuard_")
        || name.len() > 32
        || name.len() <= 10
        || !name.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_')
    {
        return Err(
            "沙箱名称必须以 DiskGuard_ 开头，仅含英文字母、数字、下划线，长度不超过 32".into(),
        );
    }
    Ok(())
}

/// Restrict user input to literal drive/UNC paths: no INI wildcards, macros,
/// image prefixes, NT namespaces, relative paths, or alternate data streams.
pub fn literal_path(input: &str) -> Result<String, String> {
    let p = input.replace('/', "\\");
    let drive = p.as_bytes().get(1) == Some(&b':')
        && p.as_bytes().get(2) == Some(&b'\\')
        && p.as_bytes()[0].is_ascii_alphabetic();
    let unc = p.starts_with("\\\\")
        && !p.starts_with("\\\\?\\")
        && !p.starts_with("\\\\.\\")
        && p[2..].split('\\').filter(|c| !c.is_empty()).count() >= 2;
    if p.len() > 2048
        || (!drive && !unc)
        || p.chars()
            .any(|c| c.is_control() || "*?%,;\"<>|".contains(c))
    {
        return Err(format!(
            "路径必须是完整磁盘或 UNC 路径，不能包含通配符或配置字符：{input}"
        ));
    }
    let components = if drive { &p[3..] } else { &p[2..] };
    if components
        .split('\\')
        .any(|c| c == "." || c == ".." || c.contains(':') || c.ends_with(' ') || c.ends_with('.'))
    {
        return Err(format!("路径含有不安全或歧义片段：{input}"));
    }
    let trimmed = p.trim_end_matches('\\');
    Ok(if drive && trimmed.len() == 2 {
        format!("{trimmed}\\")
    } else {
        trimmed.to_string()
    })
}

pub fn validate_config(c: &Config) -> Result<(), String> {
    if c.version != 1
        || c.apps.len() > 128
        || !["system", "dark", "light"].contains(&c.settings.theme.as_str())
    {
        return Err("配置版本、软件数量或主题无效".into());
    }
    let (mut ids, mut boxes, mut exes) = (HashSet::new(), HashSet::new(), HashSet::new());
    for app in &c.apps {
        if app.id.is_empty()
            || app.id.len() > 80
            || app.name.trim().is_empty()
            || app.name.len() > 120
            || app.name.chars().any(char::is_control)
            || !ids.insert(app.id.to_lowercase())
        {
            return Err("软件 ID 或名称无效，或 ID 重复".into());
        }
        validate_box(&app.sandbox)?;
        if !boxes.insert(app.sandbox.to_lowercase()) {
            return Err("每个软件必须使用独立沙箱".into());
        }
        if app.enabled || !app.executable.is_empty() {
            let path = literal_path(&app.executable)?;
            if !path.to_ascii_lowercase().ends_with(".exe") {
                return Err("请选择 EXE 程序".into());
            }
            if !exes.insert(path.to_lowercase()) {
                return Err("同一 EXE 不能分配到多个沙箱".into());
            }
        }
        if app.rules.len() > 256 {
            return Err("每个软件最多 256 条目录规则".into());
        }
        let mut rule_ids = HashSet::new();
        for rule in &app.rules {
            if rule.id.is_empty() || !rule_ids.insert(&rule.id) {
                return Err("规则 ID 无效或重复".into());
            }
            literal_path(&rule.path)?;
        }
    }
    Ok(())
}

pub fn compile(app: &ManagedApp) -> Result<CompiledPolicy, String> {
    validate_box(&app.sandbox)?;
    let mut s = BTreeMap::new();
    let mut set = |key: &str, values: Vec<String>| {
        s.insert(key.into(), values);
    };
    set("Enabled", vec![if app.enabled { "y" } else { "n" }.into()]);
    set("ConfigLevel", vec!["10".into()]);
    set("FileTrace", vec!["ad".into()]);
    set(
        "UseRuleSpecificity",
        vec![if app.mode == Mode::Whitelist {
            "y"
        } else {
            "n"
        }
        .into()],
    );
    let mut closed = Vec::new();
    let mut normal = Vec::new();
    if app.enabled && app.mode != Mode::Monitor {
        for rule in app.rules.iter().filter(|r| r.enabled) {
            let p = literal_path(&rule.path)?;
            // Exact directory + subtree. Exact-only intentionally covers only the
            // directory object; it does not imply a recursive child-file block.
            let target = if app.mode == Mode::Blacklist {
                &mut closed
            } else {
                &mut normal
            };
            target.push(p.clone());
            if rule.recursive {
                target.push(format!("{}\\*", p.trim_end_matches('\\')));
            }
        }
        if app.mode == Mode::Whitelist {
            closed.push("*".into());
            // Compatibility exceptions are visible in docs/UI. They preserve
            // read access and write redirection, not host write-through access.
            normal.extend(
                [
                    "%SystemRoot%\\*",
                    "%SbieHome%\\*",
                    "%ProgramFiles%\\*",
                    "%ProgramFiles% (x86)\\*",
                ]
                .map(str::to_string),
            );
            let exe = literal_path(&app.executable)?;
            if let Some((dir, _)) = exe.rsplit_once('\\') {
                normal.push(dir.to_string());
                normal.push(format!("{dir}\\*"));
            }
        }
    }
    set("ClosedFilePath", closed);
    set("NormalFilePath", normal);
    let force = if app.enabled && app.auto_protect {
        // Native full-path matching requires '*'; without it upstream compares
        // this value to the basename. A trailing '*' also matches suffixes on
        // this filename (documented) while keeping the directory anchored.
        vec![format!("{}*", literal_path(&app.executable)?)]
    } else {
        vec![]
    };
    set("ForceProcess", force.clone());
    set(
        "ForceChildren",
        if app.include_children { force } else { vec![] },
    );
    Ok(CompiledPolicy {
        box_name: app.sandbox.clone(),
        settings: s,
        requires_specificity: app.enabled && app.mode == Mode::Whitelist,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{ManagedApp, Rule};

    fn app() -> ManagedApp {
        let mut a = ManagedApp::preset("test", "Test");
        a.enabled = true;
        a.executable = r"C:\Apps\Client.exe".into();
        a
    }
    #[test]
    fn rejects_ini_and_namespace_injection() {
        for p in [
            "C:\\foo\nEnabled=y",
            r"C:\a,b",
            r"C:\%USERPROFILE%",
            r"C:\*",
            r"C:\a\..\b",
            r"\\?\C:\foo",
            r"C:\a:stream",
            "C:relative",
            "relative",
        ] {
            assert!(literal_path(p).is_err(), "{p}");
        }
        assert_eq!(literal_path(r"C:\私人 文件\").unwrap(), r"C:\私人 文件");
        assert!(literal_path(r"\\server\share\folder").is_ok());
    }
    #[test]
    fn blacklist_is_exact_plus_subtree_and_monitor_has_no_rules() {
        let mut a = app();
        a.rules.push(Rule {
            id: "1".into(),
            path: r"D:\Secret".into(),
            enabled: true,
            recursive: true,
        });
        let p = compile(&a).unwrap();
        assert_eq!(p.settings["ClosedFilePath"], [r"D:\Secret", r"D:\Secret\*"]);
        a.mode = Mode::Monitor;
        assert!(compile(&a).unwrap().settings["ClosedFilePath"].is_empty());
    }
    #[test]
    fn whitelist_requires_entitlement_and_keeps_redirected_writes() {
        let mut a = app();
        a.mode = Mode::Whitelist;
        let p = compile(&a).unwrap();
        assert!(p.requires_specificity);
        assert_eq!(p.settings["ClosedFilePath"], ["*"]);
        assert!(!p.settings.contains_key("OpenFilePath"));
    }
    #[test]
    fn disabled_program_does_not_force() {
        let mut a = app();
        a.enabled = false;
        assert!(compile(&a).unwrap().settings["ForceProcess"].is_empty());
    }
    #[test]
    fn unique_executable_and_box_are_required() {
        let mut c = Config::default();
        c.apps = vec![app(), app()];
        assert!(validate_config(&c).is_err());
    }
}
