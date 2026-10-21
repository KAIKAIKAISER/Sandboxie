use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Config {
    pub version: u32,
    pub apps: Vec<ManagedApp>,
    pub settings: Settings,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            version: 1,
            apps: vec![
                ManagedApp::preset("qq", "QQ"),
                ManagedApp::preset("wechat", "微信"),
            ],
            settings: Settings {
                theme: "system".into(),
                close_to_tray: true,
                autostart: false,
            },
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ManagedApp {
    pub id: String,
    pub name: String,
    pub executable: String,
    pub sandbox: String,
    pub mode: Mode,
    pub enabled: bool,
    pub auto_protect: bool,
    pub include_children: bool,
    pub rules: Vec<Rule>,
}

impl ManagedApp {
    pub fn preset(id: &str, name: &str) -> Self {
        Self {
            id: id.into(),
            name: name.into(),
            executable: String::new(),
            sandbox: format!("DiskGuard_{id}"),
            mode: Mode::Blacklist,
            enabled: false,
            auto_protect: true,
            include_children: true,
            rules: vec![],
        }
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum Mode {
    Blacklist,
    Whitelist,
    Monitor,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Rule {
    pub id: String,
    pub path: String,
    pub enabled: bool,
    pub recursive: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Settings {
    pub theme: String,
    pub close_to_tray: bool,
    pub autostart: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct LogEntry {
    pub id: u64,
    pub timestamp: String,
    pub app_id: String,
    pub app_name: String,
    pub pid: u32,
    pub path: String,
    pub operation: String,
    pub result: String,
    pub source: String,
    pub detail: String,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct LogFilter {
    #[serde(default)]
    pub search: String,
    #[serde(default)]
    pub app_id: String,
    #[serde(default)]
    pub result: String,
    #[serde(default)]
    pub operation: String,
}

impl LogFilter {
    pub fn matches(&self, e: &LogEntry) -> bool {
        let any = |f: &str, v: &str| f.is_empty() || f == "all" || f == v;
        any(&self.app_id, &e.app_id)
            && any(&self.result, &e.result)
            && any(&self.operation, &e.operation)
            && (self.search.is_empty()
                || format!(
                    "{} {} {} {} {}",
                    e.app_name, e.pid, e.path, e.detail, e.operation
                )
                .to_lowercase()
                .contains(&self.search.to_lowercase()))
    }
}
