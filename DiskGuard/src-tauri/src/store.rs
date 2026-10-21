use crate::model::Config;
use crate::policy::validate_config;
use serde::{de::DeserializeOwned, Serialize};
use std::{fs, io::Write, path::Path};

pub fn read_config(path: &Path) -> Result<Config, String> {
    if !path.exists() {
        return Ok(Config::default());
    }
    let config: Config = read_json(path)?;
    validate_config(&config)?;
    Ok(config)
}

pub fn read_json<T: DeserializeOwned>(path: &Path) -> Result<T, String> {
    let metadata = fs::metadata(path).map_err(|e| e.to_string())?;
    if metadata.len() > 4 * 1024 * 1024 {
        return Err("配置文件过大".into());
    }
    serde_json::from_slice(&fs::read(path).map_err(|e| e.to_string())?).map_err(|e| e.to_string())
}

pub fn write_json<T: Serialize>(path: &Path, data: &T) -> Result<(), String> {
    let parent = path.parent().ok_or("配置目录无效")?;
    fs::create_dir_all(parent).map_err(|e| e.to_string())?;
    let mut file = tempfile::NamedTempFile::new_in(parent).map_err(|e| e.to_string())?;
    file.write_all(&serde_json::to_vec_pretty(data).map_err(|e| e.to_string())?)
        .map_err(|e| e.to_string())?;
    file.as_file().sync_all().map_err(|e| e.to_string())?;
    file.persist(path).map_err(|e| e.to_string())?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn configuration_roundtrip_and_atomic_replace() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("config.json");
        let mut c = Config::default();
        write_json(&p, &c).unwrap();
        c.settings.theme = "dark".into();
        write_json(&p, &c).unwrap();
        assert_eq!(read_config(&p).unwrap(), c);
    }
    #[test]
    fn corrupt_configuration_is_not_silently_discarded() {
        let d = tempfile::tempdir().unwrap();
        let p = d.path().join("config.json");
        fs::write(&p, b"{broken").unwrap();
        assert!(read_config(&p).is_err());
    }
}
