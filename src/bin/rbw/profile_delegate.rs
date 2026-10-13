//! Compatibility alias. Personal profile policy is owned by profile-use.
use anyhow::Context as _;
use std::path::{Path, PathBuf};

fn installed_script() -> anyhow::Result<PathBuf> {
    let home = std::env::var_os("HOME").context("HOME is not configured")?;
    let home = PathBuf::from(home);
    find_script(&home)
}

fn find_script(home: &Path) -> anyhow::Result<PathBuf> {
    let usable = |root: &Path| {
        let script = root.join("scripts/profile_use.py");
        (script.is_file()
            && root.join("scripts/profile_vault_sync.py").is_file())
        .then_some(script)
    };
    for root in [
        ".agents/skills/profile-use",
        ".codex/skills/profile-use",
        ".claude/skills/profile-use",
        ".agents/use-family/profile-use",
    ] {
        if let Some(script) = usable(&home.join(root)) {
            return Ok(script);
        }
    }
    // Plugin-only installations do not create the standalone skill symlinks.
    // Select a registered installation instead of an arbitrary stale cache copy.
    for registry in [
        ".claude/plugins/installed_plugins.json",
        ".codex/plugins/installed_plugins.json",
    ] {
        let Ok(bytes) = std::fs::read(home.join(registry)) else {
            continue;
        };
        let Ok(manifest) =
            serde_json::from_slice::<serde_json::Value>(&bytes)
        else {
            continue;
        };
        let Some(plugins) = manifest
            .get("plugins")
            .and_then(serde_json::Value::as_object)
        else {
            continue;
        };
        for (name, records) in plugins {
            if name != "profile-use" && !name.starts_with("profile-use@") {
                continue;
            }
            for record in records.as_array().into_iter().flatten() {
                if let Some(root) = record
                    .get("installPath")
                    .and_then(serde_json::Value::as_str)
                {
                    if let Some(script) = usable(Path::new(root)) {
                        return Ok(script);
                    }
                }
            }
        }
    }
    anyhow::bail!("profile-use 0.4 or newer is required; update or install that skill and use its sync command")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn delegation_requires_installed_owner_and_uses_its_script() {
        let home = tempfile::tempdir().unwrap();
        assert!(find_script(home.path()).is_err());
        let script = home
            .path()
            .join(".codex/skills/profile-use/scripts/profile_use.py");
        std::fs::create_dir_all(script.parent().unwrap()).unwrap();
        std::fs::write(&script, "# synthetic installed skill").unwrap();
        std::fs::write(
            script.with_file_name("profile_vault_sync.py"),
            "# synthetic sync owner",
        )
        .unwrap();
        assert_eq!(find_script(home.path()).unwrap(), script);
        let preferred = home
            .path()
            .join(".agents/skills/profile-use/scripts/profile_use.py");
        std::fs::create_dir_all(preferred.parent().unwrap()).unwrap();
        std::fs::write(&preferred, "# synthetic installed skill").unwrap();
        std::fs::write(
            preferred.with_file_name("profile_vault_sync.py"),
            "# synthetic sync owner",
        )
        .unwrap();
        assert_eq!(find_script(home.path()).unwrap(), preferred);
    }

    #[test]
    fn registered_plugin_only_owner_is_found_and_old_standalone_is_skipped() {
        let home = tempfile::tempdir().unwrap();
        let old = home
            .path()
            .join(".agents/skills/profile-use/scripts/profile_use.py");
        std::fs::create_dir_all(old.parent().unwrap()).unwrap();
        std::fs::write(old, "# older profile-use without sync").unwrap();
        let root = home
            .path()
            .join(".claude/plugins/cache/example/profile-use/0.4.0");
        std::fs::create_dir_all(root.join("scripts")).unwrap();
        for file in ["profile_use.py", "profile_vault_sync.py"] {
            std::fs::write(
                root.join("scripts").join(file),
                "# synthetic owner",
            )
            .unwrap();
        }
        let registry =
            home.path().join(".claude/plugins/installed_plugins.json");
        std::fs::write(&registry,serde_json::to_vec(&serde_json::json!({"plugins":{"profile-use@example":[{"installPath":root}]}})).unwrap()).unwrap();
        assert_eq!(
            find_script(home.path()).unwrap(),
            root.join("scripts/profile_use.py")
        );
        std::fs::write(&registry, b"invalid registry").unwrap();
        assert!(find_script(home.path()).is_err());
    }
}

pub fn sync(
    file: &Path,
    profile: Option<&str>,
    folder: &str,
    skip_attachments: bool,
    options: &crate::commands::WriteOptions,
) -> anyhow::Result<()> {
    let script = installed_script()?;
    eprintln!("bwu profile sync is a compatibility alias; personal profile sync is owned by profile-use.");
    let mut child = std::process::Command::new("python3");
    child
        .arg(script)
        .arg("sync")
        .arg("--file")
        .arg(file)
        .arg("--folder")
        .arg(folder)
        .env("PROFILE_SYNC_BWU", std::env::current_exe()?);
    if let Some(profile) = profile {
        child.arg("--profile").arg(profile);
    }
    if skip_attachments {
        child.arg("--skip-attachments");
    }
    if options.dry_run {
        child.arg("--dry-run");
    }
    if options.yes {
        child.arg("--yes");
    }
    let status = child
        .status()
        .context("profile-use requires Python 3.9 or newer")?;
    anyhow::ensure!(status.success(), "profile-use sync did not complete");
    Ok(())
}
