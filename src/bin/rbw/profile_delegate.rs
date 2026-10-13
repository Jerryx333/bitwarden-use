//! Compatibility alias. Personal profile policy is owned by profile-use.
use anyhow::Context as _;
use std::path::{Path, PathBuf};

fn installed_script() -> anyhow::Result<PathBuf> {
    let home = std::env::var_os("HOME").context("HOME is not configured")?;
    let home = PathBuf::from(home);
    find_script(&home)
}

fn find_script(home: &Path) -> anyhow::Result<PathBuf> {
    for root in [
        ".agents/skills/profile-use",
        ".codex/skills/profile-use",
        ".claude/skills/profile-use",
        ".agents/use-family/profile-use",
    ] {
        let script = home.join(root).join("scripts/profile_use.py");
        if script.is_file() {
            return Ok(script);
        }
    }
    anyhow::bail!("profile-use is not installed; install that skill and use its sync command")
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
        assert_eq!(find_script(home.path()).unwrap(), script);
        let preferred = home
            .path()
            .join(".agents/skills/profile-use/scripts/profile_use.py");
        std::fs::create_dir_all(preferred.parent().unwrap()).unwrap();
        std::fs::write(&preferred, "# synthetic installed skill").unwrap();
        assert_eq!(find_script(home.path()).unwrap(), preferred);
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
