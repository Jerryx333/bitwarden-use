//! Folder-only operations never decrypt passwords, notes or custom fields.
use super::*;
use rbw::mutation::Patch;
use serde_json::json;

#[derive(Debug, serde::Serialize)]
struct FolderInfo {
    id: String,
    name: String,
}

fn tokens(db: &rbw::db::Db) -> anyhow::Result<(&str, &str)> {
    Ok((
        db.access_token.as_deref().context("missing access token")?,
        db.refresh_token
            .as_deref()
            .context("missing refresh token")?,
    ))
}

fn save_token(
    db: &mut rbw::db::Db,
    token: Option<String>,
) -> anyhow::Result<()> {
    if let Some(token) = token {
        db.access_token = Some(token);
        save_db(db)?;
    }
    Ok(())
}

fn folders(db: &mut rbw::db::Db) -> anyhow::Result<Vec<FolderInfo>> {
    let (access, refresh) = tokens(db)?;
    let (token, encrypted) = rbw::actions::list_folders(access, refresh)?;
    save_token(db, token)?;
    encrypted
        .into_iter()
        .map(|(id, name)| {
            Ok(FolderInfo {
                id,
                name: crate::actions::decrypt(&name, None, None)?,
            })
        })
        .collect()
}

fn named_folder<'a>(
    folders: &'a [FolderInfo],
    name: &str,
) -> anyhow::Result<Option<&'a FolderInfo>> {
    let matches: Vec<_> = folders.iter().filter(|f| f.name == name).collect();
    anyhow::ensure!(
        matches.len() <= 1,
        "duplicate folder name; select a folder UUID with --to"
    );
    Ok(matches.first().copied())
}

fn destination<'a>(
    folders: &'a [FolderInfo],
    target: &str,
) -> anyhow::Result<&'a FolderInfo> {
    if let Ok(id) = uuid::Uuid::parse_str(target) {
        return folders
            .iter()
            .find(|f| uuid::Uuid::parse_str(&f.id) == Ok(id))
            .context("folder UUID not found");
    }
    named_folder(folders, target)?
        .context("folder not found; use folder create first")
}

fn valid_name(name: &str) -> anyhow::Result<()> {
    anyhow::ensure!(!name.trim().is_empty(), "folder name cannot be empty");
    Ok(())
}

pub fn folder_list(as_json: bool) -> anyhow::Result<()> {
    unlock_online()?;
    let mut db = load_db()?;
    let mut folders = folders(&mut db)?;
    folders.sort_by(|a, b| a.name.cmp(&b.name).then(a.id.cmp(&b.id)));
    if as_json {
        serde_json::to_writer_pretty(std::io::stdout(), &folders)?;
        println!();
    } else {
        for folder in folders {
            println!("{}\t{}", folder.id, folder.name.escape_debug());
        }
    }
    Ok(())
}

pub fn folder_create(
    name: &str,
    options: &WriteOptions,
) -> anyhow::Result<()> {
    valid_name(name)?;
    unlock_online()?;
    let mut db = load_db()?;
    if named_folder(&folders(&mut db)?, name)?.is_some() {
        eprintln!("Folder already exists; no changes.");
        return Ok(());
    }
    eprintln!("Create folder: {}", name.escape_debug());
    if !options.approve()? {
        return Ok(());
    }
    let encrypted = crate::actions::encrypt(name, None)?;
    let (access, refresh) = tokens(&db)?;
    let (token, id) =
        rbw::actions::create_folder(access, refresh, &encrypted)?;
    save_token(&mut db, token).context("folder created, but saving token failed; check folder list before retrying")?;
    crate::actions::sync()
        .context("folder created, but sync failed; sync before retrying")?;
    println!("{id}");
    Ok(())
}

struct MovePlan {
    id: String,
    name: String,
    from: Option<String>,
    patch: Patch,
}

fn selected<'a>(
    entries: &'a [rbw::db::Entry],
    ids: &[uuid::Uuid],
) -> anyhow::Result<Vec<&'a rbw::db::Entry>> {
    anyhow::ensure!(!ids.is_empty(), "at least one entry UUID is required");
    let mut seen = std::collections::HashSet::new();
    ids.iter()
        .map(|id| {
            anyhow::ensure!(seen.insert(*id), "duplicate entry UUID: {id}");
            entries
                .iter()
                .find(|entry| uuid::Uuid::parse_str(&entry.id) == Ok(*id))
                .with_context(|| format!("entry UUID not found: {id}"))
        })
        .collect()
}

fn folder_patch(old: Option<&str>, new: Option<&str>) -> Patch {
    let mut patch = Patch::default();
    patch.change("/folderId", json!(old), json!(new));
    patch
}

pub fn move_entries(
    ids: &[uuid::Uuid],
    target: Option<&str>,
    options: &WriteOptions,
) -> anyhow::Result<()> {
    if let Some(target) = target {
        valid_name(target)?;
    }
    // Validate duplicates before unlock; resolve every UUID before the first write.
    let mut seen = std::collections::HashSet::new();
    anyhow::ensure!(
        !ids.is_empty() && ids.iter().all(|id| seen.insert(*id)),
        "entry UUIDs must be nonempty and unique"
    );
    unlock_online()?;
    crate::actions::sync()?;
    let mut db = load_db()?;
    let folders = folders(&mut db)?;
    let dest = target
        .map(|target| destination(&folders, target))
        .transpose()?;
    let to_id = dest.map(|f| f.id.as_str());
    let to_name = dest.map(|f| f.name.as_str());
    let mut plan = Vec::new();
    for entry in selected(&db.entries, ids)? {
        if entry.folder_id.as_deref() == to_id {
            continue;
        }
        plan.push(MovePlan {
            id: entry.id.clone(),
            name: crate::actions::decrypt(
                &entry.name,
                entry.key.as_deref(),
                entry.org_id.as_deref(),
            )?,
            from: entry
                .folder
                .as_deref()
                .map(|name| crate::actions::decrypt(name, None, None))
                .transpose()?,
            patch: folder_patch(entry.folder_id.as_deref(), to_id),
        });
    }
    if plan.is_empty() {
        eprintln!("No changes.");
        return Ok(());
    }
    for item in &plan {
        eprintln!(
            "{}\t{}: {} -> {}",
            item.id,
            item.name.escape_debug(),
            item.from.as_deref().unwrap_or("[no folder]").escape_debug(),
            to_name.unwrap_or("[no folder]").escape_debug()
        );
    }
    let config = rbw::config::Config::load()?;
    if to_name
        .is_some_and(|name| config.reveal_folders.iter().any(|f| f == name))
    {
        eprintln!("Destination is in reveal_folders: these entries will follow its secret-reveal policy.");
    }
    eprintln!(
        "Move {} entries (sequential; stops on the first failure).",
        plan.len()
    );
    if !options.approve()? {
        return Ok(());
    }
    for (done, item) in plan.iter().enumerate() {
        let result = (|| -> anyhow::Result<()> {
            let (access, refresh) = tokens(&db)?;
            let (token, ()) = rbw::actions::patch_cipher(
                access,
                refresh,
                &item.id,
                &item.patch,
            )?;
            save_token(&mut db, token)
                .context("move accepted, but saving token failed")?;
            Ok(())
        })();
        if let Err(error) = result {
            let sync = crate::actions::sync();
            anyhow::bail!("batch stopped at {} after {done} completed moves; current request may have been accepted; check synced state before retrying. Sync: {}. Cause: {error:#}", item.id, sync.err().map_or_else(|| "ok".into(), |e| e.to_string()));
        }
    }
    crate::actions::sync()
        .context("moves accepted, but sync failed; sync before retrying")?;
    eprintln!("Moved {} entries.", plan.len());
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn selection_rejects_missing_and_duplicate_ids_before_any_write() {
        let first =
            uuid::Uuid::parse_str("11111111-1111-1111-1111-111111111111")
                .unwrap();
        let missing =
            uuid::Uuid::parse_str("22222222-2222-2222-2222-222222222222")
                .unwrap();
        let entries = vec![rbw::db::Entry {
            id: first.to_string(),
            org_id: None,
            folder: None,
            folder_id: None,
            name: "encrypted-name".into(),
            data: rbw::db::EntryData::SecureNote,
            fields: vec![],
            notes: Some("encrypted-secret".into()),
            history: vec![],
            key: None,
            master_password_reprompt: rbw::api::CipherRepromptType::None,
        }];
        assert_eq!(
            selected(&entries, &[first]).unwrap()[0].id,
            first.to_string()
        );
        assert!(selected(&entries, &[first, missing]).is_err());
        assert!(selected(&entries, &[first, first]).is_err());
        assert!(selected(&entries, &[]).is_err());
    }

    #[test]
    fn folder_resolution_is_exact_and_ambiguous_names_fail() {
        let folders = vec![
            FolderInfo {
                id: "11111111-1111-1111-1111-111111111111".into(),
                name: "work".into(),
            },
            FolderInfo {
                id: "22222222-2222-2222-2222-222222222222".into(),
                name: "work".into(),
            },
        ];
        assert!(destination(&folders, "work").is_err());
        assert!(destination(&folders, "wor").is_err());
        assert_eq!(
            destination(&folders, &folders[1].id).unwrap().id,
            folders[1].id
        );
        assert!(destination(
            &folders,
            "33333333-3333-3333-3333-333333333333"
        )
        .is_err());
        assert!(valid_name("  ").is_err());
    }

    #[test]
    fn move_preserves_all_secrets_and_rejects_changed_folder() {
        let original = json!({"revisionDate":"now", "folderId":"old", "type":1,
            "key":"encrypted-key", "reprompt":1, "favorite":true,
            "login":{"password":"encrypted", "totp":"encrypted-seed", "fido2Credentials":[{"keyValue":"encrypted-passkey"}]},
            "future":{"unknown":true}, "fields":[{"value":"encrypted-field"}], "notes":"encrypted-note"});
        let mut cipher = original.clone();
        folder_patch(Some("old"), Some("new"))
            .apply(&mut cipher)
            .unwrap();
        assert_eq!(cipher["folderId"], "new");
        for key in [
            "key", "reprompt", "favorite", "login", "fields", "notes",
            "future",
        ] {
            assert_eq!(cipher[key], original[key]);
        }
        let before = cipher.clone();
        assert!(folder_patch(Some("old"), None).apply(&mut cipher).is_err());
        assert_eq!(cipher, before);
        folder_patch(Some("new"), None).apply(&mut cipher).unwrap();
        assert!(cipher["folderId"].is_null());
        folder_patch(None, Some("new")).apply(&mut cipher).unwrap();
        assert_eq!(cipher["folderId"], "new");
    }
}
