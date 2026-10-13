use super::*;
use rand::RngCore as _;
use serde_json::{json, Value};
use std::io::Read as _;

const LIMIT: u64 = 128 * 1024 * 1024;

fn selected(id: uuid::Uuid) -> anyhow::Result<(rbw::db::Db, rbw::db::Entry)> {
    unlock_online()?;
    crate::actions::sync()?;
    let db = load_db()?;
    let entry = db
        .entries
        .iter()
        .find(|e| uuid::Uuid::parse_str(&e.id) == Ok(id))
        .context("item UUID not found")?
        .clone();
    Ok((db, entry))
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

fn cipher(db: &mut rbw::db::Db, id: uuid::Uuid) -> anyhow::Result<Value> {
    let (token, value) = rbw::actions::cipher_request(
        db.access_token.as_deref().context("missing access token")?,
        db.refresh_token
            .as_deref()
            .context("missing refresh token")?,
        &reqwest::Method::GET,
        &format!("/ciphers/{id}"),
        None,
    )?;
    save_token(db, token)?;
    Ok(value)
}

pub fn attachment_list(id: uuid::Uuid, reveal: bool) -> anyhow::Result<()> {
    let (mut db, entry) = selected(id)?;
    let name = crate::actions::decrypt(
        &entry.name,
        entry.key.as_deref(),
        entry.org_id.as_deref(),
    )?;
    if reveal {
        rbw::reveal::authorize(
            "attachment-list",
            &name,
            Some(&entry.id),
            Some("attachments"),
            entry.folder.as_deref(),
        )?;
    }
    let value = cipher(&mut db, id)?;
    let attachments =
        value["attachments"].as_array().cloned().unwrap_or_default();
    let mut result = Vec::new();
    for attachment in attachments {
        let filename = if reveal {
            crate::actions::decrypt(
                attachment["fileName"]
                    .as_str()
                    .context("attachment filename missing")?,
                entry.key.as_deref(),
                entry.org_id.as_deref(),
            )?
        } else {
            "[redacted]".into()
        };
        result.push(json!({"id":attachment["id"],"fileName":filename,"size":attachment["size"]}));
    }
    println!("{}", serde_json::to_string_pretty(&result)?);
    Ok(())
}

pub fn attachment_upload(
    id: uuid::Uuid,
    file: &std::path::Path,
    filename: Option<&str>,
    options: &WriteOptions,
) -> anyhow::Result<()> {
    let mut input =
        std::fs::File::open(file).context("cannot open attachment file")?;
    anyhow::ensure!(
        input.metadata()?.is_file() && input.metadata()?.len() <= LIMIT,
        "attachment must be a regular file no larger than 128 MiB"
    );
    let filename = filename
        .or_else(|| file.file_name().and_then(std::ffi::OsStr::to_str))
        .context("attachment filename required")?;
    anyhow::ensure!(
        !filename.is_empty() && !filename.contains(['\n', '\r', '\0']),
        "invalid attachment filename"
    );
    let (mut db, entry) = selected(id)?;
    anyhow::ensure!(
        entry.org_id.is_none(),
        "shared attachment uploads are not supported"
    );
    eprintln!(
        "Upload attachment to {id}: {} bytes (filename hidden)",
        input.metadata()?.len()
    );
    if !options.approve()? {
        return Ok(());
    }
    let mut plaintext = zeroize::Zeroizing::new(Vec::new());
    std::io::Read::by_ref(&mut input)
        .take(LIMIT + 1)
        .read_to_end(&mut plaintext)?;
    anyhow::ensure!(
        plaintext.len() as u64 <= LIMIT,
        "attachment grew beyond size limit"
    );
    let mut bytes = rbw::locked::Vec::new();
    let mut random = zeroize::Zeroizing::new([0u8; 64]);
    rand::rng().fill_bytes(random.as_mut());
    bytes.extend(random.iter().copied());
    let keys = rbw::locked::Keys::new(bytes);
    let encrypted = rbw::attachments::encrypt(&keys, &plaintext)?;
    let wrapped_key = crate::actions::encrypt_bytes(
        random.as_ref(),
        entry.key.as_deref(),
        entry.org_id.as_deref(),
    )?;
    let encrypted_name = crate::actions::encrypt_entry(
        filename,
        entry.key.as_deref(),
        entry.org_id.as_deref(),
    )?;
    let (token, attachment) = rbw::actions::attachment_upload(
        db.access_token.as_deref().context("missing access token")?,
        db.refresh_token
            .as_deref()
            .context("missing refresh token")?,
        &entry.id,
        &encrypted_name,
        &wrapped_key,
        &encrypted,
    )?;
    save_token(&mut db, token)?;
    crate::actions::sync().context(
        "attachment uploaded but sync failed; inspect before retrying",
    )?;
    println!("{attachment}");
    Ok(())
}

pub fn attachment_download(
    id: uuid::Uuid,
    attachment: &str,
    output: &std::path::Path,
) -> anyhow::Result<()> {
    anyhow::ensure!(
        !attachment.is_empty()
            && attachment
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'-'),
        "invalid attachment id"
    );
    // Refuse accidental overwrite before authorizing or downloading.
    anyhow::ensure!(
        output.as_os_str() == "-" || !output.exists(),
        "output already exists; choose a new path"
    );
    let (mut db, entry) = selected(id)?;
    let name = crate::actions::decrypt(
        &entry.name,
        entry.key.as_deref(),
        entry.org_id.as_deref(),
    )?;
    rbw::reveal::authorize(
        "attachment-download",
        &name,
        Some(&entry.id),
        Some("attachments"),
        entry.folder.as_deref(),
    )?;
    let (token, (metadata, encrypted)) = rbw::actions::attachment_download(
        db.access_token.as_deref().context("missing access token")?,
        db.refresh_token
            .as_deref()
            .context("missing refresh token")?,
        &entry.id,
        attachment,
        LIMIT + 65,
    )?;
    save_token(&mut db, token)?;
    let wrapped = metadata["key"]
        .as_str()
        .context("legacy attachment without a key is not supported")?;
    let key = crate::actions::decrypt_bytes(
        wrapped,
        entry.key.as_deref(),
        entry.org_id.as_deref(),
    )?;
    anyhow::ensure!(key.len() == 64, "invalid attachment key length");
    let mut bytes = rbw::locked::Vec::new();
    bytes.extend(key.iter().copied());
    let plaintext = zeroize::Zeroizing::new(rbw::attachments::decrypt(
        &rbw::locked::Keys::new(bytes),
        &encrypted,
    )?);
    if output.as_os_str() == "-" {
        std::io::stdout().write_all(&plaintext)?;
    } else {
        use std::os::unix::fs::OpenOptionsExt as _;
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(output)
            .context("cannot create attachment output")?;
        if let Err(error) =
            file.write_all(&plaintext).and_then(|()| file.sync_all())
        {
            drop(file);
            let _ = std::fs::remove_file(output);
            return Err(error.into());
        }
    }
    Ok(())
}
