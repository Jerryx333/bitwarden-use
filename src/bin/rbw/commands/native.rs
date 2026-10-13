use super::*;
use serde_json::{json, Value};
use std::io::Read as _;

const CARD: &[&str] = &[
    "cardholderName",
    "number",
    "brand",
    "expMonth",
    "expYear",
    "code",
];
const IDENTITY: &[&str] = &[
    "title",
    "firstName",
    "middleName",
    "lastName",
    "address1",
    "address2",
    "address3",
    "city",
    "state",
    "postalCode",
    "country",
    "phone",
    "email",
    "ssn",
    "licenseNumber",
    "passportNumber",
    "username",
];

// EncString: type prefix + IV base64 + separators + padded ciphertext base64 + MAC base64.
fn encrypted_string_length(value: &str) -> usize {
    let ciphertext = (value.len() / 16 + 1) * 16;
    72 + ciphertext.div_ceil(3) * 4
}

#[derive(serde::Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Item {
    name: String,
    #[serde(rename = "type")]
    kind: u8,
    notes: Option<String>,
    card: Option<Value>,
    identity: Option<Value>,
    secure_note: Option<Value>,
    #[serde(default)]
    fields: Option<Vec<Value>>,
}

fn validate_object(value: &Value, allowed: &[&str]) -> anyhow::Result<()> {
    let object = value
        .as_object()
        .context("item payload must be an object")?;
    anyhow::ensure!(
        object.iter().all(|(k, v)| allowed.contains(&k.as_str())
            && (v.is_string() || v.is_null())),
        "unsupported item field or non-string value (values hidden)"
    );
    Ok(())
}

impl Item {
    fn validate(&self) -> anyhow::Result<()> {
        anyhow::ensure!(
            !self.name.trim().is_empty(),
            "item name is required"
        );
        match self.kind {
            2 => {
                anyhow::ensure!(self.card.is_none() && self.identity.is_none() && self.notes.as_ref().is_some_and(|s| !s.is_empty()), "secure note requires notes and no card/identity payload");
                if let Some(note) = &self.secure_note { anyhow::ensure!(note == &json!({"type":0}), "secureNote must be an object with type zero"); }
            }
            3 => { anyhow::ensure!(self.identity.is_none() && self.secure_note.is_none(), "card cannot include identity/secureNote payload"); validate_object(self.card.as_ref().context("card payload required")?, CARD)?; }
            4 => { anyhow::ensure!(self.card.is_none() && self.secure_note.is_none(), "identity cannot include card/secureNote payload"); validate_object(self.identity.as_ref().context("identity payload required")?, IDENTITY)?; }
            _ => anyhow::bail!("supported item types: 2 (secure note), 3 (card), 4 (identity)"),
        }
        anyhow::ensure!(self.notes.as_ref().is_none_or(|s| encrypted_string_length(s) <= 10_000), "encrypted notes exceed the server limit; split large profiles into smaller sections");
        let mut seen = std::collections::HashSet::new();
        for field in self.fields.iter().flatten() {
            let object = field
                .as_object()
                .context("custom field must be an object")?;
            anyhow::ensure!(
                object
                    .keys()
                    .all(|k| ["name", "value", "type"].contains(&k.as_str()))
                    && field["name"].as_str().is_some_and(|s| !s.is_empty())
                    && field["value"].is_string()
                    && matches!(field["type"].as_u64(), Some(0 | 1))
                    && seen.insert(field["name"].as_str().unwrap()),
                "invalid or duplicate custom field (values hidden)"
            );
        }
        Ok(())
    }
    fn encrypt(&self, key: Option<&str>) -> anyhow::Result<Value> {
        let encrypt = |value: &Value| -> anyhow::Result<Value> {
            Ok(if let Some(s) = value.as_str() {
                json!(crate::actions::encrypt_entry(s, key, None)?)
            } else {
                Value::Null
            })
        };
        let object = |value: Option<&Value>| -> anyhow::Result<Value> {
            let Some(value) = value else {
                return Ok(Value::Null);
            };
            let mut out = serde_json::Map::new();
            for (k, v) in value.as_object().unwrap() {
                out.insert(k.clone(), encrypt(v)?);
            }
            Ok(Value::Object(out))
        };
        let fields = self.fields.iter().flatten().map(|field| Ok(json!({"name":encrypt(&field["name"])? ,"value":encrypt(&field["value"])? ,"type":field["type"]}))).collect::<anyhow::Result<Vec<_>>>()?;
        Ok(
            json!({"type":self.kind,"name":encrypt(&json!(self.name))?,"notes":encrypt(&json!(self.notes))?,"login":null,"card":object(self.card.as_ref())?,"identity":object(self.identity.as_ref())?,"secureNote":if self.kind == 2 {json!({"type":0})} else {Value::Null},"fields":fields}),
        )
    }
}

pub fn item_put(
    input: &std::path::Path,
    id: Option<uuid::Uuid>,
    folder: Option<&str>,
    options: &WriteOptions,
) -> anyhow::Result<()> {
    let mut reader: Box<dyn std::io::Read> = if input.as_os_str() == "-" {
        Box::new(std::io::stdin())
    } else {
        Box::new(std::fs::File::open(input)?)
    };
    let mut bytes = zeroize::Zeroizing::new(Vec::new());
    reader.by_ref().take(1_048_577).read_to_end(&mut bytes)?;
    anyhow::ensure!(bytes.len() <= 1_048_576, "JSON input exceeds 1 MiB");
    // serde errors can echo an offending personal value; report only the position.
    let item: Item = serde_json::from_slice(&bytes).map_err(|e| {
        anyhow::anyhow!(
            "invalid item JSON at line {}, column {} (values hidden)",
            e.line(),
            e.column()
        )
    })?;
    item.validate()?;
    unlock_online()?;
    crate::actions::sync()?;
    let mut db = load_db()?;
    let mut original = None;
    let entry = if let Some(id) = id {
        let entry = db
            .entries
            .iter()
            .find(|e| uuid::Uuid::parse_str(&e.id) == Ok(id))
            .context("item UUID not found")?
            .clone();
        anyhow::ensure!(
            entry.org_id.is_none(),
            "shared item writes are not supported"
        );
        if let rbw::db::EntryData::Login {
            username: _,
            password,
            totp,
            uris,
            fido2_credentials,
        } = &entry.data
        {
            anyhow::ensure!(
                password.is_none()
                    && totp.is_none()
                    && uris.is_empty()
                    && fido2_credentials.is_empty(),
                "refusing to convert a login holding credentials or passkeys"
            );
        }
        let (token, value) = rbw::actions::cipher_request(
            db.access_token.as_deref().context("missing access token")?,
            db.refresh_token
                .as_deref()
                .context("missing refresh token")?,
            &reqwest::Method::GET,
            &format!("/ciphers/{id}"),
            None,
        )?;
        if let Some(token) = token {
            db.access_token = Some(token);
            save_db(&db)?;
        }
        anyhow::ensure!(
            value["key"].as_str() == entry.key.as_deref(),
            "item key changed; sync and review again"
        );
        original = Some(value);
        Some(entry)
    } else {
        // Reject duplicates instead of silently creating another copy.
        for entry in &db.entries {
            if folder.is_none_or(|f| entry.folder.as_deref() == Some(f))
                && crate::actions::decrypt(
                    &entry.name,
                    entry.key.as_deref(),
                    entry.org_id.as_deref(),
                )? == item.name
            {
                anyhow::bail!(
                    "item name already exists; use --id to update explicitly"
                );
            }
        }
        None
    };
    eprintln!(
        "{} item {} (type {}, field values hidden)",
        if id.is_some() { "Update" } else { "Create" },
        item.name.escape_debug(),
        item.kind
    );
    if !options.approve()? {
        return Ok(());
    }
    let mut encrypted =
        item.encrypt(entry.as_ref().and_then(|e| e.key.as_deref()))?;
    let access = db.access_token.clone().context("missing access token")?;
    let refresh =
        db.refresh_token.clone().context("missing refresh token")?;
    let result_id;
    if let Some(original) = original {
        let mut patch = rbw::mutation::Patch::default();
        for key in [
            "type",
            "name",
            "notes",
            "card",
            "identity",
            "secureNote",
            "login",
            "fields",
        ] {
            if key == "fields" && item.fields.is_none() {
                continue;
            }
            patch.change(
                &format!("/{key}"),
                original[key].clone(),
                encrypted[key].clone(),
            );
        }
        let id = id.unwrap().to_string();
        let (token, ()) =
            rbw::actions::patch_cipher(&access, &refresh, &id, &patch)?;
        if let Some(token) = token {
            db.access_token = Some(token);
            save_db(&db)?;
        }
        result_id = id;
    } else {
        let folder_id = folder
            .map(|f| {
                resolve_folder(&mut db, &mut access.clone(), &refresh, f)
            })
            .transpose()?;
        encrypted["folderId"] = json!(folder_id);
        let (token, response) = rbw::actions::cipher_request(
            db.access_token.as_deref().context("missing access token")?,
            db.refresh_token
                .as_deref()
                .context("missing refresh token")?,
            &reqwest::Method::POST,
            "/ciphers",
            Some(&encrypted),
        )?;
        if let Some(token) = token {
            db.access_token = Some(token);
            save_db(&db)?;
        }
        result_id = response["id"]
            .as_str()
            .or_else(|| response["Id"].as_str())
            .context(
                "item created but server omitted id; sync before retrying",
            )?
            .to_owned();
    }
    crate::actions::sync()
        .context("item saved but sync failed; inspect before retrying")?;
    println!("{result_id}");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn notes_limit_accounts_for_utf8_and_encryption_overhead() {
        assert!(encrypted_string_length(&"x".repeat(7_000)) < 10_000);
        assert!(encrypted_string_length(&"語".repeat(3_000)) > 10_000);
        let item: Item = serde_json::from_value(
            json!({"name":"fixture","type":2,"notes":"x".repeat(7_500)}),
        )
        .unwrap();
        assert!(item.validate().is_err());
    }
    #[test]
    fn rejects_mixed_types_and_unknown_personal_fields() {
        for input in [
            json!({"name":"fixture","type":3,"card":{"number":"1234"},"identity":{}}),
            json!({"name":"fixture","type":4,"identity":{"unknown":"secret"}}),
            json!({"name":"fixture","type":2,"notes":"x","fields":[{"name":"x","value":"x","type":1},{"name":"x","value":"y","type":1}]}),
        ] {
            assert!(serde_json::from_value::<Item>(input)
                .unwrap()
                .validate()
                .is_err());
        }
        for input in [
            json!({"name":"fixture","type":3,"card":{"number":"1234"}}),
            json!({"name":"fixture","type":4,"identity":{"firstName":"Yamada"}}),
            json!({"name":"fixture","type":2,"notes":"fixture"}),
        ] {
            serde_json::from_value::<Item>(input)
                .unwrap()
                .validate()
                .unwrap();
        }
    }
}
