use crate::prelude::*;

use std::io::{Read as _, Write as _};

use tokio::io::AsyncReadExt as _;

#[derive(
    serde::Serialize, serde::Deserialize, Debug, Clone, Eq, PartialEq,
)]
pub struct Entry {
    pub id: String,
    pub org_id: Option<String>,
    pub folder: Option<String>,
    pub folder_id: Option<String>,
    pub name: String,
    pub data: EntryData,
    pub fields: Vec<Field>,
    pub notes: Option<String>,
    pub history: Vec<HistoryEntry>,
    pub key: Option<String>,
    pub master_password_reprompt: crate::api::CipherRepromptType,
    #[serde(default)]
    pub attachments: Vec<Attachment>,
}

#[derive(
    serde::Serialize, serde::Deserialize, Debug, Clone, Eq, PartialEq,
)]
pub struct Attachment {
    #[serde(rename = "Id", alias = "id")]
    pub id: String,
    #[serde(rename = "FileName", alias = "fileName")]
    pub file_name: String,
    #[serde(rename = "Key", alias = "key")]
    pub key: Option<String>,
}

impl Entry {
    pub fn master_password_reprompt(&self) -> bool {
        self.master_password_reprompt != crate::api::CipherRepromptType::None
    }
}

#[derive(serde::Serialize, Debug, Clone, Eq, PartialEq)]
pub struct Uri {
    pub uri: String,
    pub match_type: Option<crate::api::UriMatchType>,
}

// backwards compatibility
impl<'de> serde::Deserialize<'de> for Uri {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        struct StringOrUri;
        impl<'de> serde::de::Visitor<'de> for StringOrUri {
            type Value = Uri;

            fn expecting(
                &self,
                formatter: &mut std::fmt::Formatter,
            ) -> std::fmt::Result {
                formatter.write_str("uri")
            }

            fn visit_str<E>(
                self,
                value: &str,
            ) -> std::result::Result<Self::Value, E>
            where
                E: serde::de::Error,
            {
                Ok(Uri {
                    uri: value.to_string(),
                    match_type: None,
                })
            }

            fn visit_map<M>(
                self,
                mut map: M,
            ) -> std::result::Result<Self::Value, M::Error>
            where
                M: serde::de::MapAccess<'de>,
            {
                let mut uri = None;
                let mut match_type = None;
                while let Some(key) = map.next_key()? {
                    match key {
                        "uri" => {
                            if uri.is_some() {
                                return Err(
                                    serde::de::Error::duplicate_field("uri"),
                                );
                            }
                            uri = Some(map.next_value()?);
                        }
                        "match_type" => {
                            if match_type.is_some() {
                                return Err(
                                    serde::de::Error::duplicate_field(
                                        "match_type",
                                    ),
                                );
                            }
                            match_type = map.next_value()?;
                        }
                        _ => {
                            return Err(serde::de::Error::unknown_field(
                                key,
                                &["uri", "match_type"],
                            ))
                        }
                    }
                }

                uri.map_or_else(
                    || Err(serde::de::Error::missing_field("uri")),
                    |uri| Ok(Self::Value { uri, match_type }),
                )
            }
        }

        deserializer.deserialize_any(StringOrUri)
    }
}

#[derive(
    serde::Serialize, serde::Deserialize, Debug, Clone, Eq, PartialEq,
)]
pub enum EntryData {
    Login {
        username: Option<String>,
        password: Option<String>,
        totp: Option<String>,
        uris: Vec<Uri>,
        // passkeys / webauthn credentials attached to this login. defaulted so
        // that databases cached by older versions of rbw (which did not store
        // this field) still deserialize cleanly.
        #[serde(default)]
        fido2_credentials: Vec<Fido2Credential>,
    },
    Card {
        cardholder_name: Option<String>,
        number: Option<String>,
        brand: Option<String>,
        exp_month: Option<String>,
        exp_year: Option<String>,
        code: Option<String>,
    },
    Identity {
        title: Option<String>,
        first_name: Option<String>,
        middle_name: Option<String>,
        last_name: Option<String>,
        address1: Option<String>,
        address2: Option<String>,
        address3: Option<String>,
        city: Option<String>,
        state: Option<String>,
        postal_code: Option<String>,
        country: Option<String>,
        phone: Option<String>,
        email: Option<String>,
        ssn: Option<String>,
        license_number: Option<String>,
        passport_number: Option<String>,
        username: Option<String>,
    },
    SecureNote,
    SshKey {
        private_key: Option<String>,
        public_key: Option<String>,
        fingerprint: Option<String>,
    },
}

#[derive(
    serde::Serialize, serde::Deserialize, Debug, Clone, Eq, PartialEq,
)]
pub struct Field {
    pub ty: Option<crate::api::FieldType>,
    pub name: Option<String>,
    pub value: Option<String>,
    pub linked_id: Option<crate::api::LinkedIdType>,
}

// A FIDO2 (passkey) credential attached to a login entry. credential_id,
// key_type, key_algorithm, key_curve and creation_date are stored in the
// clear; key_value (the PKCS#8 private key, base64url-encoded), rp_id,
// user_handle and the other sensitive fields are EncStrings and must be
// decrypted with the same per-entry/org key as the rest of the login.
#[derive(
    serde::Serialize, serde::Deserialize, Debug, Clone, Eq, PartialEq,
)]
pub struct Fido2Credential {
    pub credential_id: Option<String>,
    pub key_type: Option<String>,
    pub key_algorithm: Option<String>,
    pub key_curve: Option<String>,
    pub key_value: Option<String>,
    pub rp_id: Option<String>,
    pub rp_name: Option<String>,
    pub user_handle: Option<String>,
    pub user_name: Option<String>,
    pub counter: Option<String>,
    pub discoverable: Option<String>,
    pub creation_date: Option<String>,
}

#[derive(
    serde::Serialize, serde::Deserialize, Debug, Clone, Eq, PartialEq,
)]
pub struct HistoryEntry {
    pub last_used_date: String,
    pub password: String,
}

#[derive(serde::Serialize, serde::Deserialize, Default, Debug)]
pub struct Db {
    pub access_token: Option<String>,
    pub refresh_token: Option<String>,

    pub kdf: Option<crate::api::KdfType>,
    pub iterations: Option<u32>,
    pub memory: Option<u32>,
    pub parallelism: Option<u32>,
    pub protected_key: Option<String>,
    pub protected_private_key: Option<String>,
    pub protected_org_keys: std::collections::HashMap<String, String>,

    pub entries: Vec<Entry>,
}

impl Db {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn load(server: &str, email: &str) -> Result<Self> {
        let file = crate::dirs::db_file(server, email);
        let mut fh =
            std::fs::File::open(&file).map_err(|source| Error::LoadDb {
                source,
                file: file.clone(),
            })?;
        let mut json = String::new();
        fh.read_to_string(&mut json)
            .map_err(|source| Error::LoadDb {
                source,
                file: file.clone(),
            })?;
        let slf: Self = serde_json::from_str(&json)
            .map_err(|source| Error::LoadDbJson { source, file })?;
        Ok(slf)
    }

    pub async fn load_async(server: &str, email: &str) -> Result<Self> {
        let file = crate::dirs::db_file(server, email);
        let mut fh =
            tokio::fs::File::open(&file).await.map_err(|source| {
                Error::LoadDbAsync {
                    source,
                    file: file.clone(),
                }
            })?;
        let mut json = String::new();
        fh.read_to_string(&mut json).await.map_err(|source| {
            Error::LoadDbAsync {
                source,
                file: file.clone(),
            }
        })?;
        let slf: Self = serde_json::from_str(&json)
            .map_err(|source| Error::LoadDbJson { source, file })?;
        Ok(slf)
    }

    pub fn save(&self, server: &str, email: &str) -> Result<()> {
        let file = crate::dirs::db_file(server, email);
        let json = zeroize::Zeroizing::new(
            serde_json::to_vec(self).map_err(|source| Error::SaveDbJson {
                source,
                file: file.clone(),
            })?,
        );
        save_atomic(&file, &json)
    }

    pub async fn save_async(&self, server: &str, email: &str) -> Result<()> {
        let file = crate::dirs::db_file(server, email);
        let json = zeroize::Zeroizing::new(
            serde_json::to_vec(self).map_err(|source| Error::SaveDbJson {
                source,
                file: file.clone(),
            })?,
        );
        let destination = file.clone();
        tokio::task::spawn_blocking(move || save_atomic(&destination, &json))
            .await
            .map_err(|source| Error::SaveDbAsync {
                source: std::io::Error::other(source),
                file,
            })?
    }

    pub fn remove(server: &str, email: &str) -> Result<()> {
        let file = crate::dirs::db_file(server, email);
        let res = std::fs::remove_file(&file);
        if let Err(e) = &res {
            if e.kind() == std::io::ErrorKind::NotFound {
                return Ok(());
            }
        }
        res.map_err(|source| Error::RemoveDb { source, file })?;
        Ok(())
    }

    /// Whether the encrypted vault can be unlocked without the server.
    pub fn has_offline_cache(&self) -> bool {
        self.kdf.is_some()
            && self.iterations.is_some()
            && self.protected_key.is_some()
            && self.protected_private_key.is_some()
    }

    pub fn needs_login(&self) -> bool {
        self.access_token.is_none()
            || self.refresh_token.is_none()
            || self.iterations.is_none()
            || self.kdf.is_none()
            || self.protected_key.is_none()
    }
}

/// Readers must see either complete snapshot, never a truncated file.
fn save_atomic(file: &std::path::Path, json: &[u8]) -> Result<()> {
    let parent = file.parent().unwrap();
    let error = |source| Error::SaveDb {
        source,
        file: file.to_owned(),
    };
    std::fs::create_dir_all(parent).map_err(error)?;
    let mut temporary =
        tempfile::NamedTempFile::new_in(parent).map_err(error)?;
    temporary.write_all(json).map_err(error)?;
    temporary.as_file().sync_all().map_err(error)?;
    temporary.persist(file).map_err(|e| error(e.error))?;
    Ok(())
}

#[cfg(test)]
mod atomic_tests {
    use super::*;
    #[test]
    fn concurrent_reads_never_observe_partial_cache_and_permissions_are_private(
    ) {
        use std::os::unix::fs::PermissionsExt as _;
        use std::sync::{
            atomic::{AtomicBool, Ordering},
            Arc,
        };
        let directory = tempfile::tempdir().unwrap();
        let file = directory.path().join("synthetic-cache.json");
        save_atomic(&file, b"{}").unwrap();
        let active = Arc::new(AtomicBool::new(true));
        let reading = active.clone();
        let path = file.clone();
        let reader = std::thread::spawn(move || {
            let mut reads = 0;
            while reading.load(Ordering::Relaxed) {
                let bytes = std::fs::read(&path).unwrap();
                let _: serde_json::Value =
                    serde_json::from_slice(&bytes).unwrap();
                reads += 1;
            }
            reads
        });
        for index in 0..50 {
            let data = serde_json::to_vec(&serde_json::json!({"index":index,"fixture":"x".repeat(128 * 1024)})).unwrap();
            save_atomic(&file, &data).unwrap();
        }
        active.store(false, Ordering::Relaxed);
        assert!(reader.join().unwrap() > 0);
        assert_eq!(
            std::fs::metadata(&file).unwrap().permissions().mode() & 0o777,
            0o600
        );
    }
}
