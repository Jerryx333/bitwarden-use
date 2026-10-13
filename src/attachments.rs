//! Bitwarden's binary AES-256-CBC/HMAC-SHA256 attachment format.
use crate::{cipherstring::CipherString, locked::Keys};

pub fn encrypt(
    keys: &Keys,
    plaintext: &[u8],
) -> crate::prelude::Result<Vec<u8>> {
    let CipherString::Symmetric {
        iv,
        ciphertext,
        mac: Some(mac),
    } = CipherString::encrypt_symmetric(keys, plaintext)?
    else {
        unreachable!()
    };
    let mut result = vec![2];
    result.extend(iv);
    result.extend(mac);
    result.extend(ciphertext);
    Ok(result)
}

pub fn decrypt(
    keys: &Keys,
    encrypted: &[u8],
) -> crate::prelude::Result<Vec<u8>> {
    if encrypted.len() < 65
        || encrypted[0] != 2
        || (encrypted.len() - 49) % 16 != 0
    {
        return Err(crate::error::Error::UnsafeWrite {
            message: "invalid encrypted attachment format".into(),
        });
    }
    CipherString::Symmetric {
        iv: encrypted[1..17].to_vec(),
        mac: Some(encrypted[17..49].to_vec()),
        ciphertext: encrypted[49..].to_vec(),
    }
    .decrypt_symmetric(keys, None)
}

#[cfg(test)]
mod tests {
    use super::*;
    fn keys() -> Keys {
        let mut bytes = crate::locked::Vec::new();
        bytes.extend(0..64);
        Keys::new(bytes)
    }
    #[test]
    fn binary_roundtrip_and_tamper_rejection() {
        for plaintext in
            [&b""[..], &b"\0\xff\x80\r\n"[..], &vec![0xff; 100_000][..]]
        {
            let mut encrypted = encrypt(&keys(), plaintext).unwrap();
            assert_eq!(decrypt(&keys(), &encrypted).unwrap(), plaintext);
            encrypted[17] ^= 1;
            assert!(decrypt(&keys(), &encrypted).is_err());
        }
        for bad in [vec![], vec![2; 64], vec![1; 65], vec![2; 66]] {
            assert!(decrypt(&keys(), &bad).is_err());
        }
    }
}
