//! Encryption at rest to the mailbox owner's OpenPGP key (Pinal Mail's
//! zero-access encryption).
//!
//! When an account has a public key, mail delivered to it is stored as
//! PGP/MIME (RFC 3156): the message's own headers stay outside, readable for
//! listing and threading, and its MIME headers and body go inside, encrypted
//! to the owner's key (SEIPD v1 with AES-256, never compressed). Only the
//! owner's devices hold the private key, so the server can't read stored
//! mail again. This is the format the Picacho app opens
//! (`manage/crypto.rs`, `open_message`): outer headers, then the decrypted
//! part appended to them, is the original message.
//!
//! Filters run before encryption, so Sieve, spam scoring, forwarding and
//! vacation replies still see the message as it arrived. Mail its sender
//! already encrypted (PGP/MIME, inline PGP, S/MIME) is stored as it is.
//! Messages the owner files themselves (IMAP APPEND, JMAP import: drafts,
//! sent copies) aren't encrypted here.
use crate::state::State;
use pgp::composed::{ArmorOptions, Deserializable, MessageBuilder, SignedPublicKey, SignedPublicSubKey};
use pgp::crypto::sym::SymmetricKeyAlgorithm;
use pgp::ser::Serialize;
use pgp::types::KeyDetails;

/// A usable recipient key: (key, uppercase hex fingerprint).
pub fn parse_key(armored: &str) -> Result<(SignedPublicKey, String), String> {
    if armored.len() > 256 * 1024 {
        return Err("That key is too large.".into());
    }
    let (key, _) = SignedPublicKey::from_string(armored.trim()).map_err(|_| "That isn't an OpenPGP public key (armored, -----BEGIN PGP PUBLIC KEY BLOCK-----).".to_string())?;
    key.verify_bindings().map_err(|e| format!("The key's signatures don't verify: {e}"))?;
    if encryption_subkeys(&key).is_empty() && !key.primary_key.algorithm().can_encrypt() {
        return Err("This key can't encrypt (it has no encryption subkey).".into());
    }
    let fp = format!("{:X}", key.fingerprint());
    Ok((key, fp))
}

/// The account's key as the Web Key Directory serves it for `email`:
/// binary, with only the User IDs for that address (none of the owner's
/// other addresses, no photo IDs, as GnuPG's `keep-uid=mbox=` export
/// filter does), or None when no User ID names it.
pub fn wkd_key(armored: &str, email: &str) -> Option<Vec<u8>> {
    let (mut key, _) = parse_key(armored).ok()?;
    let email = email.trim().to_lowercase();
    key.details.users.retain(|u| user_id_address(u.id.id()) == email);
    if key.details.users.is_empty() {
        return None;
    }
    key.details.user_attributes.clear();
    key.to_bytes().ok()
}

/// The address in a User ID (`Name <addr>` or a bare `addr`), lowercased;
/// the same reading as the Picacho app's `has_address`.
fn user_id_address(id: &[u8]) -> String {
    let u = String::from_utf8_lossy(id).to_lowercase();
    match (u.rfind('<'), u.rfind('>')) {
        (Some(a), Some(b)) if a < b => u[a + 1..b].to_string(),
        _ => u.trim().to_string(),
    }
}

fn encryption_subkeys(key: &SignedPublicKey) -> Vec<&SignedPublicSubKey> {
    key.public_subkeys
        .iter()
        .filter(|k| k.signatures.iter().any(|s| s.key_flags().encrypt_comms() || s.key_flags().encrypt_storage()))
        .collect()
}

/// Mail its sender already encrypted or signed opaquely: stored as it is.
/// The same test as the Picacho app's `sender_encrypted`.
pub fn sender_encrypted(raw: &[u8]) -> bool {
    let head = &raw[..raw.len().min(256 * 1024)];
    let root = crate::mime::parse(head);
    let ctype = format!("{}/{}", root.ctype, root.csub).to_ascii_lowercase();
    let p7 = root.param("name").is_some_and(|n| {
        let n = n.to_ascii_lowercase();
        [".p7m", ".p7s", ".p7c", ".p7z"].iter().any(|e| n.ends_with(e))
    });
    matches!(ctype.as_str(), "multipart/encrypted" | "application/pkcs7-mime" | "application/x-pkcs7-mime" | "application/pkcs7-signature")
        || (ctype == "application/octet-stream" && p7)
        || String::from_utf8_lossy(root.body_bytes(head)).trim_start().starts_with("-----BEGIN PGP MESSAGE-----")
}

/// The message as PGP/MIME, its non-MIME headers outside.
pub fn encrypt_message(raw: &[u8], key: &SignedPublicKey) -> anyhow::Result<Vec<u8>> {
    let root = crate::mime::parse(raw);
    let (mut outer, mut inner) = (Vec::with_capacity(1024), Vec::with_capacity(raw.len() + 64));
    for f in root.fields.iter().filter(|f| !f.name.is_empty()) {
        let name = f.name.to_ascii_lowercase();
        let mut line = raw[f.start..f.end].to_vec();
        if !line.ends_with(b"\n") {
            line.extend_from_slice(b"\r\n");
        }
        if name.starts_with("content-") {
            inner.extend_from_slice(&line);
        } else if name != "mime-version" {
            outer.extend_from_slice(&line);
        }
    }
    if !root.fields.iter().any(|f| f.name.eq_ignore_ascii_case("content-type")) {
        inner.extend_from_slice(b"Content-Type: text/plain; charset=us-ascii\r\n");
    }
    inner.extend_from_slice(b"\r\n");
    inner.extend_from_slice(root.body_bytes(raw));

    let mut rng = rand08::thread_rng();
    let mut builder = MessageBuilder::from_bytes("", inner).seipd_v1(&mut rng, SymmetricKeyAlgorithm::AES256);
    let subkeys = encryption_subkeys(key);
    if subkeys.is_empty() {
        builder.encrypt_to_key(&mut rng, &key.primary_key)?;
    } else {
        for k in subkeys {
            builder.encrypt_to_key(&mut rng, k)?;
        }
    }
    let armored = builder.to_armored_string(&mut rng, ArmorOptions::default())?;
    let boundary = format!("pgp-{}", crate::util::random_token());
    outer.extend_from_slice(b"MIME-Version: 1.0\r\n");
    outer.extend_from_slice(
        format!(
            "Content-Type: multipart/encrypted; protocol=\"application/pgp-encrypted\"; boundary=\"{boundary}\"\r\n\r\n\
             This is an OpenPGP/MIME encrypted message (RFC 4880 and 3156)\r\n\
             --{boundary}\r\nContent-Type: application/pgp-encrypted\r\nContent-Description: PGP/MIME version identification\r\n\r\nVersion: 1\r\n\r\n\
             --{boundary}\r\nContent-Type: application/octet-stream; name=\"encrypted.asc\"\r\nContent-Description: OpenPGP encrypted message\r\n\
             Content-Disposition: inline; filename=\"encrypted.asc\"\r\n\r\n{}\r\n--{boundary}--\r\n",
            armored.replace("\r\n", "\n").replace('\n', "\r\n").trim_end()
        )
        .as_bytes(),
    );
    Ok(outer)
}

/// What to store for a message delivered to `account_id`: encrypted when
/// the account has a key, else the message itself.
pub async fn for_storage(state: &State, account_id: i64, raw: &[u8]) -> anyhow::Result<std::borrow::Cow<'static, [u8]>> {
    let Some(armored) = state.db.encryption_key(account_id).await? else {
        return Ok(std::borrow::Cow::Owned(raw.to_vec()));
    };
    if sender_encrypted(raw) {
        return Ok(std::borrow::Cow::Owned(raw.to_vec()));
    }
    let raw = raw.to_vec();
    let out = tokio::task::spawn_blocking(move || -> anyhow::Result<Vec<u8>> {
        let (key, _) = parse_key(&armored).map_err(|e| anyhow::anyhow!(e))?;
        encrypt_message(&raw, &key)
    })
    .await??;
    Ok(std::borrow::Cow::Owned(out))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key_for(primary: &str, others: &[&str]) -> String {
        use pgp::composed::{EncryptionCaps, KeyType, SecretKeyParamsBuilder, SubkeyParamsBuilder};
        use pgp::crypto::ecc_curve::ECCCurve;
        let mut encrypt = SubkeyParamsBuilder::default();
        encrypt.key_type(KeyType::ECDH(ECCCurve::Curve25519Legacy)).can_sign(false).can_encrypt(EncryptionCaps::All);
        let mut params = SecretKeyParamsBuilder::default();
        params
            .key_type(KeyType::Ed25519Legacy)
            .can_certify(true)
            .can_sign(true)
            .can_encrypt(EncryptionCaps::None)
            .primary_user_id(primary.into())
            .user_ids(others.iter().map(|s| s.to_string()).collect())
            .subkeys(vec![encrypt.build().unwrap()]);
        let secret = params.build().unwrap().generate(rand08::thread_rng()).unwrap();
        SignedPublicKey::from(secret).to_armored_string(ArmorOptions::default()).unwrap()
    }

    #[test]
    fn wkd_key_keeps_only_the_requested_address() {
        let armored = key_for("Amy <amy@example.test>", &["amy.private@elsewhere.test", "Amy Sales <SALES@example.test>"]);
        let (full, fp) = parse_key(&armored).unwrap();
        assert_eq!(full.details.users.len(), 3);

        let bytes = wkd_key(&armored, "Sales@Example.test").unwrap();
        assert_ne!(bytes.first(), Some(&b'-'), "binary, not armored");
        let served = SignedPublicKey::from_bytes(&bytes[..]).unwrap();
        served.verify_bindings().unwrap();
        assert_eq!(format!("{:X}", served.fingerprint()), fp);
        let ids: Vec<String> = served.details.users.iter().map(|u| String::from_utf8_lossy(u.id.id()).into_owned()).collect();
        assert_eq!(ids, ["Amy Sales <SALES@example.test>"]);
        assert_eq!(served.public_subkeys.len(), 1, "the encryption subkey goes along");

        let bare = SignedPublicKey::from_bytes(&wkd_key(&armored, "amy.private@elsewhere.test").unwrap()[..]).unwrap();
        assert_eq!(bare.details.users.len(), 1);
        assert!(wkd_key(&armored, "bob@example.test").is_none(), "no User ID for the address: nothing published");
        assert!(wkd_key(&armored, "my@example.test").is_none(), "a suffix of an address isn't it");
    }
}
