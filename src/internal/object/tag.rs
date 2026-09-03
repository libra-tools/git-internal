//! In Git objects there are two types of tags: Lightweight tags and annotated tags.
//!
//! A lightweight tag is simply a pointer to a specific commit in Git's version history,
//! without any additional metadata or information associated with it. It is created by
//! running the `git tag` command with a name for the tag and the commit hash that it points to.
//!
//! An annotated tag, on the other hand, is a Git object in its own right, and includes
//! metadata such as the tagger's name and email address, the date and time the tag was created,
//! and a message describing the tag. It is created by running the `git tag -a` command with
//! a name for the tag, the commit hash that it points to, and the additional metadata that
//! should be associated with the tag.
//!
//! When you create a tag in Git, whether it's a lightweight or annotated tag, Git creates a
//! new object in its object database to represent the tag. This object includes the name of the
//! tag, the hash of the commit it points to, and any additional metadata associated with the
//! tag (in the case of an annotated tag).
//!
//! There is no difference in binary format between lightweight tags and annotated tags in Git,
//! as both are represented using the same lightweight object format in Git's object database.
//!
//! The lightweight tag is a reference to a specific commit in Git's version history, not be stored
//! as a separate object in Git's object database. This means that if you create a lightweight tag
//! and then move the tag to a different commit, the tag will still point to the original commit.
//!
//! The lightweight just a text file with the commit hash in it, and the file name is the tag name.
//! If one of -a, -s, or -u \<key-id\> is passed, the command creates a tag object, and requires a tag
//! message. Unless -m \<msg\> or -F \<file\> is given, an editor is started for the user to type in the
//! tag message.
//!
//! ```bash
//! 4b00093bee9b3ef5afc5f8e3645dc39cfa2f49aa
//! ```
//!
//! The annotated tag is a Git object in its own right, and includes metadata such as the tagger's
//! name and email address, the date and time the tag was created, and a message describing the tag.
//!
//! So, we can use the `git cat-file -p <tag>` command to get the tag object, and the command not
//! for the lightweight tag.
use std::fmt::Display;

use bstr::ByteSlice;

use crate::{
    errors::GitError,
    hash::{HashKind, ObjectHash},
    internal::object::{ObjectTrait, ObjectType, signature::Signature},
};

/// The tag object is used to Annotated tag
#[derive(Eq, Debug, Clone)]
pub struct Tag {
    pub id: ObjectHash,
    pub object_hash: ObjectHash,
    pub object_type: ObjectType,
    pub tag_name: String,
    pub tagger: Signature,
    pub message: String,
}

impl PartialEq for Tag {
    fn eq(&self, other: &Self) -> bool {
        self.id == other.id
    }
}

impl Display for Tag {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "object {}\ntype {}\ntag {}\ntagger {}\n\n{}",
            self.object_hash, self.object_type, self.tag_name, self.tagger, self.message
        )
    }
}

impl Tag {
    // pub fn new_from_meta(meta: Meta) -> Result<Tag, GitError> {
    //     Ok(Tag::new_from_data(meta.data))
    // }

    // pub fn new_from_file(path: &str) -> Result<Tag, GitError> {
    //     let meta = Meta::new_from_file(path)?;
    //     Tag::new_from_meta(meta)
    // }

    /// Create an annotated tag and derive its ID with an explicit repository `kind`.
    ///
    /// Does not consult the thread-local [`HashKind`]. `object_hash` must
    /// belong to `kind`; a cross-kind reference fails closed with
    /// [`GitError::InvalidHashValue`]. Never panics.
    pub fn new_with_kind(
        kind: HashKind,
        object_hash: ObjectHash,
        object_type: ObjectType,
        tag_name: String,
        tagger: Signature,
        message: String,
    ) -> Result<Self, GitError> {
        object_hash.ensure_kind(kind)?;
        let mut tag = Self {
            id: ObjectHash::zero_for_kind(kind),
            object_hash,
            object_type,
            tag_name,
            tagger,
            message,
        };
        let data = tag.to_data()?;
        tag.id = ObjectHash::from_type_and_data_for_kind(kind, ObjectType::Tag, &data)?;
        Ok(tag)
    }

    /// Create an annotated tag using the thread-local [`HashKind`]; see [`Tag::new_with_kind`].
    pub fn new(
        object_hash: ObjectHash,
        object_type: ObjectType,
        tag_name: String,
        tagger: Signature,
        message: String,
    ) -> Self {
        let mut tag = Self {
            id: ObjectHash::default(),
            object_hash,
            object_type,
            tag_name,
            tagger,
            message,
        };
        // The id is the canonical git object hash of the *serialized* tag
        // (`to_data()`), computed exactly like `Commit::new`. Previously this
        // hashed a hand-written `format!` string that interpolated the tagger via
        // `Signature`'s `Display` (a human-readable `"<name> <<email>>\nDate: …"`
        // form) rather than `Signature::to_data()` (`"tagger <name> <<email>>
        // <timestamp> <tz>"`). That made `id != hash(to_data())`, so the bytes
        // libra stores/packs hash to a *different* OID than the ref points at —
        // breaking every packfile round-trip (fetch/push/repack) of annotated
        // tags. Hashing `to_data()` keeps the id canonical.
        tag.id = ObjectHash::from_type_and_data(ObjectType::Tag, &tag.to_data().unwrap());
        tag
    }
}

impl ObjectTrait for Tag {
    /// The tag object is used to Annotated tag, it's binary format is:
    ///
    /// ```bash
    /// object <object_hash> 0x0a # The SHA-1 hash of the object that the annotated tag is attached to (usually a commit)
    /// type <object_type> 0x0a #The type of Git object that the annotated tag is attached to (usually 'commit')
    /// tag <tag_name> 0x0a # The name of the annotated tag(in UTF-8 encoding)
    /// tagger <tagger> 0x0a # The name, email address, and date of the person who created the annotated tag
    /// <message>
    /// ```
    fn from_bytes(row_data: &[u8], hash: ObjectHash) -> Result<Self, GitError>
    where
        Self: Sized,
    {
        let mut headers = row_data;
        let mut message_start = 0;

        if let Some(pos) = headers.find(b"\n\n") {
            message_start = pos + 2;
            headers = &headers[..pos];
        }

        let mut object_hash: Option<ObjectHash> = None;
        let mut object_type: Option<ObjectType> = None;
        let mut tag_name: Option<String> = None;
        let mut tagger: Option<Signature> = None;

        for line in headers.lines() {
            if let Some(s) = line.strip_prefix(b"object ") {
                let hash_str = s.to_str().map_err(|_| {
                    GitError::InvalidTagObject(format!(
                        "Invalid UTF-8 in object hash (from_bytes: expected {} {} hex chars, got {} bytes)",
                        hash.kind().hex_len(),
                        hash.kind(),
                        s.len()
                    ))
                })?;
                // The referenced object belongs to the tag's own repository kind; never
                // infer the algorithm from the hex length.
                object_hash = Some(
                    ObjectHash::from_hex_for_kind(hash.kind(), hash_str).map_err(|e| {
                        GitError::InvalidTagObject(format!("Invalid object hash format: {e}"))
                    })?,
                );
            } else if let Some(s) = line.strip_prefix(b"type ") {
                let type_str = s.to_str().map_err(|_| {
                    GitError::InvalidTagObject("Invalid UTF-8 in object type".to_string())
                })?;
                object_type = Some(ObjectType::from_string(type_str)?);
            } else if let Some(s) = line.strip_prefix(b"tag ") {
                let tag_str = s.to_str().map_err(|_| {
                    GitError::InvalidTagObject("Invalid UTF-8 in tag name".to_string())
                })?;
                tag_name = Some(tag_str.to_string());
            } else if line.starts_with(b"tagger ") {
                tagger = Some(Signature::from_data(line.to_vec())?);
            }
        }

        let message = if message_start > 0 {
            String::from_utf8_lossy(&row_data[message_start..]).to_string()
        } else {
            String::new()
        };

        Ok(Tag {
            id: hash,
            object_hash: object_hash
                .ok_or_else(|| GitError::InvalidTagObject("Missing object hash".to_string()))?,
            object_type: object_type
                .ok_or_else(|| GitError::InvalidTagObject("Missing object type".to_string()))?,
            tag_name: tag_name
                .ok_or_else(|| GitError::InvalidTagObject("Missing tag name".to_string()))?,
            tagger: tagger
                .ok_or_else(|| GitError::InvalidTagObject("Missing tagger".to_string()))?,
            message,
        })
    }

    fn get_type(&self) -> ObjectType {
        ObjectType::Tag
    }

    fn get_size(&self) -> usize {
        self.to_data().map(|data| data.len()).unwrap_or(0)
    }

    ///
    /// ```bash
    /// object <object_hash> 0x0a # The SHA-1/ SHA-256 hash of the object that the annotated tag is attached to (usually a commit)
    /// type <object_type> 0x0a #The type of Git object that the annotated tag is attached to (usually 'commit')
    /// tag <tag_name> 0x0a # The name of the annotated tag(in UTF-8 encoding)
    /// tagger <tagger> 0x0a # The name, email address, and date of the person who created the annotated tag
    /// <message>
    /// ```
    /// When using SHA-1, `<object_hash>` is 40 hex chars; when using SHA-256, it is 64 hex chars.
    fn to_data(&self) -> Result<Vec<u8>, GitError> {
        let mut data = Vec::new();

        data.extend_from_slice(b"object ");
        data.extend_from_slice(self.object_hash.to_string().as_bytes());
        data.extend_from_slice(b"\n");

        data.extend_from_slice(b"type ");
        data.extend_from_slice(self.object_type.to_string().as_bytes());
        data.extend_from_slice(b"\n");

        data.extend_from_slice(b"tag ");
        data.extend_from_slice(self.tag_name.as_bytes());
        data.extend_from_slice(b"\n");

        data.extend_from_slice(&self.tagger.to_data()?);
        data.extend_from_slice(b"\n\n");

        data.extend_from_slice(self.message.as_bytes());

        Ok(data)
    }
}

#[cfg(test)]
mod tests {
    use std::str::FromStr;

    use super::*;
    use crate::{
        hash::{HashKind, ObjectHash, set_hash_kind_for_test},
        internal::object::signature::{Signature, SignatureType},
    };

    /// Helper to build a deterministic signature for tests.
    fn make_sig() -> Signature {
        Signature::new(
            SignatureType::Tagger,
            "tagger".to_string(),
            "tagger@example.com".to_string(),
        )
    }

    /// `1234567890abcdef…` repeated to the width of `kind` (no exhaustive `HashKind` match,
    /// so adding a variant does not break this helper).
    fn pattern_id(kind: HashKind) -> ObjectHash {
        let bytes: Vec<u8> = [0x12u8, 0x34, 0x56, 0x78, 0x90, 0xab, 0xcd, 0xef]
            .iter()
            .cycle()
            .take(kind.size())
            .copied()
            .collect();
        ObjectHash::from_bytes_for_kind(kind, &bytes).unwrap()
    }

    /// Tag creation should serialize/deserialize correctly under the given hash kind.
    fn round_trip(kind: HashKind) {
        let _guard = set_hash_kind_for_test(kind);
        let target = pattern_id(kind);
        let sig = make_sig();
        let tag = Tag::new(
            target,
            ObjectType::Commit,
            "v1.0.0".to_string(),
            sig.clone(),
            "release".to_string(),
        );

        let data = tag.to_data().unwrap();
        let parsed = Tag::from_bytes(&data, tag.id).unwrap();

        assert_eq!(parsed.id, tag.id);
        assert_eq!(parsed.object_hash, target);
        assert_eq!(parsed.object_type, ObjectType::Commit);
        assert_eq!(parsed.tag_name, "v1.0.0");
        assert_eq!(parsed.message, "release");
        assert_eq!(parsed.tagger.to_string(), sig.to_string());
    }

    /// Tag round trip tests for both SHA-1 and SHA-256 hash kinds.
    #[tokio::test]
    async fn tag_round_trip() {
        round_trip(HashKind::Sha1);
        round_trip(HashKind::Sha256);
    }

    /// Regression: a tag's `id` MUST equal the canonical git object hash of its
    /// serialized (`to_data()`) form. Before the fix, `Tag::new` hashed a
    /// `Display`-based string (which renders the tagger as a human-readable
    /// `"<name> <<email>>\nDate: <chrono-date> <tz>"`) instead of `to_data()`
    /// (`"tagger <name> <<email>> <timestamp> <tz>"`), so `id != hash(to_data())`.
    /// The object was then stored/packed under different bytes than its id —
    /// breaking every packfile round-trip (fetch/push/repack) of annotated tags.
    #[test]
    fn tag_id_is_canonical_hash_of_to_data() {
        for kind in [HashKind::Sha1, HashKind::Sha256] {
            let _guard = set_hash_kind_for_test(kind);
            let target = pattern_id(kind);
            let tag = Tag::new(
                target,
                ObjectType::Commit,
                "v1.0.0".to_string(),
                make_sig(),
                "release".to_string(),
            );
            let canonical =
                ObjectHash::from_type_and_data(ObjectType::Tag, &tag.to_data().unwrap());
            assert_eq!(
                tag.id, canonical,
                "tag id must be the canonical hash of its to_data() bytes ({kind:?})"
            );
        }
    }

    /// Invalid tag missing required fields should error.
    #[test]
    fn tag_invalid_missing_fields_errors() {
        let _guard = set_hash_kind_for_test(HashKind::Sha1);
        let bad = b"type commit\ntag v1.0.0\n\nno object line".to_vec();
        let hash = ObjectHash::from_str("ffffffffffffffffffffffffffffffffffffffff").unwrap();
        assert!(Tag::from_bytes(&bad, hash).is_err());
    }
}
