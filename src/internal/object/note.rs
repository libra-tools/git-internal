//! Git Note object implementation
//!
//! Git Notes are a mechanism for adding metadata to existing Git objects (usually commits)
//! without modifying the original objects. Notes are commonly used for:
//!
//! - Adding review comments or approval metadata
//! - Storing CI/CD build status and code scan results  
//! - Attaching author signatures, annotations, or other metadata
//!
//! In Git's object model, Notes are stored as Blob objects, with the association between
//! notes and target objects managed through the refs/notes/* namespace.

use std::fmt::Display;

use crate::{
    errors::GitError,
    hash::{HashKind, ObjectHash},
    internal::object::{ObjectTrait, ObjectType},
};

/// Git Note object structure
///
/// A Note represents additional metadata attached to a Git object (typically a commit).
/// The Note itself is stored as a Blob object in Git's object database, with the
/// association managed through Git's reference system.
#[derive(
    Eq,
    Debug,
    Clone,
    serde::Serialize,
    serde::Deserialize,
    rkyv::Archive,
    rkyv::Serialize,
    rkyv::Deserialize,
)]
pub struct Note {
    /// The ObjectHash of this Note object (same as the underlying Blob)
    pub id: ObjectHash,
    /// The ObjectHash of the object this Note annotates (usually a commit)
    pub target_object_id: ObjectHash,
    /// The textual content of the Note
    pub content: String,
}

impl PartialEq for Note {
    /// Two Notes are equal if they have the same ID
    fn eq(&self, other: &Self) -> bool {
        self.id == other.id
    }
}

impl Display for Note {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        writeln!(f, "Note for object: {}", self.target_object_id)?;
        writeln!(f, "Content: {}", self.content)
    }
}

impl Note {
    /// Create a new Note for the specified target object with the given content
    ///
    /// # Arguments
    /// * `target_object_id` - The ObjectHash of the object to annotate
    /// * `content` - The textual content of the note
    ///
    /// Create a Note for `target_object_id` with an explicit repository `kind`.
    ///
    /// Notes are hashed as blobs. Does not consult the thread-local
    /// [`HashKind`]; the target ID must belong to `kind`, otherwise the call
    /// fails closed with [`GitError::InvalidHashValue`]. Never panics.
    pub fn new_with_kind(
        kind: HashKind,
        target_object_id: ObjectHash,
        content: String,
    ) -> Result<Self, GitError> {
        target_object_id.ensure_kind(kind)?;
        let id =
            ObjectHash::from_type_and_data_for_kind(kind, ObjectType::Blob, content.as_bytes())?;
        Ok(Self {
            id,
            target_object_id,
            content,
        })
    }

    /// Create a Note with a placeholder (zero) target of an explicit repository `kind`.
    ///
    /// The placeholder target is [`ObjectHash::zero_for_kind`] so that it has the
    /// right width for the repository; see [`Note::from_content`] for the
    /// thread-local variant.
    pub fn from_content_with_kind(kind: HashKind, content: &str) -> Result<Self, GitError> {
        Self::new_with_kind(kind, ObjectHash::zero_for_kind(kind), content.to_string())
    }

    /// # Returns
    /// A new Note instance with calculated ID based on the content
    ///
    /// Uses the thread-local [`HashKind`]; see [`Note::new_with_kind`].
    pub fn new(target_object_id: ObjectHash, content: String) -> Self {
        // Calculate the SHA-1/ SHA-256 hash for this Note's content
        // Notes are stored as Blob objects in Git
        let id = ObjectHash::from_type_and_data(ObjectType::Blob, content.as_bytes());

        Self {
            id,
            target_object_id,
            content,
        }
    }

    /// Create a Note from content string, with default target object
    ///
    /// This is a convenience method for creating Notes when the target
    /// will be set later by the notes management system.
    ///
    /// # Arguments
    /// * `content` - The textual content of the note
    ///
    /// # Returns
    /// A new Note instance with default target object ID
    ///
    /// The default target is the SHA-1 zero ID regardless of the thread-local
    /// kind (legacy behaviour); see [`Note::from_content_with_kind`] for a
    /// kind-correct placeholder.
    pub fn from_content(content: &str) -> Self {
        Self::new(ObjectHash::default(), content.to_string())
    }

    /// Get the size of the Note content in bytes
    pub fn content_size(&self) -> usize {
        self.content.len()
    }

    /// Check if the Note is empty (has no content)
    pub fn is_empty(&self) -> bool {
        self.content.is_empty()
    }

    /// Update the target object ID for this Note
    ///
    /// This method allows changing which object this Note annotates
    /// without changing the Note's content or ID.
    ///
    /// # Arguments
    /// * `new_target` - The new target object SHA-1/ SHA-256 hash
    pub fn set_target(&mut self, new_target: ObjectHash) {
        self.target_object_id = new_target;
    }

    /// Create a Note object from raw bytes with explicit target object ID
    ///
    /// This is the preferred method when you know both the content and the target object,
    /// as it preserves the complete Note association information.
    ///
    /// # Arguments
    /// * `data` - The raw byte data (UTF-8 encoded text content)
    /// * `hash` - The SHA-1/ SHA-256 hash of this Note object
    /// * `target_object_id` - The SHA-1/ SHA-256 hash of the object this Note annotates
    ///
    /// # Returns
    /// A Result containing the Note object with complete association info
    pub fn from_bytes_with_target(
        data: &[u8],
        hash: ObjectHash,
        target_object_id: ObjectHash,
    ) -> Result<Self, GitError> {
        let content = String::from_utf8(data.to_vec())
            .map_err(|e| GitError::InvalidNoteObject(format!("Invalid UTF-8 content: {e}")))?;

        Ok(Note {
            id: hash,
            target_object_id,
            content,
        })
    }

    /// Serialize a Note with its target association for external storage
    ///
    /// This method returns both the Git object data and the target object ID,
    /// which can be used by higher-level systems to manage the refs/notes/* references.
    ///
    /// # Returns
    /// A tuple of (object_data, target_object_id)
    pub fn to_data_with_target(&self) -> Result<(Vec<u8>, ObjectHash), GitError> {
        let data = self.to_data()?;
        Ok((data, self.target_object_id))
    }
}

impl ObjectTrait for Note {
    /// Create a Note object from raw bytes and hash
    ///
    /// # Arguments
    /// * `data` - The raw byte data (UTF-8 encoded text content)
    /// * `hash` - The SHA-1/ SHA-256 hash of this Note object
    ///
    /// # Returns
    /// A Result containing the Note object or an error
    fn from_bytes(data: &[u8], hash: ObjectHash) -> Result<Self, GitError>
    where
        Self: Sized,
    {
        // Convert bytes to UTF-8 string
        let content = String::from_utf8(data.to_vec())
            .map_err(|e| GitError::InvalidNoteObject(format!("Invalid UTF-8 content: {e}")))?;

        Ok(Note {
            id: hash,
            // Target association is managed externally; the placeholder has the
            // width of the note's own repository kind (never a fixed SHA-1 zero).
            target_object_id: ObjectHash::zero_for_kind(hash.kind()),
            content,
        })
    }

    /// Get the Git object type for Notes
    ///
    /// Notes are stored as Blob objects in Git's object database
    fn get_type(&self) -> ObjectType {
        ObjectType::Blob
    }

    /// Get the size of the Note content
    fn get_size(&self) -> usize {
        self.content.len()
    }

    /// Convert the Note to raw byte data for storage
    ///
    /// # Returns
    /// A Result containing the byte representation or an error
    fn to_data(&self) -> Result<Vec<u8>, GitError> {
        Ok(self.content.as_bytes().to_vec())
    }
}

#[cfg(test)]
mod tests {
    use std::str::FromStr;

    use super::*;
    use crate::hash::{HashKind, ObjectHash, set_hash_kind_for_test};

    /// Helper to build a Note, serialize/deserialize with/without target under given hash kind.
    fn round_trip(kind: HashKind) {
        let _guard = set_hash_kind_for_test(kind);
        // `1234567890abcdef…` repeated to the width of `kind`; no exhaustive match on
        // `HashKind`, so adding a variant does not break this helper.
        let pattern: Vec<u8> = [0x12u8, 0x34, 0x56, 0x78, 0x90, 0xab, 0xcd, 0xef]
            .iter()
            .cycle()
            .take(kind.size())
            .copied()
            .collect();
        let target_id = ObjectHash::from_bytes_for_kind(kind, &pattern).unwrap();
        let hash_len = kind.hex_len();
        let content = "This commit needs review".to_string();
        let note = Note::new(target_id, content.clone());

        assert_eq!(note.target_object_id, target_id);
        assert_eq!(note.content, content);
        assert_eq!(note.get_type(), ObjectType::Blob);
        assert_eq!(note.id.to_string().len(), hash_len);

        // serialization without target
        let data = note.to_data().unwrap();
        assert_eq!(data, content.as_bytes());
        assert_eq!(note.get_size(), content.len());

        // basic deserialization (placeholder target has the note's own kind width)
        let basic = Note::from_bytes(&data, note.id).unwrap();
        assert_eq!(basic.content, content);
        assert_eq!(basic.id, note.id);
        assert_eq!(basic.target_object_id, ObjectHash::zero_for_kind(kind));
        assert_eq!(basic.target_object_id.kind(), kind);

        // with target
        let (data_with_target, returned_target) = note.to_data_with_target().unwrap();
        assert_eq!(returned_target, target_id);
        let restored = Note::from_bytes_with_target(&data_with_target, note.id, target_id).unwrap();
        assert_eq!(restored, note);
        assert_eq!(restored.target_object_id, target_id);
        assert_eq!(restored.content, content);
    }

    /// Test round-trip Note serialization/deserialization with SHA-1 and SHA-256
    #[tokio::test]
    async fn note_async_round_trip() {
        round_trip(HashKind::Sha1);
        round_trip(HashKind::Sha256);
    }

    /// Invalid UTF-8 content should return an error in both constructors.
    #[test]
    fn note_invalid_utf8_errors() {
        let _guard = set_hash_kind_for_test(HashKind::Sha1);
        let invalid_utf8 = vec![0xFF, 0xFE, 0xFD];
        let hash = ObjectHash::from_str("3333333333333333333333333333333333333333").unwrap();
        let target = ObjectHash::from_str("4444444444444444444444444444444444444444").unwrap();
        assert!(Note::from_bytes(&invalid_utf8, hash).is_err());
        assert!(Note::from_bytes_with_target(&invalid_utf8, hash, target).is_err());
    }

    /// Test Note demo functionality showcasing best practices
    #[test]
    fn test_note_demo_functionality() {
        let _guard = set_hash_kind_for_test(HashKind::Sha1);
        // This is a demonstration test that shows the complete functionality
        // It's kept separate from unit tests for clarity
        println!("\n🚀 Git Note Object Demo - Best Practices");
        println!("==========================================");

        let commit_id = ObjectHash::from_str("a1b2c3d4e5f6789012345678901234567890abcd").unwrap();

        println!("\n1️⃣ Creating a new Note object:");
        let note = Note::new(
            commit_id,
            "Code review: LGTM! Great implementation.".to_string(),
        );
        println!("   Target Commit: {}", note.target_object_id);
        println!("   Note ID: {}", note.id);
        println!("   Content: {}", note.content);
        println!("   Size: {} bytes", note.get_size());

        println!("\n2️⃣ Serializing Note with target association:");
        let (serialized_data, target_id) = note.to_data_with_target().unwrap();
        println!("   Serialized size: {} bytes", serialized_data.len());
        println!("   Target object ID: {}", target_id);
        println!(
            "   Git object format: blob {}\\0<content>",
            note.content.len()
        );
        println!(
            "   Raw data preview: {:?}...",
            &serialized_data[..std::cmp::min(30, serialized_data.len())]
        );

        println!("\n3️⃣ Basic deserialization (ObjectTrait):");
        let basic_note = Note::from_bytes(&serialized_data, note.id).unwrap();
        println!("   Successfully deserialized!");
        println!(
            "   Target Commit: {} (default - target managed externally)",
            basic_note.target_object_id
        );
        println!("   Content: {}", basic_note.content);
        println!("   Content matches: {}", note.content == basic_note.content);

        println!("\n4️⃣ Best practice deserialization (with target):");
        let complete_note =
            Note::from_bytes_with_target(&serialized_data, note.id, target_id).unwrap();
        println!("   Successfully deserialized with target!");
        println!("   Target Commit: {}", complete_note.target_object_id);
        println!("   Content: {}", complete_note.content);
        println!("   Complete objects are equal: {}", note == complete_note);

        // Basic assertions to ensure demo works
        assert_eq!(note, complete_note);
        assert_eq!(target_id, commit_id);
    }

    /// Test Note demo functionality showcasing best practices with SHA-256
    #[test]
    fn test_note_demo_functionality_sha256() {
        let _guard = set_hash_kind_for_test(HashKind::Sha256);
        // This is a demonstration test that shows the complete functionality
        // It's kept separate from unit tests for clarity
        println!("\n🚀 Git Note Object Demo - Best Practices");
        println!("==========================================");

        let commit_id = ObjectHash::from_str(
            "1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef",
        )
        .unwrap();

        println!("\n1️⃣ Creating a new Note object:");
        let note = Note::new(
            commit_id,
            "Code review: LGTM! Great implementation.".to_string(),
        );
        println!("   Target Commit: {}", note.target_object_id);
        println!("   Note ID: {}", note.id);
        println!("   Content: {}", note.content);
        println!("   Size: {} bytes", note.get_size());

        println!("\n2️⃣ Serializing Note with target association:");
        let (serialized_data, target_id) = note.to_data_with_target().unwrap();
        println!("   Serialized size: {} bytes", serialized_data.len());
        println!("   Target object ID: {}", target_id);
        println!(
            "   Git object format: blob {}\\0<content>",
            note.content.len()
        );
        println!(
            "   Raw data preview: {:?}...",
            &serialized_data[..std::cmp::min(30, serialized_data.len())]
        );

        println!("\n3️⃣ Basic deserialization (ObjectTrait):");
        let basic_note = Note::from_bytes(&serialized_data, note.id).unwrap();
        println!("   Successfully deserialized!");
        println!(
            "   Target Commit: {} (default - target managed externally)",
            basic_note.target_object_id
        );
        println!("   Content: {}", basic_note.content);
        println!("   Content matches: {}", note.content == basic_note.content);

        println!("\n4️⃣ Best practice deserialization (with target):");
        let complete_note =
            Note::from_bytes_with_target(&serialized_data, note.id, target_id).unwrap();
        println!("   Successfully deserialized with target!");
        println!("   Target Commit: {}", complete_note.target_object_id);
        println!("   Content: {}", complete_note.content);
        println!("   Complete objects are equal: {}", note == complete_note);

        // Basic assertions to ensure demo works
        assert_eq!(note, complete_note);
        assert_eq!(target_id, commit_id);
    }
}
