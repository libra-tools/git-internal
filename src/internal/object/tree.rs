//! In Git, a tree object is used to represent the state of a directory at a specific point in time.
//! It stores information about the files and directories within that directory, including their names,
//! permissions, and the IDs of the objects that represent their contents.
//!
//! A tree object can contain other tree objects as well as blob objects, which represent the contents
//! of individual files. The object IDs of these child objects are stored within the tree object itself.
//!
//! When you make a commit in Git, you create a new tree object that represents the state of the
//! repository at that point in time. The parent of the new commit is typically the tree object
//! representing the previous state of the repository.
//!
//! Git uses the tree object to efficiently store and manage the contents of a repository. By
//! representing the contents of a directory as a tree object, Git can quickly determine which files
//! have been added, modified, or deleted between two points in time. This allows Git to perform
//! operations like merging and rebasing more quickly and accurately.
//!
use std::fmt::Display;

use colored::Colorize;
use encoding_rs::GBK;

use crate::{
    errors::GitError,
    hash::{HashKind, ObjectHash},
    internal::object::{ObjectTrait, ObjectType},
};

/// In Git, the mode field in a tree object's entry specifies the type of the object represented by
/// that entry. The mode is a three-digit octal number that encodes both the permissions and the
/// type of the object. The first digit specifies the object type, and the remaining two digits
/// specify the file mode or permissions.
#[derive(
    PartialEq,
    Eq,
    Debug,
    Clone,
    Copy,
    serde::Serialize,
    serde::Deserialize,
    Hash,
    rkyv::Archive,
    rkyv::Serialize,
    rkyv::Deserialize,
)]
pub enum TreeItemMode {
    Blob,
    BlobExecutable,
    Tree,
    Commit,
    Link,
}

impl Display for TreeItemMode {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        let _print = match *self {
            TreeItemMode::Blob => "blob",
            TreeItemMode::BlobExecutable => "blob executable",
            TreeItemMode::Tree => "tree",
            TreeItemMode::Commit => "commit",
            TreeItemMode::Link => "link",
        };

        write!(f, "{}", String::from(_print).blue())
    }
}

impl TreeItemMode {
    /// Convert a 32-bit mode to a TreeItemType
    ///
    /// |0100000000000000| (040000)| Directory|
    /// |1000000110100100| (100644)| Regular non-executable file|
    /// |1000000110110100| (100664)| Regular non-executable group-writeable file|
    /// |1000000111101101| (100755)| Regular executable file|
    /// |1010000000000000| (120000)| Symbolic link|
    /// |1110000000000000| (160000)| Gitlink|
    /// ---
    /// # GitLink
    /// Gitlink, also known as a submodule, is a feature in Git that allows you to include a Git
    /// repository as a subdirectory within another Git repository. This is useful when you want to
    /// incorporate code from another project into your own project, without having to manually copy
    /// the code into your repository.
    ///
    /// When you add a submodule to your Git repository, Git stores a reference to the other
    /// repository at a specific commit. This means that your repository will always point to a
    /// specific version of the other repository, even if changes are made to the submodule's code
    /// in the future.
    ///
    /// To work with a submodule in Git, you use commands like git submodule add, git submodule
    /// update, and git submodule init. These commands allow you to add a submodule to your repository,
    /// update it to the latest version, and initialize it for use.
    ///
    /// Submodules can be a powerful tool for managing dependencies between different projects and
    /// components. However, they can also add complexity to your workflow, so it's important to
    /// understand how they work and when to use them.
    pub fn tree_item_type_from_bytes(mode: &[u8]) -> Result<TreeItemMode, GitError> {
        Ok(match mode {
            b"40000" => TreeItemMode::Tree,
            b"100644" => TreeItemMode::Blob,
            b"100755" => TreeItemMode::BlobExecutable,
            b"120000" => TreeItemMode::Link,
            b"160000" => TreeItemMode::Commit,
            b"100664" => TreeItemMode::Blob,
            b"100640" => TreeItemMode::Blob,
            _ => {
                // Non-UTF-8 modes are reported lossily instead of panicking.
                return Err(GitError::InvalidTreeItem(
                    String::from_utf8_lossy(mode).into_owned(),
                ));
            }
        })
    }

    /// 32-bit mode, split into (high to low bits):
    /// - 4-bit object type: valid values in binary are 1000 (regular file), 1010 (symbolic link) and 1110 (gitlink)
    /// - 3-bit unused
    /// - 9-bit unix permission: Only 0755 and 0644 are valid for regular files. Symbolic links and gitlink have value 0 in this field.
    pub fn to_bytes(self) -> &'static [u8] {
        match self {
            TreeItemMode::Blob => b"100644",
            TreeItemMode::BlobExecutable => b"100755",
            TreeItemMode::Link => b"120000",
            TreeItemMode::Tree => b"40000",
            TreeItemMode::Commit => b"160000",
        }
    }
}

/// A tree object contains a list of entries, one for each file or directory in the tree. Each entry
/// in the file represents an entry in the tree, and each entry has the following format:
///
/// ```bash
/// <mode> <name>\0<binary object ID>
/// ```
/// - `<mode>` is the mode of the object, represented as a six-digit octal number. The first digit
///   represents the object type (tree, blob, etc.), and the remaining digits represent the file mode or permissions.
/// - `<name>` is the name of the object.
/// - `\0` is a null byte separator.
/// - `<binary object ID>` is the ID of the object that represents the contents of the file or
///   directory, represented as a binary SHA-1 hash.
///
/// # Example
/// ```bash
/// 100644 hello-world\0<blob object ID>
/// 040000 data\0<tree object ID>
/// ```
#[derive(
    PartialEq,
    Eq,
    Debug,
    Clone,
    serde::Serialize,
    serde::Deserialize,
    Hash,
    rkyv::Archive,
    rkyv::Serialize,
    rkyv::Deserialize,
)]
pub struct TreeItem {
    pub mode: TreeItemMode,
    pub id: ObjectHash,
    pub name: String,
}

impl Display for TreeItem {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(
            f,
            "{} {} {}",
            self.mode,
            self.name,
            self.id.to_string().blue()
        )
    }
}

impl TreeItem {
    /// Creates a new [`TreeItem`] with the given mode, object ID, and name.
    pub fn new(mode: TreeItemMode, id: ObjectHash, name: String) -> Self {
        TreeItem { mode, id, name }
    }

    /// Parse one `<mode> <name>\0<binary object ID>` entry whose ID belongs to an
    /// explicit repository `kind`.
    ///
    /// Does not consult the thread-local [`HashKind`]. Fails closed (never
    /// panics) on a malformed entry or an ID of the wrong width.
    pub fn from_bytes_with_kind(bytes: &[u8], kind: HashKind) -> Result<Self, GitError> {
        let malformed = |what: &str| {
            GitError::InvalidTreeItem(format!(
                "tree entry is missing its {what} ({} bytes, expected {} mode/name bytes + 1 NUL + {}-byte {kind} id)",
                bytes.len(),
                bytes.len().saturating_sub(kind.size() + 1),
                kind.size()
            ))
        };
        let space = memchr::memchr(b' ', bytes).ok_or_else(|| malformed("mode"))?;
        let (mode, rest) = (&bytes[..space], &bytes[space + 1..]);
        let nul = memchr::memchr(0, rest).ok_or_else(|| malformed("NUL separator"))?;
        let (raw_name, id) = (&rest[..nul], &rest[nul + 1..]);

        let name = match String::from_utf8(raw_name.to_vec()) {
            Ok(name) => name,
            Err(_) => {
                let (decoded, _, had_errors) = GBK.decode(raw_name);
                if had_errors {
                    return Err(GitError::InvalidTreeItem(format!(
                        "Unsupported raw format: {raw_name:?}"
                    )));
                }
                decoded.to_string()
            }
        };
        Ok(TreeItem {
            mode: TreeItemMode::tree_item_type_from_bytes(mode)?,
            id: ObjectHash::from_bytes_for_kind(kind, id)?,
            name,
        })
    }

    /// Create a new TreeItem from a byte vector, split into a mode, id and name, the TreeItem format is:
    ///
    /// ```bash
    /// <mode> <name>\0<binary object ID>
    /// ```
    ///
    /// Legacy entry point: the ID width comes from the thread-local
    /// [`HashKind`]. Prefer [`TreeItem::from_bytes_with_kind`].
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, GitError> {
        let mut parts = bytes.splitn(2, |b| *b == b' ');
        let mode = parts.next().unwrap();
        let rest = parts.next().unwrap();
        let mut parts = rest.splitn(2, |b| *b == b'\0');
        let raw_name = parts.next().unwrap();
        let id = parts.next().unwrap();

        let name = if String::from_utf8(raw_name.to_vec()).is_ok() {
            String::from_utf8(raw_name.to_vec()).unwrap()
        } else {
            let (decoded, _, had_errors) = GBK.decode(raw_name);
            if had_errors {
                return Err(GitError::InvalidTreeItem(format!(
                    "Unsupported raw format: {raw_name:?}"
                )));
            } else {
                decoded.to_string()
            }
        };
        Ok(TreeItem {
            mode: TreeItemMode::tree_item_type_from_bytes(mode)?,
            id: ObjectHash::from_bytes(id).unwrap(),
            name,
        })
    }

    /// Convert a TreeItem to a byte vector
    /// ```rust
    /// use std::str::FromStr;
    /// use git_internal::internal::object::tree::{TreeItem, TreeItemMode};
    /// use git_internal::hash::ObjectHash;
    ///
    /// let tree_item = TreeItem::new(
    ///     TreeItemMode::Blob,
    ///     ObjectHash::from_str("8ab686eafeb1f44702738c8b0f24f2567c36da6d").unwrap(),
    ///     "hello-world".to_string(),
    /// );
    ///
    //  let bytes = tree_item.to_bytes();
    /// ```
    pub fn to_data(&self) -> Vec<u8> {
        let mut bytes = Vec::new();

        bytes.extend_from_slice(self.mode.to_bytes());
        bytes.push(b' ');
        bytes.extend_from_slice(self.name.as_bytes());
        bytes.push(b'\0');
        bytes.extend_from_slice(&self.id.to_data());

        bytes
    }

    /// Returns `true` if this item represents a subdirectory (tree).
    pub fn is_tree(&self) -> bool {
        self.mode == TreeItemMode::Tree
    }

    /// Returns `true` if this item represents a regular file (blob).
    pub fn is_blob(&self) -> bool {
        self.mode == TreeItemMode::Blob
    }
}

/// A tree object is a Git object that represents a directory. It contains a list of entries, one
/// for each file or directory in the tree.
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
pub struct Tree {
    pub id: ObjectHash,
    pub tree_items: Vec<TreeItem>,
}

impl PartialEq for Tree {
    fn eq(&self, other: &Self) -> bool {
        self.id == other.id
    }
}

impl Display for Tree {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        writeln!(f, "Tree: {}", self.id.to_string().blue())?;
        for item in &self.tree_items {
            writeln!(f, "{item}")?;
        }
        Ok(())
    }
}

impl Tree {
    /// Serialize `items` and verify every entry ID belongs to `kind`.
    fn items_data_for_kind(kind: HashKind, items: &[TreeItem]) -> Result<Vec<u8>, GitError> {
        let mut data = Vec::new();
        for item in items {
            item.id.ensure_kind(kind)?;
            data.extend_from_slice(item.to_data().as_slice());
        }
        Ok(data)
    }

    /// Create a new Tree from a list of TreeItems, hashing with an explicit repository `kind`.
    ///
    /// Does not consult the thread-local [`HashKind`]. Every entry ID must
    /// belong to `kind`; a cross-kind reference fails closed with
    /// [`GitError::InvalidHashValue`].
    pub fn from_tree_items_with_kind(
        kind: HashKind,
        tree_items: Vec<TreeItem>,
    ) -> Result<Self, GitError> {
        if tree_items.is_empty() {
            return Err(GitError::EmptyTreeItems(
                "When export tree object to meta, the items is empty".to_string(),
            ));
        }
        let data = Self::items_data_for_kind(kind, &tree_items)?;
        Ok(Tree {
            id: ObjectHash::from_type_and_data_for_kind(kind, ObjectType::Tree, &data)?,
            tree_items,
        })
    }

    /// Create a new Tree from a list of TreeItems
    ///
    /// Uses the thread-local [`HashKind`]; see [`Tree::from_tree_items_with_kind`].
    pub fn from_tree_items(tree_items: Vec<TreeItem>) -> Result<Self, GitError> {
        if tree_items.is_empty() {
            return Err(GitError::EmptyTreeItems(
                "When export tree object to meta, the items is empty"
                    .parse()
                    .unwrap(),
            ));
        }
        let mut data = Vec::new();
        for item in &tree_items {
            data.extend_from_slice(item.to_data().as_slice());
        }

        Ok(Tree {
            id: ObjectHash::from_type_and_data(ObjectType::Tree, &data),
            tree_items,
        })
    }

    /// Recalculate the tree ID for an explicit repository `kind` after the entries changed.
    ///
    /// Every entry ID must belong to `kind`; on failure the ID is left unchanged.
    pub fn rehash_with_kind(&mut self, kind: HashKind) -> Result<(), GitError> {
        let data = Self::items_data_for_kind(kind, &self.tree_items)?;
        self.id = ObjectHash::from_type_and_data_for_kind(kind, ObjectType::Tree, &data)?;
        Ok(())
    }

    /// After the subdirectory is changed, the hash value of the tree is recalculated.
    ///
    /// Uses the thread-local [`HashKind`]; see [`Tree::rehash_with_kind`].
    pub fn rehash(&mut self) {
        let mut data = Vec::new();
        for item in &self.tree_items {
            data.extend_from_slice(item.to_data().as_slice());
        }
        self.id = ObjectHash::from_type_and_data(ObjectType::Tree, &data);
    }
}

impl TryFrom<&[u8]> for Tree {
    type Error = GitError;
    fn try_from(data: &[u8]) -> Result<Self, Self::Error> {
        let h = ObjectHash::from_type_and_data(ObjectType::Tree, data);
        Tree::from_bytes(data, h)
    }
}
impl ObjectTrait for Tree {
    /// Parse a tree body. Entry IDs are sliced with the width of `hash.kind()` —
    /// the repository kind of the tree being loaded — never the thread-local
    /// kind, so an explicit-kind loader works on any thread.
    fn from_bytes(data: &[u8], hash: ObjectHash) -> Result<Self, GitError>
    where
        Self: Sized,
    {
        let kind = hash.kind();
        let mut tree_items = Vec::new();
        let mut i = 0;
        while i < data.len() {
            // Find the position of the null byte (0x00)
            if let Some(index) = memchr::memchr(0x00, &data[i..]) {
                // Calculate the next position
                let next = i + index + kind.size() + 1; // +1 for the null byte
                if next > data.len() {
                    return Err(GitError::InvalidTreeObject);
                } //check bounds before slicing the fixed-width id
                // Extract the bytes and create a TreeItem
                let item_data = &data[i..next];
                let tree_item = TreeItem::from_bytes_with_kind(item_data, kind)?;

                tree_items.push(tree_item);

                i = next;
            } else {
                // If no null byte is found, return an error
                return Err(GitError::InvalidTreeObject);
            }
        }

        Ok(Tree {
            id: hash,
            tree_items,
        })
    }

    fn get_type(&self) -> ObjectType {
        ObjectType::Tree
    }

    fn get_size(&self) -> usize {
        self.to_data().map(|data| data.len()).unwrap_or(0)
    }

    fn to_data(&self) -> Result<Vec<u8>, GitError> {
        let mut data: Vec<u8> = Vec::new();

        for item in &self.tree_items {
            data.extend_from_slice(item.to_data().as_slice());
            //data.push(b'\0');
        }

        Ok(data)
    }
}

#[cfg(test)]
mod tests {

    use std::str::FromStr;

    use crate::{
        errors::GitError,
        hash::{HashKind, ObjectHash, set_hash_kind_for_test},
        internal::object::tree::{Tree, TreeItem, TreeItemMode},
    };

    /// Helper: roundtrip a single TreeItem under a given hash kind.
    fn tree_item_round_trip(kind: HashKind, id_hex: &str) {
        let _guard = set_hash_kind_for_test(kind);
        let item = TreeItem::new(
            TreeItemMode::Blob,
            ObjectHash::from_str(id_hex).unwrap(),
            "hello-world".to_string(),
        );

        let bytes = item.to_data();
        let parsed = TreeItem::from_bytes(&bytes).unwrap();

        assert_eq!(parsed.mode, TreeItemMode::Blob);
        assert_eq!(parsed.id, item.id);
        assert_eq!(parsed.name, item.name);
    }

    /// TreeItem new/to_data/from_bytes roundtrip with SHA-1.
    #[test]
    fn tree_item_round_trip_sha1() {
        tree_item_round_trip(HashKind::Sha1, "8ab686eafeb1f44702738c8b0f24f2567c36da6d");
    }

    /// TreeItem new/to_data/from_bytes roundtrip with SHA-256.
    #[test]
    fn tree_item_round_trip_sha256() {
        tree_item_round_trip(
            HashKind::Sha256,
            "2cf8d83d9ee29543b34a87727421fdecb7e3f3a183d337639025de576db9ebb4",
        );
    }

    /// Helper: build a tree from items and assert the resulting ID.
    fn tree_round_trip(kind: HashKind, items: Vec<(&str, &str)>, expected_id: &str) {
        let _guard = set_hash_kind_for_test(kind);
        let tree_items = items
            .into_iter()
            .map(|(name, id_hex)| {
                TreeItem::new(
                    TreeItemMode::Blob,
                    ObjectHash::from_str(id_hex).unwrap(),
                    name.to_string(),
                )
            })
            .collect::<Vec<_>>();
        let tree = Tree::from_tree_items(tree_items).unwrap();
        assert_eq!(tree.id.to_string(), expected_id);
    }

    /// Tree construction from items (SHA-1).
    /// Explicit-kind entry parsing fails closed on malformed input (never panics).
    #[test]
    fn tree_item_from_bytes_with_kind_rejects_malformed() {
        let _guard = set_hash_kind_for_test(HashKind::Sha256);
        let id = [0x11u8; 20];

        // Non-UTF-8 mode bytes: reported lossily, not a panic.
        let mut bad_mode = b"\xff\xfe name\0".to_vec();
        bad_mode.extend_from_slice(&id);
        assert!(matches!(
            TreeItem::from_bytes_with_kind(&bad_mode, HashKind::Sha1),
            Err(GitError::InvalidTreeItem(_))
        ));

        // Missing NUL separator / missing space.
        assert!(matches!(
            TreeItem::from_bytes_with_kind(b"100644 name", HashKind::Sha1),
            Err(GitError::InvalidTreeItem(_))
        ));
        assert!(matches!(
            TreeItem::from_bytes_with_kind(b"100644", HashKind::Sha1),
            Err(GitError::InvalidTreeItem(_))
        ));

        // Wrong id width for the requested kind (20 bytes offered as SHA-256).
        let mut short_id = b"100644 name\0".to_vec();
        short_id.extend_from_slice(&id);
        match TreeItem::from_bytes_with_kind(&short_id, HashKind::Sha256) {
            Err(GitError::InvalidHashValue(msg)) => {
                assert!(
                    msg.contains("sha256") && msg.contains("32") && msg.contains("20"),
                    "{msg}"
                )
            }
            other => panic!("unexpected: {other:?}"),
        }

        // Correct width parses regardless of the thread-local kind.
        let item = TreeItem::from_bytes_with_kind(&short_id, HashKind::Sha1).unwrap();
        assert_eq!(item.id, ObjectHash::Sha1(id));
        assert_eq!(item.name, "name");
    }

    #[test]
    fn tree_from_items_sha1() {
        tree_round_trip(
            HashKind::Sha1,
            vec![("hello-world", "17288789afffb273c8c394bc65e87d899b92897b")],
            "cf99336fa61439a2f074c7e6de1c1a05579550e2",
        );
    }

    /// Tree construction from items (SHA-256).
    #[test]
    fn tree_from_items_sha256() {
        tree_round_trip(
            HashKind::Sha256,
            vec![
                (
                    "a.txt",
                    "2cf8d83d9ee29543b34a87727421fdecb7e3f3a183d337639025de576db9ebb4",
                ),
                (
                    "b.txt",
                    "fc2593998f8e1dec9c3a8be11557888134dad90ef5c7a2d6236ed75534c7698e",
                ),
                (
                    "c.txt",
                    "21513dcb4d6f9eb247db3b4c52158395d94f809cbaa2630bd2a7a474d9b39fab",
                ),
                (
                    "hello-world",
                    "2cf8d83d9ee29543b34a87727421fdecb7e3f3a183d337639025de576db9ebb4",
                ),
                (
                    "message.txt",
                    "9ba9ae56288652bf32f074f922e37d3e95df8920b3cdfc053309595b8f86cbc6",
                ),
            ],
            "d712a36aadfb47cabc7aaa90cf9e515773ba3bfc1fe3783730b387ce15c49261",
        );
    }
}
