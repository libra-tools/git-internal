//! The Commit object is a data structure used to represent a specific version of a project's
//! files at a particular point in time. In Git, the commit object is a fundamental data structure
//! that is used to track changes to a repository's files over time. Whenever a developer makes
//! changes to the files in a repository, they create a new commit object that records those changes.
//!
//! Each commit object in Git contains the following information:
//!
//! - A unique SHA-1/ SHA-256 hash that identifies the commit.
//! - The author and committer of the commit (which may be different people).
//! - The date and time the commit was made.
//! - A commit message that describes the changes made in the commit.
//! - A reference to the parent commit or commits (in the case of a merge commit) that the new commit is based on.
//! - The contents of the files in the repository at the time the commit was made.
use std::{fmt::Display, str::FromStr};

use bstr::ByteSlice;

use crate::{
    errors::GitError,
    hash::{HashKind, ObjectHash},
    internal::object::{ObjectTrait, ObjectType, signature::Signature},
};

/// The `Commit` struct is used to represent a commit object.
///
/// - The tree object SHA-1/SHA-256 hashpoints to the top level tree for this commit, which reflects the complete
///   state of the repository at the time of the commit. The tree object in turn points to blobs and
///   subtrees which represent the files in the repository.
/// - The parent commit SHAs allow Git to construct a linked list of commits and build the full
///   commit history. By chaining together commits in this fashion, Git is able to represent the entire
///   history of a repository with a single commit object at its root.
/// - The author and committer fields contain the name, email address, timestamp and timezone.
/// - The message field contains the commit message, which maybe include signed or DCO.
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
pub struct Commit {
    pub id: ObjectHash,
    pub tree_id: ObjectHash,
    pub parent_commit_ids: Vec<ObjectHash>,
    pub author: Signature,
    pub committer: Signature,
    pub message: String,
}
impl PartialEq for Commit {
    fn eq(&self, other: &Self) -> bool {
        self.id == other.id
    }
}

impl Display for Commit {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        writeln!(f, "tree: {}", self.tree_id)?;
        for parent in self.parent_commit_ids.iter() {
            writeln!(f, "parent: {parent}")?;
        }
        writeln!(f, "author {}", self.author)?;
        writeln!(f, "committer {}", self.committer)?;
        writeln!(f, "{}", self.message)
    }
}

impl Commit {
    /// Create a commit and derive its ID with an explicit repository `kind`.
    ///
    /// Does not consult the thread-local [`HashKind`]. `tree_id` and every
    /// parent ID must belong to `kind`; a cross-kind reference fails closed
    /// with [`GitError::InvalidHashValue`]. Never panics.
    pub fn new_with_kind(
        kind: HashKind,
        author: Signature,
        committer: Signature,
        tree_id: ObjectHash,
        parent_commit_ids: Vec<ObjectHash>,
        message: &str,
    ) -> Result<Commit, GitError> {
        tree_id.ensure_kind(kind)?;
        for parent in &parent_commit_ids {
            parent.ensure_kind(kind)?;
        }
        let mut commit = Commit {
            id: ObjectHash::zero_for_kind(kind),
            tree_id,
            parent_commit_ids,
            author,
            committer,
            message: message.to_string(),
        };
        let data = commit.to_data()?;
        commit.id = ObjectHash::from_type_and_data_for_kind(kind, ObjectType::Commit, &data)?;
        Ok(commit)
    }

    /// Convenience variant of [`Commit::new_with_kind`] that generates author and
    /// committer signatures from the current time (see [`Commit::from_tree_id`]).
    pub fn from_tree_id_with_kind(
        kind: HashKind,
        tree_id: ObjectHash,
        parent_commit_ids: Vec<ObjectHash>,
        message: &str,
    ) -> Result<Commit, GitError> {
        let now = chrono::Utc::now().timestamp();
        let author =
            Signature::from_data(format!("author mega <admin@mega.org> {now} +0800").into_bytes())?;
        let committer = Signature::from_data(
            format!("committer mega <admin@mega.org> {now} +0800").into_bytes(),
        )?;
        Commit::new_with_kind(kind, author, committer, tree_id, parent_commit_ids, message)
    }

    /// Create a commit using the thread-local [`HashKind`]; see [`Commit::new_with_kind`].
    pub fn new(
        author: Signature,
        committer: Signature,
        tree_id: ObjectHash,
        parent_commit_ids: Vec<ObjectHash>,
        message: &str,
    ) -> Commit {
        let mut commit = Commit {
            id: ObjectHash::default(),
            tree_id,
            parent_commit_ids,
            author,
            committer,
            message: message.to_string(),
        };
        // Calculate the hash of the commit object
        // The hash is calculated from the type and data of the commit object
        let hash = ObjectHash::from_type_and_data(ObjectType::Commit, &commit.to_data().unwrap());
        commit.id = hash;
        commit
    }

    /// Creates a new commit object from a tree ID and a list of parent commit IDs.
    /// This function generates the author and committer signatures using the current time
    /// and a fixed email address.
    /// It also sets the commit message to the provided string.
    /// # Arguments
    /// - `tree_id`: The SHA1/ SHA-256 hash of the tree object that this commit points to.
    /// - `parent_commit_ids`: A vector of SHA1/ SHA-256 hashes of the parent commits.
    /// - `message`: A string containing the commit message.
    /// # Returns
    /// A new `Commit` object with the specified tree ID, parent commit IDs, and commit message.
    /// The author and committer signatures are generated using the current time and a fixed email address.
    /// Uses the thread-local [`HashKind`]; see [`Commit::from_tree_id_with_kind`].
    pub fn from_tree_id(
        tree_id: ObjectHash,
        parent_commit_ids: Vec<ObjectHash>,
        message: &str,
    ) -> Commit {
        let author = Signature::from_data(
            format!(
                "author mega <admin@mega.org> {} +0800",
                chrono::Utc::now().timestamp()
            )
            .to_string()
            .into_bytes(),
        )
        .unwrap();
        let committer = Signature::from_data(
            format!(
                "committer mega <admin@mega.org> {} +0800",
                chrono::Utc::now().timestamp()
            )
            .to_string()
            .into_bytes(),
        )
        .unwrap();
        Commit::new(author, committer, tree_id, parent_commit_ids, message)
    }

    /// Formats the commit message by extracting the first meaningful line.
    ///
    /// If the message contains a PGP signature, it returns the first non-empty line
    /// after the signature block. Otherwise, it returns the first non-empty line
    /// in the message. If no such line exists, it returns the original message.
    pub fn format_message(&self) -> String {
        let mut lines = self.message.lines();

        // If a PGP signature is present, skip lines until after the signature ends
        if let Some(pos) = self
            .message
            .lines()
            .position(|line| line.contains("-----END PGP SIGNATURE-----"))
        {
            return self
                .message
                .lines()
                .skip(pos + 1)
                .find(|line| !line.trim().is_empty())
                .map(|line| line.to_owned())
                .unwrap_or_else(|| self.message.clone());
        }

        // Return the first non-empty line from the start
        lines
            .find(|line| !line.trim().is_empty())
            .map(|line| line.to_owned())
            .unwrap_or_else(|| self.message.clone())
    }
}

impl ObjectTrait for Commit {
    fn from_bytes(data: &[u8], hash: ObjectHash) -> Result<Self, GitError>
    where
        Self: Sized,
    {
        let mut commit = data;
        // Find the tree id and remove it from the data
        let tree_end = commit.find_byte(0x0a).unwrap();
        let tree_id: ObjectHash = ObjectHash::from_str(
            String::from_utf8(commit[5..tree_end].to_owned()) // 5 is the length of "tree "
                .unwrap()
                .as_str(),
        )
        .unwrap();
        let binding = commit[tree_end + 1..].to_vec(); // Move past the tree id
        commit = &binding;

        // Find the parent commit ids and remove them from the data
        let author_begin = commit.find("author").unwrap();
        // Find all parent commit ids
        // The parent commit ids are all the lines that start with "parent "
        // We can use find_iter to find all occurrences of "parent "
        // and then extract the SHA1/ SHA-256 hashes from them.
        let parent_commit_ids: Vec<ObjectHash> = commit[..author_begin]
            .find_iter("parent")
            .map(|parent| {
                let parent_end = commit[parent..].find_byte(0x0a).unwrap();
                ObjectHash::from_str(
                    // 7 is the length of "parent "
                    String::from_utf8(commit[parent + 7..parent + parent_end].to_owned())
                        .unwrap()
                        .as_str(),
                )
                .unwrap()
            })
            .collect();
        let binding = commit[author_begin..].to_vec();
        commit = &binding;

        // Find the author and committer and remove them from the data
        // 0x0a is the newline character
        let author =
            Signature::from_data(commit[..commit.find_byte(0x0a).unwrap()].to_vec()).unwrap();

        let binding = commit[commit.find_byte(0x0a).unwrap() + 1..].to_vec();
        commit = &binding;
        let committer =
            Signature::from_data(commit[..commit.find_byte(0x0a).unwrap()].to_vec()).unwrap();

        // The rest is the message
        let message = unsafe {
            String::from_utf8_unchecked(commit[commit.find_byte(0x0a).unwrap() + 1..].to_vec())
        };
        Ok(Commit {
            id: hash,
            tree_id,
            parent_commit_ids,
            author,
            committer,
            message,
        })
    }

    fn get_type(&self) -> ObjectType {
        ObjectType::Commit
    }

    fn get_size(&self) -> usize {
        self.to_data().map(|data| data.len()).unwrap_or(0)
    }

    /// [Git-Internals-Git-Objects](https://git-scm.com/book/en/v2/Git-Internals-Git-Objects)
    fn to_data(&self) -> Result<Vec<u8>, GitError> {
        let mut data = Vec::new();

        data.extend(b"tree ");
        data.extend(self.tree_id.to_string().as_bytes());
        data.extend(&[0x0a]);

        for parent_tree_id in &self.parent_commit_ids {
            data.extend(b"parent ");
            data.extend(parent_tree_id.to_string().as_bytes());
            data.extend(&[0x0a]);
        }

        data.extend(self.author.to_data()?);
        data.extend(&[0x0a]);
        data.extend(self.committer.to_data()?);
        data.extend(&[0x0a]);
        // Important! or Git Server can't parse & reply: unpack-objects abnormal exit
        // We can move [0x0a] to message instead here.
        // data.extend(&[0x0a]);
        data.extend(self.message.as_bytes());

        Ok(data)
    }
}

#[cfg(test)]
mod tests {
    use std::str::FromStr;

    use super::*;
    use crate::hash::{HashKind, set_hash_kind_for_test};

    /// Create a basic commit object for testing
    fn basic_commit() -> Commit {
        let _guard = set_hash_kind_for_test(HashKind::Sha1);
        let raw_commit = br#"tree 341e54913a3a43069f2927cc0f703e5a9f730df1
author benjamin.747 <benjamin.747@outlook.com> 1757467768 +0800
committer benjamin.747 <benjamin.747@outlook.com> 1757491219 +0800
gpgsig -----BEGIN PGP SIGNATURE-----

 iQJNBAABCAA3FiEEs4MaYUV7JcjxsVMPyqxGczTZ6K4FAmjBMC4ZHGJlbmphbWlu
 Ljc0N0BvdXRsb29rLmNvbQAKCRDKrEZzNNnorj73EADNpsyLAHsB3NgoeH+uy9Vq
 G2+LRtlvqv3QMK7vbQUadXHlQYWk25SIk+WJ1kG1AnUy5fqOrLSDTA1ny+qwpH8O
 +2sKCF/S1wlzqGWjCcRH5/ir9srsGIn9HbNqBjmU22NJ6Dt2jnqoUvtWfPwyqwWg
 VpjYlj390cFdXTpH5hMvtlmUQB+zCSKtWQW2Ur64h/UsGtllARlACi+KHQQmA2/p
 FLWNddvfJQpPM597DkGohQTD68g0PqOBhUkOHduHq7VHy68DVW+07bPNXK8JhJ8S
 4dyV1sZwcVcov0GcKl0wUbEqzy4gf+zV7DQhkfrSRQMBdo5vCWahYj1AbgaTiu8a
 hscshYDuWWqpxBU/+nCxOPskV29uUG1sRyXp3DqmKJZpnO9CVdw3QaVrqnMEeh2S
 t/wYRI9aI1A+Mi/DETom5ifTVygMkK+3m1h7pAMOlblFEdZx2sDXPRG2IEUcatr4
 Jb2+7PUJQXxUQnwHC7xHHxRh6a2h8TfEJfSoEyrgzxZ0CRxJ6XMJaJu0UwZ2xMsx
 Lgmeu6miB/imwxz5R5RL2yVHbgllSlO5l12AIeBaPoarKXYPSALigQnKCXu5OM3x
 Jq5qsSGtxdr6S1VgLyYHR4o69bQjzBp9K47J3IXqvrpo/ZiO/6Mspk2ZRWhGj82q
 e3qERPp5b7+hA+M7jKPyJg==
 =UeLf
 -----END PGP SIGNATURE-----

test parse commit from bytes
"#;

        let hash = ObjectHash::from_str("57d7685c60213a9da465cf900f31933be3a7ee39").unwrap();
        Commit::from_bytes(raw_commit, hash).unwrap()
    }

    /// Create a basic commit object with SHA-256 for testing
    fn basic_commit_sha256() -> Commit {
        let _guard = set_hash_kind_for_test(HashKind::Sha256);
        let raw_commit = br#"tree 0250024cf99636335fff1070e4220c5d8f67cb8633572d54b304629ad5382760
parent 33324c6819589e8eed81d6c72f216469151a0f2dbe7f42ba021d8b63049eb754
author jackieismpc <jackieismpc@gmail.com> 1764061895 +0800
committer jackieismpc <jackieismpc@gmail.com> 1764061895 +0800
gpgsig-sha256 -----BEGIN PGP SIGNATURE-----

 iQIzBAABCAAdFiEEzW/BI6wDXimDk/4lItD7G/h4TUsFAmklcscACgkQItD7G/h4
 TUtKFRAAtJq9tdl9XdND1ef2dXVQYCkQQlSdNHe2AR/QRVOPI39ZjD5aajRmZoE2
 rKDenNML1ruiGEm+K3ntRDjus+3QF5Xkhj1D6eImQt6RXyOlo64I+GLRKlzw80Sl
 hrd+l1eeuS4n46Z0U9fo1Qgc/crSn2VhUtLHJjvRntJoOb1vNreI2Y42Zmal3oVT
 fQNQ7mqzh3KuWoa8T6nVrLaLH1vl9qhRgkPcIRbFf+ECbB96qykHqcbdHuneSgfx
 +REpr1cedilkQlX81JrQ8Ntf4QFUPPHALl27/G6oPLT714cflEbvcFw7rNR+ktcD
 ZJIMu5Cl7X3/v5e0od/hF9uPfiLHckUsOXiMFLfqRdZx/5XeQFWRpq4eYcW7e89e
 3wJoBA2lCk8SHTBfsprKMpAweXJF9FCjRT5f9Zse2grqH81aQeNJnpSOoCq86oc/
 nxhi8+rbIbClLCGQoGF7sE/fvmKqcex++JnXHcHTtK002Gnh3oHX07sbahlcGuYY
 kg4QhXiLTQ5GfXnEnTPdFqbOVG02vEEsNeRgkmOz4c8Pm1FTDyOkuXd/Igvy7A9R
 MZwQcJ6E4MnsMnoH8FKswGqCD7ftwtJtRzryORBVzvPKALufIXDVLyBbae9dxdej
 bcpUK1bGtDljlwNtbLIOu+F1y2OVh7Tn3zxaQLcEhbUe2tP6rGk=
 =nJMO
 -----END PGP SIGNATURE-----

signed sha256 commit for test"#;
        let hash = ObjectHash::from_str(
            "ed43b50437e260a4d8fedacbaa38bad28b54cc424925e4180d9f186afaa0508c",
        )
        .unwrap();
        Commit::from_bytes(raw_commit.as_bytes(), hash).unwrap()
    }

    /// Test creating a Commit from bytes with PGP signature
    #[test]
    fn test_from_bytes_with_gpgsig() {
        let commit = basic_commit();

        assert_eq!(
            commit.id,
            ObjectHash::from_str("57d7685c60213a9da465cf900f31933be3a7ee39").unwrap()
        );

        assert_eq!(
            commit.tree_id,
            ObjectHash::from_str("341e54913a3a43069f2927cc0f703e5a9f730df1").unwrap()
        );

        assert_eq!(commit.author.name, "benjamin.747");
        assert_eq!(commit.author.email, "benjamin.747@outlook.com");

        assert_eq!(commit.committer.name, "benjamin.747");

        // check message content（must contains gpgsig and content）
        assert!(commit.message.contains("-----BEGIN PGP SIGNATURE-----"));
        assert!(commit.message.contains("-----END PGP SIGNATURE-----"));
        assert!(commit.message.contains("test parse commit from bytes"));
    }

    /// Test creating a Commit from bytes with SHA-256
    #[test]
    fn test_from_bytes_with_gpgsig_sha256() {
        let commit = basic_commit_sha256();
        assert_eq!(
            commit.id,
            ObjectHash::from_str(
                "ed43b50437e260a4d8fedacbaa38bad28b54cc424925e4180d9f186afaa0508c"
            )
            .unwrap()
        );
        assert_eq!(
            commit.tree_id,
            ObjectHash::from_str(
                "0250024cf99636335fff1070e4220c5d8f67cb8633572d54b304629ad5382760"
            )
            .unwrap()
        );
        assert_eq!(commit.author.name, "jackieismpc");
        assert_eq!(commit.author.email, "jackieismpc@gmail.com");
        assert_eq!(commit.committer.name, "jackieismpc");
        // // check message content (must contain gpgsig-sha256 and content)
        assert!(commit.message.contains("-----BEGIN PGP SIGNATURE-----"));
        assert!(commit.message.contains("-----END PGP SIGNATURE-----"));
        assert!(commit.message.contains("signed sha256 commit for test"));
    }

    /// Test formatting commit message with PGP signature
    #[test]
    fn test_format_message_with_pgp_signature() {
        let _guard = set_hash_kind_for_test(HashKind::Sha1);
        let commit = basic_commit();
        assert_eq!(commit.format_message(), "test parse commit from bytes");
    }

    /// Test formatting commit message with SHA-256 PGP signature
    #[test]
    fn test_format_message_with_pgp_signature_sha256() {
        let _guard = set_hash_kind_for_test(HashKind::Sha256);
        let commit = basic_commit_sha256();
        assert_eq!(commit.format_message(), "signed sha256 commit for test");
    }
}
