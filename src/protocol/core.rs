//! Core Git protocol implementation
//!
//! This module provides the main `GitProtocol` struct and `RepositoryAccess` trait
//! that form the core interface of the git-internal library.
use std::collections::HashMap;

use async_trait::async_trait;
use bytes::{BufMut, Bytes, BytesMut};
use futures::stream::StreamExt;

use crate::{
    hash::{HashKind, ObjectHash, get_hash_kind},
    internal::object::ObjectTrait,
    protocol::{
        smart::SmartProtocol,
        types::{Capability, ProtocolError, ProtocolStream, ServiceType, SideBand},
    },
};

/// Repository access trait for storage operations
///
/// This trait only handles storage-level operations, not Git protocol details.
/// The git-internal library handles all Git protocol formatting and parsing.
#[async_trait]
pub trait RepositoryAccess: Send + Sync + Clone {
    /// The object-ID hash kind of this repository.
    ///
    /// The default returns the thread-local [`HashKind`] so existing
    /// implementors keep working unchanged; implementors that serve a
    /// repository whose format is known (or that may be called from a thread
    /// configured for another repository) should override it to return the
    /// repository's real format. The default object accessors below parse
    /// incoming hash strings against this kind and fail closed on a mismatch.
    fn object_hash_kind(&self) -> HashKind {
        get_hash_kind()
    }

    /// Get repository references as raw (name, hash) pairs
    async fn get_repository_refs(&self) -> Result<Vec<(String, String)>, ProtocolError>;

    /// Check if an object exists in the repository
    async fn has_object(&self, object_hash: &str) -> Result<bool, ProtocolError>;

    /// Get raw object data by hash
    async fn get_object(&self, object_hash: &str) -> Result<Vec<u8>, ProtocolError>;

    /// Store pack data in the repository
    async fn store_pack_data(&self, pack_data: &[u8]) -> Result<(), ProtocolError>;

    /// Update a single reference
    async fn update_reference(
        &self,
        ref_name: &str,
        old_hash: Option<&str>,
        new_hash: &str,
    ) -> Result<(), ProtocolError>;

    /// Get objects needed for pack generation
    async fn get_objects_for_pack(
        &self,
        wants: &[String],
        haves: &[String],
    ) -> Result<Vec<String>, ProtocolError>;

    /// Check if repository has a default branch
    async fn has_default_branch(&self) -> Result<bool, ProtocolError>;

    /// Post-receive hook after successful push
    async fn post_receive_hook(&self) -> Result<(), ProtocolError>;

    /// Get blob data by hash
    ///
    /// Default implementation parses the object data using the internal object module.
    /// Override this method if you need custom blob handling logic.
    async fn get_blob(
        &self,
        object_hash: &str,
    ) -> Result<crate::internal::object::blob::Blob, ProtocolError> {
        // Resolve the repository kind before the first await: the default reads a

        // thread-local, and the future may resume on another worker thread.

        let kind = self.object_hash_kind();

        let hash = ObjectHash::from_hex_for_kind(kind, object_hash)
            .map_err(|e| ProtocolError::repository_error(format!("Invalid hash format: {e}")))?;
        let data = self.get_object(object_hash).await?;

        crate::internal::object::blob::Blob::from_bytes(&data, hash)
            .map_err(|e| ProtocolError::repository_error(format!("Failed to parse blob: {e}")))
    }

    /// Get commit data by hash
    ///
    /// Default implementation parses the object data using the internal object module.
    /// Override this method if you need custom commit handling logic.
    async fn get_commit(
        &self,
        commit_hash: &str,
    ) -> Result<crate::internal::object::commit::Commit, ProtocolError> {
        // Resolve the repository kind before the first await: the default reads a

        // thread-local, and the future may resume on another worker thread.

        let kind = self.object_hash_kind();

        let hash = ObjectHash::from_hex_for_kind(kind, commit_hash)
            .map_err(|e| ProtocolError::repository_error(format!("Invalid hash format: {e}")))?;
        let data = self.get_object(commit_hash).await?;

        crate::internal::object::commit::Commit::from_bytes(&data, hash)
            .map_err(|e| ProtocolError::repository_error(format!("Failed to parse commit: {e}")))
    }

    /// Get tree data by hash
    ///
    /// Default implementation parses the object data using the internal object module.
    /// Override this method if you need custom tree handling logic.
    async fn get_tree(
        &self,
        tree_hash: &str,
    ) -> Result<crate::internal::object::tree::Tree, ProtocolError> {
        // Resolve the repository kind before the first await: the default reads a

        // thread-local, and the future may resume on another worker thread.

        let kind = self.object_hash_kind();

        let hash = ObjectHash::from_hex_for_kind(kind, tree_hash)
            .map_err(|e| ProtocolError::repository_error(format!("Invalid hash format: {e}")))?;
        let data = self.get_object(tree_hash).await?;

        crate::internal::object::tree::Tree::from_bytes(&data, hash)
            .map_err(|e| ProtocolError::repository_error(format!("Failed to parse tree: {e}")))
    }

    /// Check if a commit exists
    ///
    /// Default implementation checks object existence and validates it's a commit.
    /// Override this method if you have more efficient commit existence checking.
    async fn commit_exists(&self, commit_hash: &str) -> Result<bool, ProtocolError> {
        match self.has_object(commit_hash).await {
            Ok(exists) => {
                if !exists {
                    return Ok(false);
                }

                // Verify it's actually a commit by trying to parse it
                match self.get_commit(commit_hash).await {
                    Ok(_) => Ok(true),
                    Err(_) => Ok(false), // Object exists but is not a valid commit
                }
            }
            Err(e) => Err(e),
        }
    }

    /// Handle pack objects after unpacking
    ///
    /// Default implementation stores each object individually using store_pack_data.
    /// Override this method if you need batch processing or custom storage logic.
    async fn handle_pack_objects(
        &self,
        commits: Vec<crate::internal::object::commit::Commit>,
        trees: Vec<crate::internal::object::tree::Tree>,
        blobs: Vec<crate::internal::object::blob::Blob>,
    ) -> Result<(), ProtocolError> {
        // Store blobs
        for blob in blobs {
            let data = blob.to_data().map_err(|e| {
                ProtocolError::repository_error(format!("Failed to serialize blob: {e}"))
            })?;
            self.store_pack_data(&data).await.map_err(|e| {
                ProtocolError::repository_error(format!("Failed to store blob {}: {}", blob.id, e))
            })?;
        }

        // Store trees
        for tree in trees {
            let data = tree.to_data().map_err(|e| {
                ProtocolError::repository_error(format!("Failed to serialize tree: {e}"))
            })?;
            self.store_pack_data(&data).await.map_err(|e| {
                ProtocolError::repository_error(format!("Failed to store tree {}: {}", tree.id, e))
            })?;
        }

        // Store commits
        for commit in commits {
            let data = commit.to_data().map_err(|e| {
                ProtocolError::repository_error(format!("Failed to serialize commit: {e}"))
            })?;
            self.store_pack_data(&data).await.map_err(|e| {
                ProtocolError::repository_error(format!(
                    "Failed to store commit {}: {}",
                    commit.id, e
                ))
            })?;
        }

        Ok(())
    }
}

/// Authentication service trait
#[async_trait]
pub trait AuthenticationService: Send + Sync {
    /// Authenticate HTTP request
    async fn authenticate_http(
        &self,
        headers: &std::collections::HashMap<String, String>,
    ) -> Result<(), ProtocolError>;

    /// Authenticate SSH public key
    async fn authenticate_ssh(
        &self,
        username: &str,
        public_key: &[u8],
    ) -> Result<(), ProtocolError>;
}

/// Transport-agnostic Git smart protocol handler
/// Main Git protocol handler
///
/// This struct provides the core Git protocol implementation that works
/// across HTTP, SSH, and other transports. It uses SmartProtocol internally
/// to handle all Git protocol details.
pub struct GitProtocol<R: RepositoryAccess, A: AuthenticationService> {
    smart_protocol: SmartProtocol<R, A>,
}

impl<R: RepositoryAccess, A: AuthenticationService> GitProtocol<R, A> {
    /// Create a new GitProtocol instance
    pub fn new(repo_access: R, auth_service: A) -> Self {
        Self {
            smart_protocol: SmartProtocol::new(
                super::types::TransportProtocol::Http,
                repo_access,
                auth_service,
            ),
        }
    }

    /// Authenticate HTTP request before serving Git operations
    pub async fn authenticate_http(
        &self,
        headers: &HashMap<String, String>,
    ) -> Result<(), ProtocolError> {
        self.smart_protocol.authenticate_http(headers).await
    }

    /// Authenticate SSH session before serving Git operations
    pub async fn authenticate_ssh(
        &self,
        username: &str,
        public_key: &[u8],
    ) -> Result<(), ProtocolError> {
        self.smart_protocol
            .authenticate_ssh(username, public_key)
            .await
    }

    /// Set transport protocol (Http, Ssh, etc.)
    pub fn set_transport(&mut self, protocol: super::types::TransportProtocol) {
        self.smart_protocol.set_transport_protocol(protocol);
    }

    /// Handle git info-refs request
    pub async fn info_refs(&self, service: &str) -> Result<Vec<u8>, ProtocolError> {
        let service_type = match service {
            "git-upload-pack" => ServiceType::UploadPack,
            "git-receive-pack" => ServiceType::ReceivePack,
            _ => return Err(ProtocolError::invalid_service(service)),
        };

        let bytes = self.smart_protocol.git_info_refs(service_type).await?;
        Ok(bytes.to_vec())
    }

    /// Handle git-upload-pack request (for clone/fetch)
    pub async fn upload_pack(
        &mut self,
        request_data: &[u8],
    ) -> Result<ProtocolStream, ProtocolError> {
        const SIDE_BAND_PACKET_LEN: usize = 1000;
        const SIDE_BAND_64K_PACKET_LEN: usize = 65520;
        const SIDE_BAND_HEADER_LEN: usize = 5; // 4-byte length + 1-byte band

        let request_bytes = bytes::Bytes::from(request_data.to_vec());
        let (pack_stream, protocol_buf) =
            self.smart_protocol.git_upload_pack(request_bytes).await?;
        let ack_bytes = protocol_buf.freeze();

        let ack_stream: ProtocolStream = if ack_bytes.is_empty() {
            Box::pin(futures::stream::empty::<Result<Bytes, ProtocolError>>())
        } else {
            Box::pin(futures::stream::once(async move { Ok(ack_bytes) }))
        };

        let sideband_max = if self
            .smart_protocol
            .capabilities
            .contains(&Capability::SideBand64k)
        {
            Some(SIDE_BAND_64K_PACKET_LEN - SIDE_BAND_HEADER_LEN)
        } else if self
            .smart_protocol
            .capabilities
            .contains(&Capability::SideBand)
        {
            Some(SIDE_BAND_PACKET_LEN - SIDE_BAND_HEADER_LEN)
        } else {
            None
        };

        let data_stream: ProtocolStream = if let Some(max_payload) = sideband_max {
            let stream = pack_stream.flat_map(move |chunk| {
                let packets = build_side_band_packets(&chunk, max_payload);
                futures::stream::iter(packets.into_iter().map(Ok))
            });
            let stream = stream.chain(futures::stream::once(async {
                Ok(Bytes::from_static(b"0000"))
            }));
            Box::pin(stream)
        } else {
            Box::pin(pack_stream.map(|data| Ok(Bytes::from(data))))
        };

        Ok(Box::pin(ack_stream.chain(data_stream)))
    }

    /// Handle git-receive-pack request (for push)
    pub async fn receive_pack(
        &mut self,
        request_stream: ProtocolStream,
    ) -> Result<ProtocolStream, ProtocolError> {
        const SIDE_BAND_PACKET_LEN: usize = 1000;
        const SIDE_BAND_64K_PACKET_LEN: usize = 65520;
        const SIDE_BAND_HEADER_LEN: usize = 5; // 4-byte length + 1-byte band

        let result_bytes = self
            .smart_protocol
            .git_receive_pack_stream(request_stream)
            .await?;

        let sideband_max = if self
            .smart_protocol
            .capabilities
            .contains(&Capability::SideBand64k)
        {
            Some(SIDE_BAND_64K_PACKET_LEN - SIDE_BAND_HEADER_LEN)
        } else if self
            .smart_protocol
            .capabilities
            .contains(&Capability::SideBand)
        {
            Some(SIDE_BAND_PACKET_LEN - SIDE_BAND_HEADER_LEN)
        } else {
            None
        };

        // Wrap report-status in side-band if negotiated by the client.
        if let Some(max_payload) = sideband_max {
            let packets = build_side_band_packets(result_bytes.as_ref(), max_payload);
            let stream = futures::stream::iter(packets.into_iter().map(Ok)).chain(
                futures::stream::once(async { Ok(Bytes::from_static(b"0000")) }),
            );
            Ok(Box::pin(stream))
        } else {
            // Return the report status as a single-chunk stream
            Ok(Box::pin(futures::stream::once(async { Ok(result_bytes) })))
        }
    }
}

fn build_side_band_packets(chunk: &[u8], max_payload: usize) -> Vec<Bytes> {
    if chunk.is_empty() {
        return Vec::new();
    }

    let mut out = Vec::new();
    let mut offset = 0;

    while offset < chunk.len() {
        let end = (offset + max_payload).min(chunk.len());
        let payload = &chunk[offset..end];
        let length = payload.len() + 5; // 4-byte length + 1-byte band
        let mut pkt = BytesMut::with_capacity(length);
        pkt.put(Bytes::from(format!("{length:04x}")));
        pkt.put_u8(SideBand::PackfileData.value());
        pkt.put(payload);
        out.push(pkt.freeze());
        offset = end;
    }

    out
}

#[cfg(test)]
mod tests {
    use async_trait::async_trait;
    use bytes::{Bytes, BytesMut};
    use futures::StreamExt;

    use super::*;
    use crate::{
        hash::{HashKind, set_hash_kind_for_test},
        internal::object::{
            blob::Blob,
            commit::Commit,
            signature::{Signature, SignatureType},
            tree::{Tree, TreeItem, TreeItemMode},
        },
        protocol::{types::TransportProtocol, utils},
    };

    /// Simple mock repository that serves fixed refs and echoes wants.
    #[derive(Clone)]
    struct MockRepo {
        refs: Vec<(String, String)>,
    }

    #[async_trait]
    impl RepositoryAccess for MockRepo {
        async fn get_repository_refs(&self) -> Result<Vec<(String, String)>, ProtocolError> {
            Ok(self.refs.clone())
        }
        async fn has_object(&self, _object_hash: &str) -> Result<bool, ProtocolError> {
            Ok(false)
        }
        async fn get_object(&self, _object_hash: &str) -> Result<Vec<u8>, ProtocolError> {
            Ok(Vec::new())
        }
        async fn store_pack_data(&self, _pack_data: &[u8]) -> Result<(), ProtocolError> {
            Ok(())
        }
        async fn update_reference(
            &self,
            _ref_name: &str,
            _old_hash: Option<&str>,
            _new_hash: &str,
        ) -> Result<(), ProtocolError> {
            Ok(())
        }
        async fn get_objects_for_pack(
            &self,
            wants: &[String],
            _haves: &[String],
        ) -> Result<Vec<String>, ProtocolError> {
            Ok(wants.to_vec())
        }
        async fn has_default_branch(&self) -> Result<bool, ProtocolError> {
            Ok(false)
        }
        async fn post_receive_hook(&self) -> Result<(), ProtocolError> {
            Ok(())
        }
    }

    /// No-op auth service for tests.
    struct MockAuth;
    #[async_trait]
    impl AuthenticationService for MockAuth {
        async fn authenticate_http(
            &self,
            _headers: &std::collections::HashMap<String, String>,
        ) -> Result<(), ProtocolError> {
            Ok(())
        }
        async fn authenticate_ssh(
            &self,
            _username: &str,
            _public_key: &[u8],
        ) -> Result<(), ProtocolError> {
            Ok(())
        }
    }

    /// Convenience builder for GitProtocol with mock repo/auth.
    fn make_protocol() -> GitProtocol<MockRepo, MockAuth> {
        GitProtocol::new(
            MockRepo {
                refs: vec![
                    (
                        "refs/heads/main".to_string(),
                        ObjectHash::default().to_string(),
                    ),
                    ("HEAD".to_string(), ObjectHash::default().to_string()),
                ],
            },
            MockAuth,
        )
    }

    /// Mock repo that serves a single commit, tree, and blobs.
    #[derive(Clone)]
    struct SideBandRepo {
        commit: Commit,
        tree: Tree,
        blobs: Vec<Blob>,
    }
    #[async_trait]
    impl RepositoryAccess for SideBandRepo {
        async fn get_repository_refs(&self) -> Result<Vec<(String, String)>, ProtocolError> {
            Ok(vec![(
                "refs/heads/main".to_string(),
                self.commit.id.to_string(),
            )])
        }

        async fn has_object(&self, object_hash: &str) -> Result<bool, ProtocolError> {
            let known = object_hash == self.commit.id.to_string()
                || object_hash == self.tree.id.to_string()
                || self.blobs.iter().any(|b| b.id.to_string() == object_hash);
            Ok(known)
        }

        async fn get_object(&self, _object_hash: &str) -> Result<Vec<u8>, ProtocolError> {
            Ok(Vec::new())
        }

        async fn store_pack_data(&self, _pack_data: &[u8]) -> Result<(), ProtocolError> {
            Ok(())
        }

        async fn update_reference(
            &self,
            _ref_name: &str,
            _old_hash: Option<&str>,
            _new_hash: &str,
        ) -> Result<(), ProtocolError> {
            Ok(())
        }

        async fn get_objects_for_pack(
            &self,
            _wants: &[String],
            _haves: &[String],
        ) -> Result<Vec<String>, ProtocolError> {
            Ok(Vec::new())
        }

        async fn has_default_branch(&self) -> Result<bool, ProtocolError> {
            Ok(true)
        }

        async fn post_receive_hook(&self) -> Result<(), ProtocolError> {
            Ok(())
        }

        async fn get_commit(&self, commit_hash: &str) -> Result<Commit, ProtocolError> {
            if commit_hash == self.commit.id.to_string() {
                Ok(self.commit.clone())
            } else {
                Err(ProtocolError::ObjectNotFound(commit_hash.to_string()))
            }
        }

        async fn get_tree(&self, tree_hash: &str) -> Result<Tree, ProtocolError> {
            if tree_hash == self.tree.id.to_string() {
                Ok(self.tree.clone())
            } else {
                Err(ProtocolError::ObjectNotFound(tree_hash.to_string()))
            }
        }

        async fn get_blob(&self, blob_hash: &str) -> Result<Blob, ProtocolError> {
            self.blobs
                .iter()
                .find(|b| b.id.to_string() == blob_hash)
                .cloned()
                .ok_or_else(|| ProtocolError::ObjectNotFound(blob_hash.to_string()))
        }
    }

    fn build_repo_with_objects() -> (SideBandRepo, Commit) {
        let blob = Blob::from_content("hello");
        let item = TreeItem::new(TreeItemMode::Blob, blob.id, "hello.txt".to_string());
        let tree = Tree::from_tree_items(vec![item]).unwrap();
        let author = Signature::new(
            SignatureType::Author,
            "tester".to_string(),
            "tester@example.com".to_string(),
        );
        let committer = Signature::new(
            SignatureType::Committer,
            "tester".to_string(),
            "tester@example.com".to_string(),
        );
        let commit = Commit::new(author, committer, tree.id, vec![], "init commit");

        let repo = SideBandRepo {
            commit: commit.clone(),
            tree,
            blobs: vec![blob],
        };

        (repo, commit)
    }

    /// upload-pack should emit NAK before sending pack data.
    #[tokio::test]
    async fn upload_pack_emits_ack_before_pack() {
        let _guard = set_hash_kind_for_test(HashKind::Sha1);
        let (repo, commit) = build_repo_with_objects();
        let mut proto = GitProtocol::new(repo, MockAuth);
        let mut request = BytesMut::new();
        utils::add_pkt_line_string(&mut request, format!("want {}\n", commit.id));
        utils::add_pkt_line_string(&mut request, "done\n".to_string());

        let mut stream = proto.upload_pack(&request).await.expect("upload-pack");
        let mut out = BytesMut::new();
        while let Some(chunk) = stream.next().await {
            out.extend_from_slice(&chunk.expect("stream chunk"));
        }

        let mut out_bytes = out.freeze();
        let (_len, line) = utils::read_pkt_line(&mut out_bytes);
        assert_eq!(line, Bytes::from_static(b"NAK\n"));
        assert!(
            out_bytes.as_ref().starts_with(b"PACK"),
            "pack should follow ack"
        );
    }

    /// upload-pack with side-band should wrap pack data in side-band packets.
    #[tokio::test]
    async fn upload_pack_sideband_frames_pack() {
        let _guard = set_hash_kind_for_test(HashKind::Sha1);
        let (repo, commit) = build_repo_with_objects();

        let mut proto = GitProtocol::new(repo, MockAuth);
        let mut request = BytesMut::new();
        utils::add_pkt_line_string(&mut request, format!("want {} side-band-64k\n", commit.id));
        utils::add_pkt_line_string(&mut request, "done\n".to_string());

        let mut stream = proto.upload_pack(&request).await.expect("upload-pack");
        let mut out = BytesMut::new();
        while let Some(chunk) = stream.next().await {
            out.extend_from_slice(&chunk.expect("stream chunk"));
        }

        let mut out_bytes = out.freeze();
        let (_len, line) = utils::read_pkt_line(&mut out_bytes);
        assert_eq!(line, Bytes::from_static(b"NAK\n"));

        let raw = out_bytes.as_ref();
        assert!(raw.len() > 9, "side-band packet should include PACK header");
        let len_hex = std::str::from_utf8(&raw[..4]).expect("hex length");
        let pkt_len = usize::from_str_radix(len_hex, 16).expect("parse length");
        assert!(pkt_len > 5, "side-band packet should contain data");
        assert_eq!(raw[4], SideBand::PackfileData.value());
        assert_eq!(&raw[5..9], b"PACK");
        assert!(raw.ends_with(b"0000"), "side-band stream should flush");
    }

    /// info_refs should include refs, capabilities, and object-format.
    #[tokio::test]
    async fn info_refs_includes_refs_and_caps() {
        let proto = make_protocol();
        let bytes = proto.info_refs("git-upload-pack").await.expect("info_refs");
        let text = String::from_utf8(bytes).expect("utf8");
        assert!(text.contains("refs/heads/main"));
        assert!(text.contains("capabilities"));
        assert!(text.contains("object-format"));
    }

    /// Invalid service name should return InvalidService.
    #[tokio::test]
    async fn info_refs_invalid_service_errors() {
        let proto = make_protocol();
        let err = proto.info_refs("git-invalid").await.unwrap_err();
        assert!(matches!(err, ProtocolError::InvalidService(_)));
    }

    /// Ensure set_transport can switch protocols without panic.
    #[tokio::test]
    async fn can_switch_transport() {
        let mut proto = make_protocol();
        proto.set_transport(TransportProtocol::Ssh);
        // if set_transport did not panic, we consider this path covered
    }

    /// Wire hash kind expects SHA1 length; providing SHA256 refs should error.
    #[tokio::test]
    async fn info_refs_hash_length_mismatch_errors() {
        let proto = GitProtocol::new(
            MockRepo {
                refs: vec![(
                    "refs/heads/main".to_string(),
                    "f".repeat(HashKind::Sha256.hex_len()),
                )],
            },
            MockAuth,
        );
        let err = proto.info_refs("git-upload-pack").await.unwrap_err();
        assert!(matches!(err, ProtocolError::InvalidRequest(_)));
    }

    /// Mock repo that reports a fixed object-hash kind and serves one blob.
    #[derive(Clone)]
    struct FixedKindRepo {
        kind: HashKind,
        blob: Blob,
    }

    #[async_trait]
    impl RepositoryAccess for FixedKindRepo {
        fn object_hash_kind(&self) -> HashKind {
            self.kind
        }
        async fn get_repository_refs(&self) -> Result<Vec<(String, String)>, ProtocolError> {
            Ok(Vec::new())
        }
        async fn has_object(&self, object_hash: &str) -> Result<bool, ProtocolError> {
            Ok(object_hash == self.blob.id.to_string())
        }
        async fn get_object(&self, _object_hash: &str) -> Result<Vec<u8>, ProtocolError> {
            Ok(self.blob.data.clone())
        }
        async fn store_pack_data(&self, _pack_data: &[u8]) -> Result<(), ProtocolError> {
            Ok(())
        }
        async fn update_reference(
            &self,
            _ref_name: &str,
            _old_hash: Option<&str>,
            _new_hash: &str,
        ) -> Result<(), ProtocolError> {
            Ok(())
        }
        async fn get_objects_for_pack(
            &self,
            _wants: &[String],
            _haves: &[String],
        ) -> Result<Vec<String>, ProtocolError> {
            Ok(Vec::new())
        }
        async fn has_default_branch(&self) -> Result<bool, ProtocolError> {
            Ok(false)
        }
        async fn post_receive_hook(&self) -> Result<(), ProtocolError> {
            Ok(())
        }
    }

    /// `object_hash_kind()` defaults to the thread-local kind; an override drives the default
    /// object accessors, which parse hashes against it and fail closed on a width mismatch.
    #[tokio::test]
    async fn repository_hash_kind_default_and_override() {
        for (kind, other) in [
            (HashKind::Sha1, HashKind::Sha256),
            (HashKind::Sha256, HashKind::Sha1),
        ] {
            let _guard = set_hash_kind_for_test(kind);
            // Default implementation follows the thread-local kind.
            assert_eq!(MockRepo { refs: Vec::new() }.object_hash_kind(), kind);

            // Override wins over the thread-local kind.
            let blob = Blob::from_content_bytes_with_kind(other, b"hello".to_vec()).unwrap();
            let repo = FixedKindRepo {
                kind: other,
                blob: blob.clone(),
            };
            assert_eq!(repo.object_hash_kind(), other);

            let fetched = repo.get_blob(&blob.id.to_string()).await.unwrap();
            assert_eq!(fetched.id, blob.id);
            assert_eq!(fetched.id.kind(), other);

            // A hash of the thread-local kind's width is rejected for this repository.
            let wrong_width = ObjectHash::zero_for_kind(kind).to_string();
            for err in [
                repo.get_blob(&wrong_width).await.unwrap_err(),
                repo.get_commit(&wrong_width).await.unwrap_err(),
                repo.get_tree(&wrong_width).await.unwrap_err(),
            ] {
                let msg = err.to_string();
                assert!(msg.contains("Invalid hash format"), "{msg}");
                assert!(
                    msg.contains(other.as_str())
                        && msg.contains(&format!("expected {}", other.hex_len()))
                        && msg.contains(&format!("got {}", kind.hex_len())),
                    "{msg}"
                );
            }
        }
    }
}
