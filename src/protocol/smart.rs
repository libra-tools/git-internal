//! Implementation of the Git smart protocol state machine, handling capability negotiation, pkt
//! exchanges, authentication delegation, and bridging repository storage to transport streams.

use std::collections::HashMap;

use bytes::{BufMut, Bytes, BytesMut};
use tokio_stream::wrappers::ReceiverStream;

use super::{
    core::{AuthenticationService, RepositoryAccess},
    pack::PackGenerator,
    types::{
        COMMON_CAP_LIST, Capability, LF, NUL, PKT_LINE_END_MARKER, ProtocolError, ProtocolStream,
        RECEIVE_CAP_LIST, RefCommand, RefTypeEnum, SP, ServiceType, SideBand, TransportProtocol,
        UPLOAD_CAP_LIST,
    },
    utils::{add_pkt_line_string, build_smart_reply, read_pkt_line, read_until_white_space},
};
use crate::hash::{HashKind, ObjectHash, get_hash_kind};
/// Smart Git Protocol implementation
///
/// This struct handles the Git smart protocol operations for both HTTP and SSH transports.
/// It uses trait abstractions to decouple from specific business logic implementations.
pub struct SmartProtocol<R, A>
where
    R: RepositoryAccess,
    A: AuthenticationService,
{
    pub transport_protocol: TransportProtocol,
    pub capabilities: Vec<Capability>,
    pub side_band: Option<SideBand>,
    pub command_list: Vec<RefCommand>,
    pub wire_hash_kind: HashKind,
    pub local_hash_kind: HashKind,
    pub zero_id: String,
    // Trait-based dependencies
    repo_storage: R,
    auth_service: A,
}

impl<R, A> SmartProtocol<R, A>
where
    R: RepositoryAccess,
    A: AuthenticationService,
{
    /// Set the wire hash kind (sha1 or sha256)
    pub fn set_wire_hash_kind(&mut self, kind: HashKind) {
        self.wire_hash_kind = kind;
        self.zero_id = ObjectHash::zero_str(kind);
    }

    /// Create a new SmartProtocol instance
    pub fn new(transport_protocol: TransportProtocol, repo_storage: R, auth_service: A) -> Self {
        Self {
            transport_protocol,
            capabilities: Vec::new(),
            side_band: None,
            command_list: Vec::new(),
            repo_storage,
            auth_service,
            wire_hash_kind: HashKind::default(), // Default to SHA-1
            local_hash_kind: get_hash_kind(),
            zero_id: ObjectHash::zero_str(HashKind::default()),
        }
    }

    /// Authenticate an HTTP request using the injected auth service
    pub async fn authenticate_http(
        &self,
        headers: &HashMap<String, String>,
    ) -> Result<(), ProtocolError> {
        self.auth_service.authenticate_http(headers).await
    }

    /// Authenticate an SSH session using username and public key
    pub async fn authenticate_ssh(
        &self,
        username: &str,
        public_key: &[u8],
    ) -> Result<(), ProtocolError> {
        self.auth_service
            .authenticate_ssh(username, public_key)
            .await
    }

    /// Set transport protocol (Http, Ssh, etc.)
    pub fn set_transport_protocol(&mut self, protocol: TransportProtocol) {
        self.transport_protocol = protocol;
    }

    /// Get git info refs for the repository, with explicit service type
    pub async fn git_info_refs(
        &self,
        service_type: ServiceType,
    ) -> Result<BytesMut, ProtocolError> {
        let refs = self
            .repo_storage
            .get_repository_refs()
            .await
            .map_err(|e| ProtocolError::repository_error(format!("Failed to get refs: {e}")))?;
        let hex_len = self.wire_hash_kind.hex_len();
        for (name, h) in &refs {
            if h.len() != hex_len {
                return Err(ProtocolError::invalid_request(&format!(
                    "Hash length mismatch for ref {}: expected {}, got {}",
                    name,
                    hex_len,
                    h.len()
                )));
            }
        } // Ensure refs match the expected wire hash kind
        // Convert to the expected format (head_hash, git_refs)
        let head_hash = refs
            .iter()
            .find(|(name, _)| {
                name == "HEAD" || name.ends_with("/main") || name.ends_with("/master")
            })
            .map(|(_, hash)| hash.clone())
            .unwrap_or_else(|| self.zero_id.clone());

        let git_refs: Vec<super::types::GitRef> = refs
            .into_iter()
            .map(|(name, hash)| super::types::GitRef { name, hash })
            .collect();
        // capability add object-format, declare the wire hash kind (single source:
        // `HashKind::as_str`, no per-algorithm table here)
        let format_cap = format!(" object-format={}", self.wire_hash_kind.as_str());
        // Determine capabilities based on service type
        let cap_list = match service_type {
            ServiceType::UploadPack => format!("{UPLOAD_CAP_LIST}{COMMON_CAP_LIST}{format_cap}"),
            ServiceType::ReceivePack => format!("{RECEIVE_CAP_LIST}{COMMON_CAP_LIST}{format_cap}"),
        };

        // The stream MUST include capability declarations behind a NUL on the first ref.
        let name = if head_hash == self.zero_id {
            "capabilities^{}"
        } else {
            "HEAD"
        };
        let pkt_line = format!("{head_hash}{SP}{name}{NUL}{cap_list}{LF}");
        let mut ref_list = vec![pkt_line];

        for git_ref in git_refs {
            let pkt_line = format!("{}{}{}{}", git_ref.hash, SP, git_ref.name, LF);
            ref_list.push(pkt_line);
        }

        let pkt_line_stream =
            build_smart_reply(self.transport_protocol, &ref_list, service_type.to_string());
        tracing::debug!("git_info_refs, return: --------> {:?}", pkt_line_stream);
        Ok(pkt_line_stream)
    }

    /// Handle git-upload-pack request
    pub async fn git_upload_pack(
        &mut self,
        upload_request: Bytes,
    ) -> Result<(ReceiverStream<Vec<u8>>, BytesMut), ProtocolError> {
        self.capabilities.clear();
        self.set_wire_hash_kind(self.local_hash_kind);
        let mut upload_request = upload_request;
        let mut want: Vec<String> = Vec::new();
        let mut have: Vec<String> = Vec::new();
        let mut last_common_commit = String::new();

        let mut read_first_line = false;
        loop {
            let (bytes_take, pkt_line) = read_pkt_line(&mut upload_request);

            if bytes_take == 0 {
                break;
            }

            if pkt_line.is_empty() {
                break;
            }

            let mut pkt_line = pkt_line;
            let command = read_until_white_space(&mut pkt_line);

            match command.as_str() {
                "want" => {
                    let hash = read_until_white_space(&mut pkt_line);
                    want.push(hash);
                    if !read_first_line {
                        let cap_str = String::from_utf8_lossy(&pkt_line).to_string();
                        self.parse_capabilities(&cap_str);
                        read_first_line = true;
                    }
                }
                "have" => {
                    let hash = read_until_white_space(&mut pkt_line);
                    have.push(hash);
                }
                "done" => {
                    break;
                }
                _ => {
                    tracing::warn!("Unknown upload-pack command: {}", command);
                }
            }
        }

        let mut protocol_buf = BytesMut::new();

        // Create pack generator for this operation
        let pack_generator = PackGenerator::new(&self.repo_storage);

        if have.is_empty() {
            // Full pack
            add_pkt_line_string(&mut protocol_buf, String::from("NAK\n"));
            let pack_stream = pack_generator.generate_full_pack(want).await?;
            return Ok((pack_stream, protocol_buf));
        }

        // Check for common commits
        for hash in &have {
            let exists = self.repo_storage.commit_exists(hash).await.map_err(|e| {
                ProtocolError::repository_error(format!("Failed to check commit existence: {e}"))
            })?;
            if exists {
                add_pkt_line_string(&mut protocol_buf, format!("ACK {hash} common\n"));
                if last_common_commit.is_empty() {
                    last_common_commit = hash.clone();
                }
            }
        }

        if last_common_commit.is_empty() {
            // No common commits found
            add_pkt_line_string(&mut protocol_buf, String::from("NAK\n"));
            let pack_stream = pack_generator.generate_full_pack(want).await?;
            return Ok((pack_stream, protocol_buf));
        }

        // Generate incremental pack
        add_pkt_line_string(
            &mut protocol_buf,
            format!("ACK {last_common_commit} ready\n"),
        );

        let pack_stream = pack_generator.generate_incremental_pack(want, have).await?;

        Ok((pack_stream, protocol_buf))
    }

    /// Parse receive pack commands from protocol bytes
    pub fn parse_receive_pack_commands(&mut self, mut protocol_bytes: Bytes) {
        self.command_list.clear();
        self.capabilities.clear();
        self.set_wire_hash_kind(self.local_hash_kind);
        let mut first_line = true;
        loop {
            let (bytes_take, pkt_line) = read_pkt_line(&mut protocol_bytes);

            if bytes_take == 0 {
                break;
            }

            if pkt_line.is_empty() {
                break;
            }

            if first_line {
                if let Some(pos) = pkt_line.iter().position(|b| *b == b'\0') {
                    let caps = String::from_utf8_lossy(&pkt_line[(pos + 1)..]).to_string();
                    self.parse_capabilities(&caps);
                }
                first_line = false;
            }

            let ref_command = self.parse_ref_command(&mut pkt_line.clone());
            self.command_list.push(ref_command);
        }
    }

    /// Handle git receive-pack operation (push)
    pub async fn git_receive_pack_stream(
        &mut self,
        data_stream: ProtocolStream,
    ) -> Result<Bytes, ProtocolError> {
        // Collect all request data from stream
        let mut request_data = BytesMut::new();
        let mut stream = data_stream;

        while let Some(chunk_result) = futures::StreamExt::next(&mut stream).await {
            let chunk = chunk_result
                .map_err(|e| ProtocolError::invalid_request(&format!("Stream error: {e}")))?;
            request_data.extend_from_slice(&chunk);
        }

        let mut protocol_bytes = request_data.freeze();
        self.command_list.clear();
        self.capabilities.clear();
        self.set_wire_hash_kind(self.local_hash_kind);
        let mut first_line = true;
        let mut saw_flush = false;
        loop {
            let (bytes_take, pkt_line) = read_pkt_line(&mut protocol_bytes);

            if bytes_take == 0 {
                if protocol_bytes.is_empty() {
                    break;
                }
                return Err(ProtocolError::invalid_request(
                    "Invalid pkt-line in receive-pack request",
                ));
            }

            if pkt_line.is_empty() {
                saw_flush = true;
                break;
            }

            if first_line {
                if let Some(pos) = pkt_line.iter().position(|b| *b == b'\0') {
                    let caps = String::from_utf8_lossy(&pkt_line[(pos + 1)..]).to_string();
                    self.parse_capabilities(&caps);
                }
                first_line = false;
            }

            let ref_command = self.parse_ref_command(&mut pkt_line.clone());
            self.command_list.push(ref_command);
        }

        if !saw_flush {
            return Err(ProtocolError::invalid_request(
                "Missing flush before pack data",
            ));
        }

        // Remaining bytes (if any) are pack data.
        let pack_data = if protocol_bytes.is_empty() {
            None
        } else {
            Some(protocol_bytes)
        };

        if let Some(pack_data) = pack_data {
            // Create pack generator for unpacking
            let pack_generator = PackGenerator::new(&self.repo_storage);
            // Unpack the received data
            let (commits, trees, blobs) = pack_generator.unpack_stream(pack_data).await?;

            // Store the unpacked objects via the repository access trait
            self.repo_storage
                .handle_pack_objects(commits, trees, blobs)
                .await
                .map_err(|e| {
                    ProtocolError::repository_error(format!("Failed to store pack objects: {e}"))
                })?;
        }

        // Build status report
        let mut report_status = BytesMut::new();
        add_pkt_line_string(&mut report_status, "unpack ok\n".to_owned());

        let mut default_exist = self.repo_storage.has_default_branch().await.map_err(|e| {
            ProtocolError::repository_error(format!("Failed to check default branch: {e}"))
        })?;

        // Update refs with proper error handling
        for command in &mut self.command_list {
            if command.ref_type == RefTypeEnum::Tag {
                // Just update if refs type is tag
                // Convert zero_id to None for old hash
                let old_hash = if command.old_hash == self.zero_id {
                    None
                } else {
                    Some(command.old_hash.as_str())
                };
                if let Err(e) = self
                    .repo_storage
                    .update_reference(&command.ref_name, old_hash, &command.new_hash)
                    .await
                {
                    command.failed(e.to_string());
                }
            } else {
                // Handle default branch setting for the first branch
                if !default_exist {
                    command.default_branch = true;
                    default_exist = true;
                }
                // Convert zero_id to None for old hash
                let old_hash = if command.old_hash == self.zero_id {
                    None
                } else {
                    Some(command.old_hash.as_str())
                };
                if let Err(e) = self
                    .repo_storage
                    .update_reference(&command.ref_name, old_hash, &command.new_hash)
                    .await
                {
                    command.failed(e.to_string());
                }
            }
            add_pkt_line_string(&mut report_status, command.get_status());
        }

        // Post-receive hook
        self.repo_storage.post_receive_hook().await.map_err(|e| {
            ProtocolError::repository_error(format!("Post-receive hook failed: {e}"))
        })?;

        report_status.put(&PKT_LINE_END_MARKER[..]);
        Ok(report_status.freeze())
    }

    /// Builds the packet data in the sideband format if the SideBand/64k capability is enabled.
    pub fn build_side_band_format(&self, from_bytes: BytesMut, length: usize) -> BytesMut {
        let mut to_bytes = BytesMut::new();
        if self.capabilities.contains(&Capability::SideBand)
            || self.capabilities.contains(&Capability::SideBand64k)
        {
            let length = length + 5;
            to_bytes.put(Bytes::from(format!("{length:04x}")));
            to_bytes.put_u8(SideBand::PackfileData.value());
            to_bytes.put(from_bytes);
        } else {
            to_bytes.put(from_bytes);
        }
        to_bytes
    }

    /// Parse capabilities from capability string
    pub fn parse_capabilities(&mut self, cap_str: &str) {
        for cap in cap_str.split_whitespace() {
            if let Some(fmt) = cap.strip_prefix("object-format=") {
                // Single `HashKind` parser (GC-02); the wire value must be the exact
                // lowercase name (GC-13), so a case-variant is treated as unknown.
                match fmt.parse::<HashKind>() {
                    Ok(kind) if kind.as_str() == fmt => self.set_wire_hash_kind(kind),
                    _ => {
                        tracing::warn!("Unknown object-format capability: {}", fmt);
                    }
                }
                continue;
            }
            if let Ok(capability) = cap.parse::<Capability>() {
                self.capabilities.push(capability);
            }
        }
    }

    /// Parse a reference command from packet line
    pub fn parse_ref_command(&self, pkt_line: &mut Bytes) -> RefCommand {
        let old_id = read_until_white_space(pkt_line);
        let new_id = read_until_white_space(pkt_line);
        let ref_name = read_until_white_space(pkt_line);
        let _capabilities = String::from_utf8_lossy(&pkt_line[..]).to_string();

        RefCommand::new(old_id, new_id, ref_name)
    }
}

#[cfg(test)]
mod tests {
    use std::sync::{
        Arc, Mutex,
        atomic::{AtomicBool, Ordering},
    };

    use async_trait::async_trait;
    use bytes::BytesMut;
    use futures;
    use tokio::sync::mpsc;

    use super::*;
    use crate::protocol::utils; // import sibling module
    use crate::{
        hash::{HashKind, ObjectHash, set_hash_kind_for_test},
        internal::{
            metadata::{EntryMeta, MetaAttached},
            object::{
                blob::Blob,
                commit::Commit,
                signature::{Signature, SignatureType},
                tree::{Tree, TreeItem, TreeItemMode},
            },
            pack::{encode::PackEncoder, entry::Entry},
        },
    };

    // Simplify complex type via aliases to satisfy clippy::type_complexity
    type UpdateRecord = (String, Option<String>, String);
    type UpdateList = Vec<UpdateRecord>;
    type SharedUpdates = Arc<Mutex<UpdateList>>;

    /// Test repository access implementation for testing
    #[derive(Clone)]
    struct TestRepoAccess {
        updates: SharedUpdates,
        stored_count: Arc<Mutex<usize>>,
        default_branch_exists: Arc<Mutex<bool>>,
        post_called: Arc<AtomicBool>,
    }

    impl TestRepoAccess {
        fn new() -> Self {
            Self {
                updates: Arc::new(Mutex::new(vec![])),
                stored_count: Arc::new(Mutex::new(0)),
                default_branch_exists: Arc::new(Mutex::new(false)),
                post_called: Arc::new(AtomicBool::new(false)),
            }
        }

        fn updates_len(&self) -> usize {
            self.updates.lock().unwrap().len()
        }

        fn post_hook_called(&self) -> bool {
            self.post_called.load(Ordering::SeqCst)
        }
    }

    #[async_trait]
    impl RepositoryAccess for TestRepoAccess {
        async fn get_repository_refs(&self) -> Result<Vec<(String, String)>, ProtocolError> {
            Ok(vec![
                (
                    "HEAD".to_string(),
                    "0000000000000000000000000000000000000000".to_string(),
                ),
                (
                    "refs/heads/main".to_string(),
                    "1111111111111111111111111111111111111111".to_string(),
                ),
            ])
        }

        async fn has_object(&self, _object_hash: &str) -> Result<bool, ProtocolError> {
            Ok(true)
        }

        async fn get_object(&self, _object_hash: &str) -> Result<Vec<u8>, ProtocolError> {
            Ok(vec![])
        }

        async fn store_pack_data(&self, _pack_data: &[u8]) -> Result<(), ProtocolError> {
            *self.stored_count.lock().unwrap() += 1;
            Ok(())
        }

        async fn update_reference(
            &self,
            ref_name: &str,
            old_hash: Option<&str>,
            new_hash: &str,
        ) -> Result<(), ProtocolError> {
            self.updates.lock().unwrap().push((
                ref_name.to_string(),
                old_hash.map(|s| s.to_string()),
                new_hash.to_string(),
            ));
            Ok(())
        }

        async fn get_objects_for_pack(
            &self,
            _wants: &[String],
            _haves: &[String],
        ) -> Result<Vec<String>, ProtocolError> {
            Ok(vec![])
        }

        async fn has_default_branch(&self) -> Result<bool, ProtocolError> {
            let mut exists = self.default_branch_exists.lock().unwrap();
            let current = *exists;
            *exists = true; // flip to true after first check
            Ok(current)
        }

        async fn post_receive_hook(&self) -> Result<(), ProtocolError> {
            self.post_called.store(true, Ordering::SeqCst);
            Ok(())
        }
    }

    /// Test authentication service implementation for testing
    struct TestAuth;

    #[async_trait]
    impl AuthenticationService for TestAuth {
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

    /// Receive-pack stream decodes the pack, updates refs, and reports status (SHA-1).
    #[tokio::test]
    async fn test_receive_pack_stream_status_report() {
        let _guard = set_hash_kind_for_test(HashKind::Sha1);
        // Build simple objects
        let blob1 = Blob::from_content("hello");
        let blob2 = Blob::from_content("world");

        let item1 = TreeItem::new(TreeItemMode::Blob, blob1.id, "hello.txt".to_string());
        let item2 = TreeItem::new(TreeItemMode::Blob, blob2.id, "world.txt".to_string());
        let tree = Tree::from_tree_items(vec![item1, item2]).unwrap();

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

        // Encode pack bytes via PackEncoder
        let (pack_tx, mut pack_rx) = mpsc::channel(1024);
        let (entry_tx, entry_rx) = mpsc::channel(1024);
        let mut encoder = PackEncoder::new(4, 10, pack_tx);

        tokio::spawn(async move {
            if let Err(e) = encoder.encode(entry_rx).await {
                panic!("Failed to encode pack: {}", e);
            }
        });

        let commit_clone = commit.clone();
        let tree_clone = tree.clone();
        let blob1_clone = blob1.clone();
        let blob2_clone = blob2.clone();
        tokio::spawn(async move {
            let _ = entry_tx
                .send(MetaAttached {
                    inner: Entry::from(commit_clone),
                    meta: EntryMeta::new(),
                })
                .await;
            let _ = entry_tx
                .send(MetaAttached {
                    inner: Entry::from(tree_clone),
                    meta: EntryMeta::new(),
                })
                .await;
            let _ = entry_tx
                .send(MetaAttached {
                    inner: Entry::from(blob1_clone),
                    meta: EntryMeta::new(),
                })
                .await;
            let _ = entry_tx
                .send(MetaAttached {
                    inner: Entry::from(blob2_clone),
                    meta: EntryMeta::new(),
                })
                .await;
            // sender drop indicates end
        });

        let mut pack_bytes: Vec<u8> = Vec::new();
        while let Some(chunk) = pack_rx.recv().await {
            pack_bytes.extend_from_slice(&chunk);
        }

        // Prepare protocol and request
        let repo_access = TestRepoAccess::new();
        let auth = TestAuth;
        let mut smart = SmartProtocol::new(TransportProtocol::Http, repo_access.clone(), auth);
        smart.set_wire_hash_kind(HashKind::Sha1);

        let mut request = BytesMut::new();
        add_pkt_line_string(
            &mut request,
            format!(
                "{} {} refs/heads/main\0report-status\n",
                smart.zero_id, commit.id
            ),
        );
        request.put(&PKT_LINE_END_MARKER[..]);
        request.extend_from_slice(&pack_bytes);

        // Create request stream
        let request_stream = Box::pin(futures::stream::once(async { Ok(request.freeze()) }));

        // Execute receive-pack
        let result_bytes = smart
            .git_receive_pack_stream(request_stream)
            .await
            .expect("receive-pack should succeed");

        // Verify pkt-lines
        let mut out = result_bytes.clone();
        let (_c1, l1) = utils::read_pkt_line(&mut out);
        assert_eq!(String::from_utf8(l1.to_vec()).unwrap(), "unpack ok\n");

        let (_c2, l2) = utils::read_pkt_line(&mut out);
        assert_eq!(
            String::from_utf8(l2.to_vec()).unwrap(),
            "ok refs/heads/main"
        );

        let (c3, l3) = utils::read_pkt_line(&mut out);
        assert_eq!(c3, 4);
        assert!(l3.is_empty());

        // Verify side effects
        assert_eq!(repo_access.updates_len(), 1);
        assert!(repo_access.post_hook_called());
    }

    /// info-refs rejects SHA-256 wire format when repository refs are still SHA-1.
    #[tokio::test]
    async fn info_refs_rejects_sha256_with_sha1_refs() {
        let _guard = set_hash_kind_for_test(HashKind::Sha1); // avoid thread-local contamination
        let repo_access = TestRepoAccess::new(); // still returns 40-char strings
        let auth = TestAuth;
        let mut smart = SmartProtocol::new(TransportProtocol::Http, repo_access, auth);
        smart.set_wire_hash_kind(HashKind::Sha256); // claims wire uses SHA-256
        // expect failure because refs are SHA-1
        let res = smart.git_info_refs(ServiceType::UploadPack).await;
        assert!(res.is_err(), "expected failure when hash lengths mismatch");

        smart.set_wire_hash_kind(HashKind::Sha1);

        let res = smart.git_info_refs(ServiceType::UploadPack).await;
        assert!(
            res.is_ok(),
            "expected SHA1 refs to be accepted when wire is SHA1"
        );
    }

    /// Unknown or non-canonical (mixed-case) object-format values are ignored with a warning
    /// and leave the wire kind untouched; exact lowercase values are accepted.
    #[test]
    fn parse_capabilities_ignores_unknown_and_mixed_case_object_format() {
        let _guard = set_hash_kind_for_test(HashKind::Sha1);
        let mut smart =
            SmartProtocol::new(TransportProtocol::Http, TestRepoAccess::new(), TestAuth);
        assert_eq!(smart.wire_hash_kind, HashKind::Sha1);

        smart.parse_capabilities("object-format=SHA256 side-band-64k");
        assert_eq!(smart.wire_hash_kind, HashKind::Sha1);
        assert_eq!(smart.zero_id, ObjectHash::zero_str(HashKind::Sha1));

        smart.parse_capabilities("object-format=md5");
        assert_eq!(smart.wire_hash_kind, HashKind::Sha1);

        smart.parse_capabilities("object-format=sha256");
        assert_eq!(smart.wire_hash_kind, HashKind::Sha256);
        assert_eq!(smart.zero_id, ObjectHash::zero_str(HashKind::Sha256));

        smart.parse_capabilities("object-format=sha1");
        assert_eq!(smart.wire_hash_kind, HashKind::Sha1);
    }

    /// parse_capabilities should switch wire hash kind and record declared capabilities.
    #[tokio::test]
    async fn parse_capabilities_updates_hash_and_caps() {
        let _guard = set_hash_kind_for_test(HashKind::Sha1);
        let repo_access = TestRepoAccess::new();
        let auth = TestAuth;
        let mut smart = SmartProtocol::new(TransportProtocol::Http, repo_access, auth);

        smart.parse_capabilities("object-format=sha256 side-band-64k multi_ack");

        assert_eq!(smart.wire_hash_kind, HashKind::Sha256);
        assert_eq!(smart.zero_id.len(), HashKind::Sha256.hex_len());
        assert!(
            smart.capabilities.contains(&Capability::SideBand64k),
            "side-band-64k should be recorded"
        );
    }

    /// info-refs should accept SHA-256 refs and emit the matching object-format capability.
    #[tokio::test]
    async fn info_refs_accepts_sha256_refs_and_emits_capability() {
        // Define a repo access that returns SHA-256 refs
        #[derive(Clone)]
        struct Sha256Repo;

        #[async_trait]
        impl RepositoryAccess for Sha256Repo {
            async fn get_repository_refs(&self) -> Result<Vec<(String, String)>, ProtocolError> {
                Ok(vec![
                    (
                        "HEAD".to_string(),
                        "0000000000000000000000000000000000000000000000000000000000000000"
                            .to_string(),
                    ),
                    (
                        "refs/heads/main".to_string(),
                        "1111111111111111111111111111111111111111111111111111111111111111"
                            .to_string(),
                    ),
                ])
            }
            async fn has_object(&self, _object_hash: &str) -> Result<bool, ProtocolError> {
                Ok(true)
            }
            async fn get_object(&self, _object_hash: &str) -> Result<Vec<u8>, ProtocolError> {
                Ok(vec![])
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
                Ok(vec![])
            }
            async fn has_default_branch(&self) -> Result<bool, ProtocolError> {
                Ok(false)
            }
            async fn post_receive_hook(&self) -> Result<(), ProtocolError> {
                Ok(())
            }
        }

        let _guard = set_hash_kind_for_test(HashKind::Sha1);
        let repo_access = Sha256Repo;
        let auth = TestAuth;
        let mut smart = SmartProtocol::new(TransportProtocol::Http, repo_access, auth);
        smart.set_wire_hash_kind(HashKind::Sha256);

        let resp = smart
            .git_info_refs(ServiceType::UploadPack)
            .await
            .expect("sha256 refs should be accepted");
        let resp_str = String::from_utf8(resp.to_vec()).expect("pkt-line should be valid UTF-8");
        assert!(
            resp_str.contains("object-format=sha256"),
            "capability line should advertise sha256"
        );
    }

    /// parse_receive_pack_commands should decode multiple pkt-lines into RefCommand list.
    #[tokio::test]
    async fn parse_receive_pack_commands_decodes_commands() {
        let _guard = set_hash_kind_for_test(HashKind::Sha1);
        let repo_access = TestRepoAccess::new();
        let auth = TestAuth;
        let mut smart = SmartProtocol::new(TransportProtocol::Http, repo_access, auth);

        let zero = ObjectHash::zero_str(HashKind::Sha1);
        let mut pkt = BytesMut::new();
        add_pkt_line_string(&mut pkt, format!("{zero} {zero} refs/heads/main\n"));
        add_pkt_line_string(&mut pkt, format!("{zero} {zero} refs/tags/v1.0\n"));
        pkt.put(&PKT_LINE_END_MARKER[..]);

        smart.parse_receive_pack_commands(pkt.freeze());

        assert_eq!(smart.command_list.len(), 2);
        assert_eq!(smart.command_list[0].ref_name, "refs/heads/main");
        assert_eq!(smart.command_list[1].ref_name, "refs/tags/v1.0");
    }

    /// receive-pack should error if ref commands are not terminated by a flush.
    #[tokio::test]
    async fn receive_pack_missing_flush_errors() {
        let _guard = set_hash_kind_for_test(HashKind::Sha1);
        let repo_access = TestRepoAccess::new();
        let auth = TestAuth;
        let mut smart = SmartProtocol::new(TransportProtocol::Http, repo_access, auth);

        let zero = ObjectHash::zero_str(HashKind::Sha1);
        let mut pkt = BytesMut::new();
        add_pkt_line_string(&mut pkt, format!("{zero} {zero} refs/heads/main\n"));

        let request_stream = Box::pin(futures::stream::once(async { Ok(pkt.freeze()) }));
        let err = smart
            .git_receive_pack_stream(request_stream)
            .await
            .unwrap_err();
        assert!(matches!(err, ProtocolError::InvalidRequest(_)));
    }
}
