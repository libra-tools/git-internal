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
use crate::hash::{HashKind, ObjectHash};
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
    /// Set the wire hash kind (sha1, sha256 or blake3) and the matching zero ID.
    ///
    /// The wire kind must equal the repository's format
    /// (`RepositoryAccess::object_hash_kind`) and `local_hash_kind`: every protocol
    /// operation re-checks the three with [`SmartProtocol::ensure_hash_kind_consistency`]
    /// and fails closed on a divergence, so this setter cannot be used to serve a
    /// repository under another object format.
    pub fn set_wire_hash_kind(&mut self, kind: HashKind) {
        self.wire_hash_kind = kind;
        self.zero_id = ObjectHash::zero_str(kind);
    }

    /// Create a new SmartProtocol instance.
    ///
    /// The local and wire hash kinds (and the zero ID) are bound to the repository's own
    /// object format, `RepositoryAccess::object_hash_kind()` — which defaults to the
    /// thread-local kind for implementors that do not override it — so a SHA-1, SHA-256 or
    /// BLAKE3 (git-internal / Libra extension) repository advertises and accepts exactly its
    /// own `object-format`. Nothing is inferred from ID widths.
    pub fn new(transport_protocol: TransportProtocol, repo_storage: R, auth_service: A) -> Self {
        let local_hash_kind = repo_storage.object_hash_kind();
        Self {
            transport_protocol,
            capabilities: Vec::new(),
            side_band: None,
            command_list: Vec::new(),
            repo_storage,
            auth_service,
            wire_hash_kind: local_hash_kind,
            local_hash_kind,
            zero_id: ObjectHash::zero_str(local_hash_kind),
        }
    }

    /// Verify that the repository object format, the local kind bound at construction and
    /// the negotiated wire kind agree (ADR-GI-B3-03).
    ///
    /// Every protocol operation calls this before touching refs, objects or pack bytes. A
    /// divergence — a wire `object-format` that differs from the repository, a
    /// [`SmartProtocol::set_wire_hash_kind`] override, or a `RepositoryAccess` whose kind
    /// changed after construction — is a diagnosable `InvalidRequest` naming all three kinds;
    /// there is no fallback to another format.
    pub fn ensure_hash_kind_consistency(&self) -> Result<(), ProtocolError> {
        let repository = self.repo_storage.object_hash_kind();
        if repository != self.local_hash_kind || self.wire_hash_kind != self.local_hash_kind {
            return Err(ProtocolError::object_format_mismatch(
                self.wire_hash_kind,
                self.local_hash_kind,
                repository,
            ));
        }
        // The (public) zero ID must be the wire kind's zero ID: create/delete semantics of
        // receive-pack commands depend on it, so a tampered value fails closed too.
        let expected_zero = ObjectHash::zero_str(self.wire_hash_kind);
        if self.zero_id != expected_zero {
            return Err(ProtocolError::invalid_request(&format!(
                "zero ID `{}` does not match object-format {} (expected {} hex zeros)",
                self.zero_id.chars().take(80).collect::<String>(),
                self.wire_hash_kind.as_str(),
                self.wire_hash_kind.hex_len()
            )));
        }
        Ok(())
    }

    /// Parse a raw object ID received on the wire against the negotiated wire kind (GC-13).
    ///
    /// Exactly `wire_hash_kind.hex_len()` lowercase hex characters are accepted (fixed-length
    /// check, then hex decode). A wrong width (for example a 40-hex SHA-1 ID on a BLAKE3
    /// wire), uppercase or non-hex characters, or a tagged ID such as `blake3:HEX` is a
    /// diagnosable `InvalidRequest` naming the pkt-line command. Returns the canonical raw hex.
    fn parse_wire_id(&self, command: &str, id: &str) -> Result<String, ProtocolError> {
        let hash = ObjectHash::from_hex_for_kind(self.wire_hash_kind, id)
            .map_err(|e| ProtocolError::invalid_wire_id(command, id, &e))?;
        if id.bytes().any(|b| b.is_ascii_uppercase()) {
            return Err(ProtocolError::invalid_wire_id(
                command,
                id,
                &format!(
                    "object IDs on the wire must be raw lowercase hex (expected {} lowercase hex chars for {}, got uppercase characters)",
                    self.wire_hash_kind.hex_len(),
                    self.wire_hash_kind.as_str()
                ),
            ));
        }
        Ok(hash.to_string())
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
        // The advertised object-format is the repository's own format: refuse to advertise
        // (or serve) anything else before touching the repository (ADR-GI-B3-03).
        self.ensure_hash_kind_consistency()?;
        let refs = self
            .repo_storage
            .get_repository_refs()
            .await
            .map_err(|e| ProtocolError::repository_error(format!("Failed to get refs: {e}")))?;
        // Re-check after the await: the binding must still hold when the refs are advertised.
        self.ensure_hash_kind_consistency()?;
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
            // Advertised IDs must be canonical raw lowercase hex of the wire kind (GC-13): a
            // same-width ID of another namespace, a tagged ID or uppercase hex cannot be told
            // apart by a peer, so it is refused here rather than advertised.
            self.parse_wire_id("info-refs", h).map_err(|e| {
                ProtocolError::invalid_request(&format!("Invalid hash for ref {name}: {e}"))
            })?;
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
        // `HashKind::as_str`, no per-algorithm table here). `sha1`/`sha256` are the
        // standard Git values; `blake3` is the git-internal / Libra extension.
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

    /// Handle git-upload-pack request.
    ///
    /// The returned pack stream carries `Result` items: a failure inside the pack producer
    /// (encoder error, object of another format) arrives as an `Err` item so the transport
    /// can report it, instead of an EOF that looks like a truncated pack.
    pub async fn git_upload_pack(
        &mut self,
        upload_request: Bytes,
    ) -> Result<(ReceiverStream<Result<Vec<u8>, ProtocolError>>, BytesMut), ProtocolError> {
        self.capabilities.clear();
        // Validate the current binding *before* touching anything: a wire kind that was driven
        // away from the repository, or a repository whose kind changed, is an error — never
        // silently re-bound. Capabilities may then confirm the repository kind, not change it.
        self.ensure_hash_kind_consistency()?;
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
                    if !read_first_line {
                        // Capabilities first, so an object-format mismatch is reported as
                        // such rather than as a malformed ID.
                        let cap_str = String::from_utf8_lossy(&pkt_line).to_string();
                        self.parse_capabilities(&cap_str)?;
                        read_first_line = true;
                    }
                    want.push(self.parse_wire_id("want", &hash)?);
                }
                "have" => {
                    let hash = read_until_white_space(&mut pkt_line);
                    have.push(self.parse_wire_id("have", &hash)?);
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

        // Create pack generator for this operation, bound to the kind validated above (the
        // generator never re-reads `object_hash_kind()` after an `.await`).
        let pack_generator =
            PackGenerator::new_with_hash_kind(&self.repo_storage, self.local_hash_kind);

        if have.is_empty() {
            // Full pack
            add_pkt_line_string(&mut protocol_buf, String::from("NAK\n"));
            self.ensure_hash_kind_consistency()?;
            let pack_stream = pack_generator.generate_full_pack(want).await?;
            // Re-check after object collection: no drift during the awaits may reach the client.
            self.ensure_hash_kind_consistency()?;
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

        // Re-check after the `commit_exists` awaits, before any pack is produced.
        self.ensure_hash_kind_consistency()?;
        if last_common_commit.is_empty() {
            // No common commits found
            add_pkt_line_string(&mut protocol_buf, String::from("NAK\n"));
            let pack_stream = pack_generator.generate_full_pack(want).await?;
            self.ensure_hash_kind_consistency()?;
            return Ok((pack_stream, protocol_buf));
        }

        // Generate incremental pack
        add_pkt_line_string(
            &mut protocol_buf,
            format!("ACK {last_common_commit} ready\n"),
        );

        let pack_stream = pack_generator.generate_incremental_pack(want, have).await?;
        self.ensure_hash_kind_consistency()?;

        Ok((pack_stream, protocol_buf))
    }

    /// Parse receive-pack commands from protocol bytes.
    ///
    /// Fails closed (`InvalidRequest`) on an object-format capability that is unknown or
    /// differs from the repository, and on any command whose IDs are not raw lowercase hex
    /// of the wire kind; `command_list` then holds the commands parsed so far.
    pub fn parse_receive_pack_commands(
        &mut self,
        mut protocol_bytes: Bytes,
    ) -> Result<(), ProtocolError> {
        self.command_list.clear();
        self.capabilities.clear();
        // Validate before parsing (see `git_upload_pack`): no silent re-binding.
        self.ensure_hash_kind_consistency()?;
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
                    self.parse_capabilities(&caps)?;
                }
                first_line = false;
            }

            let ref_command = self.parse_ref_command(&mut pkt_line.clone())?;
            self.command_list.push(ref_command);
        }
        Ok(())
    }

    /// Handle git receive-pack operation (push)
    pub async fn git_receive_pack_stream(
        &mut self,
        data_stream: ProtocolStream,
    ) -> Result<Bytes, ProtocolError> {
        // Fail closed before a single request byte is read: the binding must be consistent
        // (repository == local == wire) before pack bytes or commands are accepted.
        self.ensure_hash_kind_consistency()?;

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
        // Re-check after the awaited drain: the binding must still hold when commands are
        // parsed (a repository following a drifting thread-local kind cannot slip through
        // by omitting `object-format`).
        self.ensure_hash_kind_consistency()?;
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
                    self.parse_capabilities(&caps)?;
                }
                first_line = false;
            }

            let ref_command = self.parse_ref_command(&mut pkt_line.clone())?;
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
            // Create pack generator for unpacking, bound to the kind validated above; it
            // decodes against that format (a pack of another kind fails closed at the
            // trailer/ID check).
            let pack_generator =
                PackGenerator::new_with_hash_kind(&self.repo_storage, self.local_hash_kind);
            // Unpack the received data
            let (commits, trees, blobs) = pack_generator.unpack_stream(pack_data).await?;
            // Re-check before the first side effect (storing objects).
            self.ensure_hash_kind_consistency()?;

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

        // Update refs with proper error handling. The binding is re-checked before *every*
        // ref write (an `update_reference` may itself change the repository's reported kind)
        // and once more after the last one, before the success report goes out.
        let mut commands = std::mem::take(&mut self.command_list);
        let mut update_result = Ok(());
        for command in &mut commands {
            if let Err(e) = self.ensure_hash_kind_consistency() {
                update_result = Err(e);
                break;
            }
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
        self.command_list = commands;
        update_result?;
        self.ensure_hash_kind_consistency()?;

        // Post-receive hook
        self.repo_storage.post_receive_hook().await.map_err(|e| {
            ProtocolError::repository_error(format!("Post-receive hook failed: {e}"))
        })?;
        // Final check after the last await: a drifted repository never gets a success report.
        self.ensure_hash_kind_consistency()?;

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

    /// Parse the capability list of the first pkt-line of a request.
    ///
    /// `object-format=<name>` goes through the single `HashKind` parser (GC-02) as an exact
    /// lowercase value (GC-13): `sha1` and `sha256` are the standard Git formats, `blake3` is
    /// the git-internal / Libra extension. An unknown or non-canonical value, or a known
    /// value that differs from the repository's format, is a diagnosable `InvalidRequest`
    /// (fail-closed: no warn-and-ignore, no fallback); the wire kind and zero ID are only
    /// updated on success. Other capabilities are recorded as before.
    pub fn parse_capabilities(&mut self, cap_str: &str) -> Result<(), ProtocolError> {
        // The current binding must already be consistent: a wire kind that was driven away
        // from the repository is an error here too, never silently reset by a capability.
        self.ensure_hash_kind_consistency()?;
        for cap in cap_str.split_whitespace() {
            if let Some(fmt) = cap.strip_prefix("object-format=") {
                let kind = match fmt.parse::<HashKind>() {
                    Ok(kind) if kind.as_str() == fmt => kind,
                    _ => return Err(ProtocolError::unknown_object_format(fmt)),
                };
                // The peer's format must equal both the kind bound at construction and the
                // repository's *current* kind, so a repository that changed kind after
                // construction cannot be served through a stale capability.
                let repository = self.repo_storage.object_hash_kind();
                if kind != self.local_hash_kind || kind != repository {
                    return Err(ProtocolError::object_format_mismatch(
                        kind,
                        self.local_hash_kind,
                        repository,
                    ));
                }
                self.set_wire_hash_kind(kind);
                // Record the negotiated format alongside the other capabilities.
                self.capabilities
                    .push(Capability::ObjectFormat(kind.as_str().to_string()));
                continue;
            }
            if let Ok(capability) = cap.parse::<Capability>() {
                self.capabilities.push(capability);
            }
        }
        Ok(())
    }

    /// Parse a reference command (`<old-id> <new-id> <ref-name>`) from a pkt-line.
    ///
    /// Both IDs must be raw lowercase hex of the wire kind (the zero ID included): a wrong
    /// width (for example a 40-hex SHA-1 ID on a BLAKE3 wire), non-hex characters, a tagged
    /// ID or a missing ref name is a diagnosable `InvalidRequest`.
    pub fn parse_ref_command(&self, pkt_line: &mut Bytes) -> Result<RefCommand, ProtocolError> {
        let old_id = read_until_white_space(pkt_line);
        let new_id = read_until_white_space(pkt_line);
        let ref_name = read_until_white_space(pkt_line);
        let _capabilities = String::from_utf8_lossy(&pkt_line[..]).to_string();

        let old_id = self.parse_wire_id("receive-pack old-id", &old_id)?;
        let new_id = self.parse_wire_id("receive-pack new-id", &new_id)?;
        if ref_name.is_empty() {
            return Err(ProtocolError::invalid_request(
                "receive-pack command is missing the ref name",
            ));
        }
        Ok(RefCommand::new(old_id, new_id, ref_name))
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

    /// Test repository access implementation for testing (SHA-1 by default; `with_kind`
    /// serves a repository of another object format, independent of the thread-local kind).
    #[derive(Clone)]
    struct TestRepoAccess {
        kind: HashKind,
        updates: SharedUpdates,
        stored_count: Arc<Mutex<usize>>,
        default_branch_exists: Arc<Mutex<bool>>,
        post_called: Arc<AtomicBool>,
    }

    impl TestRepoAccess {
        fn new() -> Self {
            Self::with_kind(HashKind::Sha1)
        }

        fn with_kind(kind: HashKind) -> Self {
            Self {
                kind,
                updates: Arc::new(Mutex::new(vec![])),
                stored_count: Arc::new(Mutex::new(0)),
                default_branch_exists: Arc::new(Mutex::new(false)),
                post_called: Arc::new(AtomicBool::new(false)),
            }
        }

        fn recorded_updates(&self) -> UpdateList {
            self.updates.lock().unwrap().clone()
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
        fn object_hash_kind(&self) -> HashKind {
            self.kind
        }

        async fn get_repository_refs(&self) -> Result<Vec<(String, String)>, ProtocolError> {
            Ok(vec![
                ("HEAD".to_string(), ObjectHash::zero_str(self.kind)),
                (
                    "refs/heads/main".to_string(),
                    "1".repeat(self.kind.hex_len()),
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

    fn blake3_repo_and_protocol() -> (TestRepoAccess, SmartProtocol<TestRepoAccess, TestAuth>) {
        let repo = TestRepoAccess::with_kind(HashKind::Blake3);
        let smart = SmartProtocol::new(TransportProtocol::Http, repo.clone(), TestAuth);
        (repo, smart)
    }

    /// A BLAKE3 repository advertises and accepts `object-format=blake3` (git-internal /
    /// Libra extension) with a 64-hex zero ID, independent of the thread-local kind; SHA-1
    /// and SHA-256 repositories keep their existing capability output.
    #[tokio::test]
    async fn blake3_capability() {
        let _guard = set_hash_kind_for_test(HashKind::Sha1);
        let (_repo, mut smart) = blake3_repo_and_protocol();
        assert_eq!(smart.wire_hash_kind, HashKind::Blake3);
        assert_eq!(smart.local_hash_kind, HashKind::Blake3);
        assert_eq!(smart.zero_id, "0".repeat(64));

        let resp = smart.git_info_refs(ServiceType::UploadPack).await.unwrap();
        let resp_str = String::from_utf8(resp.to_vec()).unwrap();
        assert!(resp_str.contains(" object-format=blake3"), "{resp_str}");
        assert!(
            resp_str.contains(&format!("{} refs/heads/main", "1".repeat(64))),
            "{resp_str}"
        );
        assert!(!resp_str.contains("object-format=sha"), "{resp_str}");

        smart
            .parse_capabilities("report-status object-format=blake3 side-band-64k")
            .unwrap();
        assert_eq!(smart.wire_hash_kind, HashKind::Blake3);
        assert_eq!(smart.zero_id.len(), HashKind::Blake3.hex_len());
        assert!(smart.capabilities.contains(&Capability::SideBand64k));
        assert!(smart.capabilities.contains(&Capability::ReportStatus));
        assert!(
            smart
                .capabilities
                .contains(&Capability::ObjectFormat("blake3".to_string()))
        );

        // A ref whose ID is not canonical raw lowercase hex of the wire kind (same width,
        // uppercase / non-hex / tagged) is refused instead of advertised.
        for bad in [
            "A".repeat(64),
            "zz".repeat(32),
            format!("blake3:{}", "1".repeat(57)),
        ] {
            let repo = BadRefRepo {
                kind: HashKind::Blake3,
                id: bad.clone(),
            };
            let smart = SmartProtocol::new(TransportProtocol::Http, repo, TestAuth);
            let err = smart
                .git_info_refs(ServiceType::UploadPack)
                .await
                .unwrap_err();
            assert!(
                matches!(err, ProtocolError::InvalidRequest(_)),
                "{bad}: {err:?}"
            );
            assert!(
                err.to_string().contains("Invalid hash for ref"),
                "{bad}: {err}"
            );
        }

        // Standard formats are unchanged: exact lowercase value, matching zero ID.
        for kind in [HashKind::Sha1, HashKind::Sha256] {
            let repo = TestRepoAccess::with_kind(kind);
            let mut smart = SmartProtocol::new(TransportProtocol::Http, repo, TestAuth);
            let resp = smart.git_info_refs(ServiceType::ReceivePack).await.unwrap();
            let resp_str = String::from_utf8(resp.to_vec()).unwrap();
            assert!(
                resp_str.contains(&format!(" object-format={}", kind.as_str())),
                "{resp_str}"
            );
            smart
                .parse_capabilities(&format!("object-format={} side-band", kind.as_str()))
                .unwrap();
            assert_eq!(smart.wire_hash_kind, kind);
            assert_eq!(smart.zero_id, ObjectHash::zero_str(kind));
        }
    }

    /// On a BLAKE3 wire the zero ID is 64 hex zeros: a create-ref command with it maps to
    /// `old_hash = None`, while the SHA-1 zero ID, a tagged ID, uppercase hex and a wrong
    /// width are rejected with diagnosable errors (GC-13).
    #[tokio::test]
    async fn blake3_zero_id() {
        let _guard = set_hash_kind_for_test(HashKind::Sha1);
        let (repo, mut smart) = blake3_repo_and_protocol();
        let zero = smart.zero_id.clone();
        let new_id = "a".repeat(64);

        let mut pkt = BytesMut::new();
        add_pkt_line_string(
            &mut pkt,
            format!("{zero} {new_id} refs/heads/main\0report-status object-format=blake3\n"),
        );
        add_pkt_line_string(&mut pkt, format!("{new_id} {zero} refs/tags/v1.0\n"));
        pkt.put(&PKT_LINE_END_MARKER[..]);
        smart
            .parse_receive_pack_commands(pkt.clone().freeze())
            .unwrap();
        assert_eq!(smart.command_list.len(), 2);
        assert_eq!(smart.command_list[0].old_hash, zero);
        assert_eq!(smart.command_list[0].new_hash, new_id);
        assert_eq!(smart.command_list[1].ref_name, "refs/tags/v1.0");

        // Commands only (no pack payload): the BLAKE3 zero ID becomes `None` for the store.
        let request_stream = Box::pin(futures::stream::once(async { Ok(pkt.freeze()) }));
        let report = smart.git_receive_pack_stream(request_stream).await.unwrap();
        assert!(report.starts_with(b"000eunpack ok\n"), "{report:?}");
        assert_eq!(
            repo.recorded_updates(),
            vec![
                ("refs/heads/main".to_string(), None, new_id.clone()),
                (
                    "refs/tags/v1.0".to_string(),
                    Some(new_id.clone()),
                    zero.clone()
                ),
            ]
        );

        let sha1_zero = ObjectHash::zero_str(HashKind::Sha1);
        let tagged = format!("blake3:{new_id}");
        let upper = new_id.to_uppercase();
        for (old, new, needle) in [
            (sha1_zero.as_str(), new_id.as_str(), "old-id"),
            (zero.as_str(), tagged.as_str(), "new-id"),
            (zero.as_str(), upper.as_str(), "lowercase"),
            (zero.as_str(), &new_id[..63], "expected 64"),
        ] {
            let mut pkt = BytesMut::new();
            add_pkt_line_string(&mut pkt, format!("{old} {new} refs/heads/main\n"));
            pkt.put(&PKT_LINE_END_MARKER[..]);
            let err = smart.parse_receive_pack_commands(pkt.freeze()).unwrap_err();
            assert!(matches!(err, ProtocolError::InvalidRequest(_)), "{err:?}");
            assert!(err.to_string().contains(needle), "{err}");
            assert!(smart.command_list.is_empty());
        }
    }

    /// object-format negotiation fails closed: unknown or non-canonical values, a known
    /// value that differs from the repository, a wire kind overridden away from the
    /// repository, and want/have IDs of the wrong width or shape are diagnosable errors,
    /// never a warning or a fallback.
    #[tokio::test]
    async fn object_format_mismatch() {
        let _guard = set_hash_kind_for_test(HashKind::Sha1);
        let mut smart =
            SmartProtocol::new(TransportProtocol::Http, TestRepoAccess::new(), TestAuth);
        for (caps, needle) in [
            (
                "object-format=SHA256 side-band-64k",
                "unknown object-format",
            ),
            ("object-format=md5", "unknown object-format"),
            (
                "object-format=sha256",
                "mismatch: wire=sha256 local=sha1 repository=sha1",
            ),
            (
                "object-format=blake3",
                "mismatch: wire=blake3 local=sha1 repository=sha1",
            ),
        ] {
            let err = smart.parse_capabilities(caps).unwrap_err();
            assert!(matches!(err, ProtocolError::InvalidRequest(_)), "{err:?}");
            assert!(err.to_string().contains(needle), "{err}");
            assert_eq!(smart.wire_hash_kind, HashKind::Sha1);
            assert_eq!(smart.zero_id, ObjectHash::zero_str(HashKind::Sha1));
        }
        smart.parse_capabilities("object-format=sha1").unwrap();
        assert_eq!(smart.wire_hash_kind, HashKind::Sha1);

        // A BLAKE3 repository refuses the standard formats the same way.
        let (_repo, mut blake3) = blake3_repo_and_protocol();
        let err = blake3
            .parse_capabilities("object-format=sha256")
            .unwrap_err();
        assert!(
            err.to_string()
                .contains("wire=sha256 local=blake3 repository=blake3"),
            "{err}"
        );

        // A wire kind overridden away from the repository is caught before any ref is
        // advertised, naming all three kinds.
        smart.set_wire_hash_kind(HashKind::Sha256);
        let err = smart
            .git_info_refs(ServiceType::UploadPack)
            .await
            .unwrap_err();
        assert!(
            err.to_string()
                .contains("wire=sha256 local=sha1 repository=sha1"),
            "{err}"
        );
        // upload-pack / receive-pack re-bind the wire kind to the repository and re-check.
        let sha1_id = "a".repeat(40);
        let mut req = BytesMut::new();
        add_pkt_line_string(&mut req, format!("want {sha1_id} object-format=sha256\n"));
        req.put(&PKT_LINE_END_MARKER[..]);
        let err = smart.git_upload_pack(req.freeze()).await.unwrap_err();
        assert!(err.to_string().contains("wire=sha256 local=sha1"), "{err}");
        // The divergent wire kind is reported, never silently re-bound to the repository.
        assert_eq!(smart.wire_hash_kind, HashKind::Sha256);
        smart.set_wire_hash_kind(HashKind::Sha1);
        // A wire kind driven away from the repository is not silently reset by a matching
        // capability: the divergence is reported first.
        smart.set_wire_hash_kind(HashKind::Sha256);
        let err = smart.parse_capabilities("object-format=sha1").unwrap_err();
        assert!(
            err.to_string()
                .contains("wire=sha256 local=sha1 repository=sha1"),
            "{err}"
        );
        assert_eq!(smart.wire_hash_kind, HashKind::Sha256);
        smart.set_wire_hash_kind(HashKind::Sha1);
        // A repository whose kind changed after construction cannot confirm a stale
        // capability either (both the bound kind and the current kind must match).
        {
            let repo = DriftingRepo::new();
            let mut dynamic = SmartProtocol::new(TransportProtocol::Http, repo.clone(), TestAuth);
            repo.set_kind(HashKind::Sha256);
            let err = dynamic
                .parse_capabilities("object-format=sha1")
                .unwrap_err();
            assert!(
                err.to_string()
                    .contains("wire=sha1 local=sha1 repository=sha256"),
                "{err}"
            );
        }
        // Uppercase IDs are diagnosed with the expected width and kind.
        let mut req = BytesMut::new();
        add_pkt_line_string(&mut req, format!("want {}\n", sha1_id.to_uppercase()));
        req.put(&PKT_LINE_END_MARKER[..]);
        let err = smart.git_upload_pack(req.freeze()).await.unwrap_err();
        assert!(
            err.to_string()
                .contains("expected 40 lowercase hex chars for sha1"),
            "{err}"
        );

        // want/have IDs: wrong width, tagged and uppercase IDs are diagnosable errors.
        for (line, needle) in [
            (format!("want {} side-band-64k\n", "b".repeat(64)), "`want`"),
            (format!("want sha1:{sha1_id}\n"), "`want`"),
            (format!("want {sha1_id}\n"), "`have`"),
        ] {
            let mut req = BytesMut::new();
            add_pkt_line_string(&mut req, line);
            if needle == "`have`" {
                add_pkt_line_string(&mut req, format!("have {}\n", sha1_id.to_uppercase()));
            }
            req.put(&PKT_LINE_END_MARKER[..]);
            let err = smart.git_upload_pack(req.freeze()).await.unwrap_err();
            assert!(matches!(err, ProtocolError::InvalidRequest(_)), "{err:?}");
            assert!(err.to_string().contains(needle), "{err}");
        }

        // A tampered public `zero_id` fails the consistency check (create/delete semantics
        // must not silently change).
        {
            let mut tampered =
                SmartProtocol::new(TransportProtocol::Http, TestRepoAccess::new(), TestAuth);
            tampered.zero_id = "0".repeat(64);
            let err = tampered
                .git_info_refs(ServiceType::UploadPack)
                .await
                .unwrap_err();
            assert!(err.to_string().contains("zero ID"), "{err}");
            assert!(err.to_string().contains("expected 40 hex zeros"), "{err}");
        }

        // Kind drift *inside* `get_repository_refs` (after the await, before advertisement)
        // and *inside* object collection (after the await, before the pack is handed out) is
        // caught as well.
        {
            let flipping = SmartProtocol::new(
                TransportProtocol::Http,
                DriftingRepo::flipping_refs(),
                TestAuth,
            );
            let err = flipping
                .git_info_refs(ServiceType::UploadPack)
                .await
                .unwrap_err();
            assert!(
                err.to_string()
                    .contains("wire=sha1 local=sha1 repository=sha256"),
                "{err}"
            );
            let mut flipping = SmartProtocol::new(
                TransportProtocol::Http,
                DriftingRepo::flipping_has_object(),
                TestAuth,
            );
            // `have` drives `commit_exists` -> `has_object` (which flips the kind) before any
            // pack is produced; the re-check after those awaits refuses to continue.
            let mut req = BytesMut::new();
            add_pkt_line_string(&mut req, format!("want {}\n", "a".repeat(40)));
            add_pkt_line_string(&mut req, format!("have {}\n", "b".repeat(40)));
            add_pkt_line_string(&mut req, "done\n".to_string());
            let err = flipping.git_upload_pack(req.freeze()).await.unwrap_err();
            assert!(
                err.to_string()
                    .contains("wire=sha1 local=sha1 repository=sha256"),
                "{err}"
            );
        }

        // Kind drift *during* the awaited request drain (a repository following the
        // thread-local kind, client omitting `object-format`) is caught before any command
        // or ref is accepted.
        {
            let repo = DriftingRepo::new();
            let mut drifting = SmartProtocol::new(TransportProtocol::Http, repo.clone(), TestAuth);
            let zero = ObjectHash::zero_str(HashKind::Sha1);
            let mut pkt = BytesMut::new();
            add_pkt_line_string(
                &mut pkt,
                format!("{zero} {} refs/heads/main\n", "a".repeat(40)),
            );
            pkt.put(&PKT_LINE_END_MARKER[..]);
            let bytes = pkt.freeze();
            let handle = repo.clone();
            let stream = Box::pin(futures::stream::once(async move {
                handle.set_kind(HashKind::Sha256);
                Ok(bytes)
            }));
            let err = drifting.git_receive_pack_stream(stream).await.unwrap_err();
            assert!(
                err.to_string()
                    .contains("wire=sha1 local=sha1 repository=sha256"),
                "{err}"
            );
            assert!(drifting.command_list.is_empty());
        }

        // Kind drift *inside* `update_reference`: the second ref is never written, no success
        // report is produced, and the parsed commands are kept for diagnosis.
        {
            let repo = DriftingRepo::flipping_update_reference();
            let mut smart = SmartProtocol::new(TransportProtocol::Http, repo.clone(), TestAuth);
            let zero = ObjectHash::zero_str(HashKind::Sha1);
            let mut pkt = BytesMut::new();
            add_pkt_line_string(
                &mut pkt,
                format!("{zero} {} refs/heads/a\n", "a".repeat(40)),
            );
            add_pkt_line_string(
                &mut pkt,
                format!("{zero} {} refs/heads/b\n", "b".repeat(40)),
            );
            pkt.put(&PKT_LINE_END_MARKER[..]);
            let stream = Box::pin(futures::stream::once(async { Ok(pkt.freeze()) }));
            let err = smart.git_receive_pack_stream(stream).await.unwrap_err();
            assert!(
                err.to_string()
                    .contains("wire=sha1 local=sha1 repository=sha256"),
                "{err}"
            );
            assert_eq!(repo.inner.updates_len(), 1);
            assert_eq!(smart.command_list.len(), 2);
        }

        // A repository whose reported kind changes after construction is refused too.
        let repo = DriftingRepo::new();
        let dynamic = SmartProtocol::new(TransportProtocol::Http, repo.clone(), TestAuth);
        assert_eq!(dynamic.local_hash_kind, HashKind::Sha1);
        repo.set_kind(HashKind::Sha256);
        let err = dynamic
            .git_info_refs(ServiceType::UploadPack)
            .await
            .unwrap_err();
        assert!(
            err.to_string()
                .contains("wire=sha1 local=sha1 repository=sha256"),
            "{err}"
        );
        repo.set_kind(HashKind::Sha1);
        assert!(dynamic.git_info_refs(ServiceType::UploadPack).await.is_ok());
    }

    /// Repository serving real objects of one format from memory (content bytes, as the default
    /// `get_commit` / `get_tree` / `get_blob` accessors expect), advertising one branch.
    #[derive(Clone)]
    struct ObjectRepo {
        kind: HashKind,
        head: String,
        objects: Arc<std::collections::HashMap<String, Vec<u8>>>,
    }

    #[async_trait]
    impl RepositoryAccess for ObjectRepo {
        fn object_hash_kind(&self) -> HashKind {
            self.kind
        }
        async fn get_repository_refs(&self) -> Result<Vec<(String, String)>, ProtocolError> {
            Ok(vec![
                ("HEAD".to_string(), self.head.clone()),
                ("refs/heads/main".to_string(), self.head.clone()),
            ])
        }
        async fn has_object(&self, object_hash: &str) -> Result<bool, ProtocolError> {
            Ok(self.objects.contains_key(object_hash))
        }
        async fn get_object(&self, object_hash: &str) -> Result<Vec<u8>, ProtocolError> {
            self.objects
                .get(object_hash)
                .cloned()
                .ok_or_else(|| ProtocolError::ObjectNotFound(object_hash.to_string()))
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
            Ok(true)
        }
        async fn post_receive_hook(&self) -> Result<(), ProtocolError> {
            Ok(())
        }
    }

    /// want/have and receive-pack command parsing accept the repository's own IDs end to end
    /// for SHA-1, SHA-256 (GC-07: the standard formats keep working) and BLAKE3, the generated
    /// pack decodes under that format, and `have` produces the ACK path.
    #[tokio::test]
    async fn wire_ids_round_trip_for_every_kind() {
        use crate::internal::object::ObjectTrait;
        let _guard = set_hash_kind_for_test(HashKind::Sha1);
        for kind in [HashKind::Sha1, HashKind::Sha256, HashKind::Blake3] {
            let blob = Blob::from_content_with_kind(kind, "wire").unwrap();
            let tree = Tree::from_tree_items_with_kind(
                kind,
                vec![TreeItem::new(
                    TreeItemMode::Blob,
                    blob.id,
                    "wire.txt".to_string(),
                )],
            )
            .unwrap();
            let commit = Commit::from_tree_id_with_kind(kind, tree.id, vec![], "wire ids").unwrap();
            let mut objects = std::collections::HashMap::new();
            objects.insert(blob.id.to_string(), blob.to_data().unwrap());
            objects.insert(tree.id.to_string(), tree.to_data().unwrap());
            objects.insert(commit.id.to_string(), commit.to_data().unwrap());
            let repo = ObjectRepo {
                kind,
                head: commit.id.to_string(),
                objects: Arc::new(objects),
            };
            let mut smart = SmartProtocol::new(TransportProtocol::Http, repo, TestAuth);

            let resp = smart.git_info_refs(ServiceType::UploadPack).await.unwrap();
            let text = String::from_utf8(resp.to_vec()).unwrap();
            assert!(
                text.contains(&format!("{} HEAD", commit.id))
                    && text.contains(&format!(" object-format={}", kind.as_str())),
                "{kind:?}: {text}"
            );

            // want (no have): NAK + a full pack that decodes under `kind`.
            let mut req = BytesMut::new();
            add_pkt_line_string(
                &mut req,
                format!(
                    "want {} side-band-64k object-format={}\n",
                    commit.id,
                    kind.as_str()
                ),
            );
            add_pkt_line_string(&mut req, "done\n".to_string());
            let (stream, buf) = smart.git_upload_pack(req.freeze()).await.unwrap();
            assert!(String::from_utf8_lossy(&buf).contains("NAK"), "{kind:?}");
            let mut stream = stream;
            let mut pack_bytes = Vec::new();
            while let Some(chunk) = futures::StreamExt::next(&mut stream).await {
                pack_bytes.extend(chunk.unwrap());
            }
            let tmp = tempfile::tempdir().unwrap();
            let mut pack = crate::internal::pack::Pack::new_with_hash_kind(
                kind,
                Some(1),
                None,
                Some(tmp.path().to_path_buf()),
                true,
            );
            let seen = Arc::new(Mutex::new(Vec::new()));
            let sink = seen.clone();
            pack.decode(
                &mut std::io::Cursor::new(&pack_bytes),
                move |entry| sink.lock().unwrap().push(entry.inner.hash),
                None::<fn(ObjectHash)>,
            )
            .unwrap();
            let seen: Vec<ObjectHash> = seen.lock().unwrap().clone();
            assert_eq!(seen.len(), 3, "{kind:?}");
            assert!(seen.contains(&commit.id) && seen.iter().all(|h| h.kind() == kind));

            // have: the common commit is acknowledged.
            let mut req = BytesMut::new();
            add_pkt_line_string(&mut req, format!("want {}\n", commit.id));
            add_pkt_line_string(&mut req, format!("have {}\n", commit.id));
            add_pkt_line_string(&mut req, "done\n".to_string());
            let (stream, buf) = smart.git_upload_pack(req.freeze()).await.unwrap();
            assert!(
                String::from_utf8_lossy(&buf).contains(&format!("ACK {}", commit.id)),
                "{kind:?}"
            );
            // Nothing left to send: a valid empty pack (0 objects, trailer of `kind`).
            let mut stream = stream;
            let mut empty_pack = Vec::new();
            while let Some(chunk) = futures::StreamExt::next(&mut stream).await {
                empty_pack.extend(chunk.unwrap());
            }
            assert_eq!(empty_pack.len(), 12 + kind.size(), "{kind:?}");
            assert_eq!(&empty_pack[..4], b"PACK");
            assert_eq!(&empty_pack[8..12], &0u32.to_be_bytes());
            assert_eq!(
                ObjectHash::from_bytes_for_kind(kind, &empty_pack[12..]).unwrap(),
                ObjectHash::new_for_kind(kind, &empty_pack[..12])
            );

            // receive-pack command with this kind's zero ID and commit ID.
            let zero = ObjectHash::zero_str(kind);
            let mut pkt = BytesMut::new();
            add_pkt_line_string(
                &mut pkt,
                format!(
                    "{zero} {} refs/heads/feature\0report-status object-format={}\n",
                    commit.id,
                    kind.as_str()
                ),
            );
            pkt.put(&PKT_LINE_END_MARKER[..]);
            smart.parse_receive_pack_commands(pkt.freeze()).unwrap();
            assert_eq!(smart.command_list.len(), 1);
            assert_eq!(smart.command_list[0].old_hash, zero);
            assert_eq!(smart.command_list[0].new_hash, commit.id.to_string());
            assert!(smart.capabilities.contains(&Capability::ReportStatus));
        }
    }

    /// Repository advertising one ref with an arbitrary (possibly malformed) ID string.
    #[derive(Clone)]
    struct BadRefRepo {
        kind: HashKind,
        id: String,
    }

    #[async_trait]
    impl RepositoryAccess for BadRefRepo {
        fn object_hash_kind(&self) -> HashKind {
            self.kind
        }
        async fn get_repository_refs(&self) -> Result<Vec<(String, String)>, ProtocolError> {
            Ok(vec![("refs/heads/main".to_string(), self.id.clone())])
        }
        async fn has_object(&self, _object_hash: &str) -> Result<bool, ProtocolError> {
            Ok(false)
        }
        async fn get_object(&self, object_hash: &str) -> Result<Vec<u8>, ProtocolError> {
            Err(ProtocolError::ObjectNotFound(object_hash.to_string()))
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
            Ok(true)
        }
        async fn post_receive_hook(&self) -> Result<(), ProtocolError> {
            Ok(())
        }
    }

    /// Repository whose reported kind is test-local shared state (no thread-local mutation):
    /// `set_kind` changes it at any time, and the flip flags make the refs / `has_object`
    /// accessors switch it to SHA-256 while they run (drift inside an awaited repository
    /// call). Refs and objects are served by a SHA-1 `TestRepoAccess`.
    #[derive(Clone)]
    struct DriftingRepo {
        inner: TestRepoAccess,
        kind: Arc<Mutex<HashKind>>,
        flip_in_refs: bool,
        flip_in_has_object: bool,
        flip_in_update_reference: bool,
    }

    impl DriftingRepo {
        fn new() -> Self {
            Self {
                inner: TestRepoAccess::new(),
                kind: Arc::new(Mutex::new(HashKind::Sha1)),
                flip_in_refs: false,
                flip_in_has_object: false,
                flip_in_update_reference: false,
            }
        }

        fn flipping_update_reference() -> Self {
            Self {
                flip_in_update_reference: true,
                ..Self::new()
            }
        }

        fn flipping_refs() -> Self {
            Self {
                flip_in_refs: true,
                ..Self::new()
            }
        }

        fn flipping_has_object() -> Self {
            Self {
                flip_in_has_object: true,
                ..Self::new()
            }
        }

        fn set_kind(&self, kind: HashKind) {
            *self.kind.lock().unwrap() = kind;
        }
    }

    #[async_trait]
    impl RepositoryAccess for DriftingRepo {
        fn object_hash_kind(&self) -> HashKind {
            *self.kind.lock().unwrap()
        }
        async fn get_repository_refs(&self) -> Result<Vec<(String, String)>, ProtocolError> {
            if self.flip_in_refs {
                self.set_kind(HashKind::Sha256);
            }
            self.inner.get_repository_refs().await
        }
        async fn has_object(&self, object_hash: &str) -> Result<bool, ProtocolError> {
            if self.flip_in_has_object {
                self.set_kind(HashKind::Sha256);
            }
            self.inner.has_object(object_hash).await
        }
        async fn get_object(&self, object_hash: &str) -> Result<Vec<u8>, ProtocolError> {
            self.inner.get_object(object_hash).await
        }
        async fn store_pack_data(&self, pack_data: &[u8]) -> Result<(), ProtocolError> {
            self.inner.store_pack_data(pack_data).await
        }
        async fn update_reference(
            &self,
            ref_name: &str,
            old_hash: Option<&str>,
            new_hash: &str,
        ) -> Result<(), ProtocolError> {
            let result = self
                .inner
                .update_reference(ref_name, old_hash, new_hash)
                .await;
            if self.flip_in_update_reference {
                self.set_kind(HashKind::Sha256);
            }
            result
        }
        async fn get_objects_for_pack(
            &self,
            wants: &[String],
            haves: &[String],
        ) -> Result<Vec<String>, ProtocolError> {
            self.inner.get_objects_for_pack(wants, haves).await
        }
        async fn has_default_branch(&self) -> Result<bool, ProtocolError> {
            self.inner.has_default_branch().await
        }
        async fn post_receive_hook(&self) -> Result<(), ProtocolError> {
            self.inner.post_receive_hook().await
        }
    }

    /// parse_capabilities should confirm the repository's wire hash kind and record declared
    /// capabilities (SHA-256 repository; thread-local kind is SHA-1 and does not matter).
    #[tokio::test]
    async fn parse_capabilities_updates_hash_and_caps() {
        let _guard = set_hash_kind_for_test(HashKind::Sha1);
        let repo_access = TestRepoAccess::with_kind(HashKind::Sha256);
        let auth = TestAuth;
        let mut smart = SmartProtocol::new(TransportProtocol::Http, repo_access, auth);

        smart
            .parse_capabilities("object-format=sha256 side-band-64k multi_ack")
            .unwrap();

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
            fn object_hash_kind(&self) -> HashKind {
                HashKind::Sha256
            }
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

        smart.parse_receive_pack_commands(pkt.freeze()).unwrap();

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
