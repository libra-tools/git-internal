# BLAKE3 Integration Handoff（git-internal → Libra / Monoengine）

**狀態：** handoff contract（B3-07 產出，DEP-OUT-01 的移交文件）
**適用版本：** git-internal 0.9.0（由 B3-08 發布；0.8.7 → 0.9.0 為 0.x 階段的 breaking minor，見 §5）
**來源計劃：** `docs/development/plan/plan-20260902.md`（ADR-GI-B3-01 … ADR-GI-B3-06）

本文件把 git-internal 交付的 BLAKE3 object ID 支援整理成下游可直接採用的契約：API、格式、錯誤、相容性邊界，以及 Libra 與 Monoengine 各自必須修改的位置。目標只有一個：**下游不得再以「64 hex 長度」猜測 SHA-256**；所有 ID 解析都要帶明確的 repository `HashKind`。

---

## 1. 範圍與非目標

**本文件涵蓋**

- git-internal 0.9.0 提供的 `HashKind::Blake3`、context parser、tagged ID API 與 pack / idx / protocol 契約（§2–§5）。
- 不變的契約：AI `IntegrityHash` 維持 SHA-256、Monoengine Buck manifest 維持 `sha1:40HEX`（§6）。
- 既有 SHA-1 / SHA-256 repository **不原地** migration，以及 BLAKE3 peer 的 interoperability 限制（§7）。
- Libra 必須修改的邊界（§8）、Monoengine 必須修改的邊界（§9）。
- DEP-OUT-01 的接手判據、未接手時的回落行為與不重做範圍（§10）。

**本文件不涵蓋（由 DEP-OUT-01 接手方實作）**

- Libra CLI / SQLite / D1 / R2 schema、loose storage、fetch / clone / push / fsck / maintenance 的實際修改。
- Monoengine API / DB / converter 的實際修改。
- 標準 Git upstream 的 BLAKE3 interoperability（DEFER-04：目前沒有正式規範，git-internal 不宣稱）。

---

## 2. git-internal 0.9.0 交付內容

### 2.1 `HashKind::Blake3`

| 項目 | 值 |
|---|---|
| enum variant | `git_internal::hash::HashKind::Blake3` |
| digest 寬度 | 32 bytes / 64 hex（與 SHA-256 相同寬度，**不同 namespace**） |
| `as_str()` / capability 名稱 | `"blake3"`（精確小寫；`HashKind::ACCEPTED_TAGS = "sha1|sha256|blake3"`） |
| `is_git_standard()` | `false`（`Sha1` / `Sha256` 為 `true`） |
| tagged 形式 | `blake3:<64 hex>` |
| 標準 Git 相容 | **否**：git-internal / Libra extension |

`HashKind`、`ObjectHash`、`HashAlgorithm` 三個 enum 都新增了 variant，且都不是 `#[non_exhaustive]`：下游對它們的窮舉 `match` 在升級到 0.9.0 時會 **編譯失敗**，必須補上 `Blake3` 分支（這是刻意的：讓每個依 kind 分派的位置都被迫檢視）。

### 2.2 Context parser（顯式 kind）— 取代長度推斷

所有帶 `_for_kind` / `_with_kind` 後綴的 API 都 **不讀 thread-local**、**不從長度推斷演算法**，對不符的輸入 **fail-closed**（hash 層回傳 `HashError`；物件 / pack / index 層把它轉為 `GitError::InvalidHashValue` 等；`new_for_kind` / `zero_for_kind` 這類無輸入校驗需求的建構子不可失敗）：

| API | 用途 |
|---|---|
| `ObjectHash::from_hex_for_kind(kind, &str)` | 解析 raw hex（長度必須恰為 `kind.hex_len()`） |
| `ObjectHash::from_bytes_for_kind(kind, &[u8])` | 解析 raw bytes（長度必須恰為 `kind.size()`） |
| `ObjectHash::from_stream_for_kind(kind, reader)` | 從串流讀取固定寬度 ID |
| `ObjectHash::new_for_kind(kind, bytes)` | 對任意位元組計算 digest |
| `ObjectHash::from_type_and_data_for_kind(kind, ObjectType, data)` | Git object ID（`<type> <size>\0<data>`） |
| `ObjectHash::zero_for_kind(kind)` / `ObjectHash::zero_str(kind)` | 該 kind 的 zero ID |
| `ObjectHash::ensure_kind(kind)` | 斷言一個 `ObjectHash` 屬於 `kind`（跨 kind → `HashError::KindMismatch`） |
| `ObjectHash::kind()` | 取得 ID 所屬演算法（ID 永遠攜帶 kind 作為 metadata） |
| `ObjectHash::to_tagged_string()` / `ObjectHash::from_tagged_str(&str)` | tagged ID `<kind>:<hex>`（見 §2.3） |
| `HashAlgorithm::new_for_kind(kind)` + `update` / `finalize_object_hash` | 串流 hasher（`utils.rs`） |
| `git_internal::internal::pack::utils::calculate_object_hash_for_kind(kind, type, data)` | pack 物件 hash |

**Legacy API 的行為（保留，語義不變）**——兩類不同的規則，下游必須分清：

- **長度推斷（不讀 thread-local，永不產生 BLAKE3）**：`ObjectHash::from_str`（`FromStr`）以字串長度決定演算法：40 hex → SHA-1、64 hex → SHA-256，其他長度 → `"Invalid hash length"`；因此對 BLAKE3 repository 的 64 hex ID，`from_str` 會 **靜默地** 回傳一個 `ObjectHash::Sha256`（同寬度、錯 namespace）。`ObjectHash::from_bytes_infer_kind` 同理（20 / 32 bytes → SHA-1 / SHA-256），已 `#[deprecated(since = "0.9.0")]`。
- **thread-local kind（`set_hash_kind`）**：`ObjectHash::new` / `from_bytes` / `from_stream` / `from_type_and_data`、`HashAlgorithm::new`、`Blob::from_content` / `Tree::from_tree_items` / `Commit::new` 等無 kind 參數的建構子依 thread-local `HashKind` 運作；thread-local 設為 `Blake3` 時它們 **會** 產生 BLAKE3 ID，但只在「單一 repository、在同一 thread 上先呼叫 `set_hash_kind`」的流程中正確。

下游凡是在 **可能服務多個 repository 的 thread / async task / callback** 中解析或計算 ID，必須改用顯式 kind API（GC-06）；凡是接收 **字串** ID 的邊界（CLI、API、DB、protocol）不得再用 `from_str`，必須用 `from_hex_for_kind(repo kind, …)`；protocol / pkt-line 邊界 **只** 接受 raw hex（以 wire kind 解析）；API / DB 邊界若接受 tagged ID，`from_tagged_str` 之後 **必須** 再 `ensure_kind(repo kind)`——tag 只描述該 ID 自身的演算法，不證明它屬於這個 repository，跨 kind 的 tagged ID 必須被拒絕而不是「成功解析」。

**`HashError`**（`git_internal::hash::HashError`，`thiserror`）：`InvalidLength { operation, kind, expected, actual }`、`InvalidHex { … , source }`、`KindMismatch { operation, expected, actual, expected_len, actual_len }`、`UnknownKind { … expected_tags }`、`UnsupportedObjectType { … }`、`Io { … }`。各變體都帶 `operation` 與該情境的 expected / actual（`InvalidLength` / `InvalidHex` / `KindMismatch` 帶 kind 與長度；`UnknownKind` 帶 `expected_tags` 與實際 tag，因為它正是「沒有可解析的 kind」的情況），可直接進入 CLI / API 錯誤訊息；`From<HashError> for GitError`（`GitError::InvalidHashValue`）與 `From<HashError> for io::Error` 均已提供。

### 2.3 Tagged ID 邊界（GC-13）

- **wire 與格式檔** 不含 tag：pkt-line 與 commit / tag 文字 payload 使用 raw lowercase hex；tree entry、pack（trailer、ref-delta base）、idx（name、checksum）、`.git/index` 使用固定寬度的 raw binary ID。兩者都不得寫入 tagged ID。
- **API / 索引 / 日誌 / DB** 等離開 repository context 的位置使用 tagged ID `sha1:HEX` / `sha256:HEX` / `blake3:HEX`（`to_tagged_string` / `from_tagged_str`），或在同一列上另存 kind 欄位。
- 64 hex 的 raw ID **必須** 伴隨 repository kind 才能解析；SHA-256 與 BLAKE3 的 raw hex 在沒有 context 時是不可區分的。

### 2.4 Object model

| 物件 | 顯式 kind 建構 / 解析 |
|---|---|
| `Blob` | `from_content_with_kind(kind, &str)`、`from_content_bytes_with_kind(kind, Vec<u8>)` |
| `Tree` / `TreeItem` | `Tree::from_tree_items_with_kind(kind, items)`、`Tree::rehash_with_kind(kind)`、`TreeItem::from_bytes_with_kind(bytes, kind)`；`Tree::from_bytes(bytes, hash)` 依 `hash.kind()` 切分 entry ID |
| `Commit` | `new_with_kind(kind, author, committer, tree_id, parents, msg)`、`from_tree_id_with_kind(kind, …)`；`from_bytes` 依傳入 hash 的 kind 解析 `tree` / `parent` 行 |
| `Tag` / `Note` | `new_with_kind(kind, …)`、`Note::from_content_with_kind(kind, …)` |
| 任意 `ObjectTrait` | `from_buf_read_with_kind(reader, size, kind)`（reader hasher kind ≠ `kind` → `KindMismatch`） |

跨 kind 的 reference（例如以 SHA-1 blob ID 建 BLAKE3 tree）一律 `GitError::InvalidHashValue`（fail-closed）。

### 2.5 Pack / idx 契約（ADR-GI-B3-03、ADR-GI-B3-05）

| 元件 | 顯式 kind 入口 | 行為 |
|---|---|---|
| `Pack` | `Pack::new_with_hash_kind(kind, threads, mem_limit, tmp, clean)` | trailer、ref-delta base ID、object ID 全部以 `kind` 計算/驗證；SHA-256 `Pack` 解 BLAKE3 pack 必失敗（trailer mismatch） |
| `PackEncoder` | `new_with_hash_kind` / `new_with_idx_and_hash_kind` | 拒絕 ID 不屬於 `kind` 的 entry；trailer 以 `kind` 計算 |
| 檔案輸出 | `encode_and_output_to_files_with_hash_kind(kind, rx, n, dir, window)` | 產生 `pack-<hash>.pack` / `.idx`（idx **v2 only**） |
| `PackStats` | `analyze_with_hash_kind(kind, path)` | 驗證 trailer、idx（count、pack checksum、每個 base object 的 name **在其 offset**、ref-delta base） |
| `IdxBuilder` | kind 由 `pack_hash.kind()` 決定 | 只寫 idx v2；idx checksum 涵蓋 pack checksum |
| `Index`（`.git/index`） | `from_file_with_hash_kind` / `to_file_with_hash_kind` / `load_with_hash_kind` / `save_with_hash_kind` / `refresh_with_hash_kind` | entry ID 必須屬於 `kind`；跨 kind 寫入 / refresh fail-closed 且不破壞既有檔案 |
| cache spill | 自動 | spill 路徑以 kind namespace 隔離（`<tmp>/rkyv-v2/<2hex>/<kind>-<hex>`） |

idx 契約（讀取端，`pack_index::parse_idx_v2_from`，decode / stats 共用）：

- 只接受 **idx v2**（magic + version 2）；BLAKE3 沒有 idx v1。
- fanout 單調且與 name 表逐 first-byte 一致；name 嚴格遞增；offset 唯一；large-offset slot 必須存在；兩個 checksum（pack checksum 副本 + idx checksum）以 `kind` 驗證；無尾隨資料；配置以實際讀取為準（不依宣告數預配置）。
- **`.idx` 存在即必須有效**：magic / version / checksum / count / name / CRC / offset 任一不符 → `GitError::InvalidPackFile`，**不回退**掃描；只有 `NotFound` 才走無 idx 路徑（懸空 symlink 視為存在且失敗）。
- idx CRC32 = 每個物件 **編碼後 pack entry 位元組**（header + base ref + 壓縮 payload）的 CRC；decode 逐物件校驗（含被跳過的 base object 與 delta）。
- decode 逐物件核對 idx name（重算內容 hash）、CRC、offset（實際起始 offset == idx offset）；delta 一律重建校驗（不因 callback 模式跳過）；缺失 base（thin pack）→ 錯誤而非 panic。
- payload hash 在解碼同一趟內聯計算並與 trailer / idx pack hash 比對；沒有第二次整檔讀取。

### 2.6 Smart protocol 契約（B3-06）

- `RepositoryAccess::object_hash_kind() -> HashKind`（預設回傳 thread-local；**服務已知格式的 repository 時必須覆寫**）。`get_blob` / `get_commit` / `get_tree` 預設實作以 `from_hex_for_kind(object_hash_kind(), …)` 解析輸入。
- `SmartProtocol::new` 把 `local_hash_kind` / `wire_hash_kind` / zero ID 綁定到 `object_hash_kind()`；`ensure_hash_kind_consistency()` 在 info-refs / upload-pack / receive-pack 前檢查 repository == local == wire，否則 `InvalidRequest("object-format mismatch: wire=… local=… repository=…")`。
- info-refs 廣播 ` object-format=<kind.as_str()>`；BLAKE3 repository 廣播 `object-format=blake3`。
- `parse_capabilities(&str) -> Result<(), ProtocolError>`：精確小寫 `sha1` / `sha256` / `blake3`；未知或非正規值 → `InvalidRequest("unknown object-format capability …")`；已知但與 repository 不符 → mismatch 錯誤；**不再 warn-and-ignore、不回退 SHA-1**。
- want / have / receive-pack command 的 ID 以 `from_hex_for_kind(wire kind)` 解析：寬度錯誤、非 hex、大寫、tagged ID → `InvalidRequest("invalid object ID in \`want\` line …")`；info-refs 廣播的 ref ID 同樣必須是 wire kind 的 raw lowercase hex。`parse_ref_command` / `parse_receive_pack_commands` 改為回傳 `Result`。
- 一致性檢查在每個 await / 副作用邊界重複執行（取 refs 後、產生 pack 前後、receive-pack 讀取前、drain 後、儲存物件前、每次 `update_reference` 前、成功報告前），並包含公開欄位 `zero_id` 必須等於 wire kind 的 zero ID；`RepositoryAccess` 在操作中途改變 `object_hash_kind()` 會被拒絕，不會以陳舊 kind 完成操作。
- `PackGenerator` 於建構時綁定一個 kind（`SmartProtocol` 以 `PackGenerator::new_with_hash_kind(repo, 已驗證的 kind)` 建立；`new` 只觀察一次 `object_hash_kind()`），以 `PackEncoder::new_with_hash_kind` / `Pack::new_with_hash_kind` 編解碼，對收集到的每個 commit / tree / blob 及其嵌入引用（tree、parents、tree entries）做 kind 校驗，在送出任何 PACK 位元組前驗證 entry kind，「無物件可送」時送出合法空 pack（header + 0 objects + kind trailer），consumer 丟棄串流時不會卡住。
- pack 串流以 `Result<Vec<u8>, ProtocolError>` 項目傳遞：`generate_full_pack` / `generate_incremental_pack` / `SmartProtocol::git_upload_pack` 回傳 `ReceiverStream<Result<Vec<u8>, ProtocolError>>`，producer 失敗以最後一個 `Err` 項目送達（已送出的 chunk 之後），`GitProtocol::upload_pack` 在 side-band 與 raw framing 下都把它轉為協定錯誤；consumer 必須把含 `Err` 的串流視為失敗。

---

## 3. 相容性矩陣

| 面向 | SHA-1 | SHA-256 | BLAKE3 |
|---|---|---|---|
| loose object / tree / commit payload | 標準 Git | 標準 Git | 同格式，ID 為 BLAKE3；只有 git-internal / Libra 讀得懂 |
| pack trailer / ref-delta base | 標準 Git | 標準 Git | BLAKE3，32 bytes |
| idx | v2（v1 讀取不在本 crate） | v2 | **v2 only** |
| `object-format` capability | `sha1`（標準） | `sha256`（標準） | `blake3`（extension；未修改的 Git 不理解） |
| `.git/index` | 標準 | 標準 | 同 layout，ID 32 bytes，checksum 為 BLAKE3 |
| AI `IntegrityHash` | SHA-256 | SHA-256 | **SHA-256（不變）** |
| Monoengine Buck manifest | `sha1:40HEX` | — | **`sha1:40HEX`（不變）** |
| 與未修改 Git 互通 | 是 | 是 | **否** |

---

## 4. 錯誤面（下游應直接對映）

| 情境 | git-internal 錯誤 |
|---|---|
| ID 寬度 / hex / kind 不符 | `HashError::{InvalidLength, InvalidHex, KindMismatch}` → `GitError::InvalidHashValue` |
| 未知 tag（`from_tagged_str`） | `HashError::UnknownKind { expected_tags: "sha1|sha256|blake3" }` |
| pack trailer / idx / CRC / offset / name 不符、thin pack、AI object 出現在 pack | `GitError::InvalidPackFile(String)` |
| `.git/index` checksum / entry kind | `GitError::InvalidIndexFile` / `InvalidHashValue` |
| protocol object-format 未知 / mismatch / wire ID 錯誤 | `ProtocolError::InvalidRequest(String)`（`unknown_object_format` / `object_format_mismatch` / `invalid_wire_id` 建構子） |

所有情境都是 **fail-closed**：沒有回退到 SHA-1、沒有以長度重新猜測、沒有 warn-and-continue。

---

## 5. 版本與遷移（ADR-GI-B3-06）

- 0.8.7 → **0.9.0**：新增 enum variant（`HashKind::Blake3`、`ObjectHash::Blake3`、`HashAlgorithm::Blake3`）；`RepositoryAccess` 新增帶預設實作的 `object_hash_kind()`；`SmartProtocol::parse_capabilities` / `parse_ref_command` / `parse_receive_pack_commands` 改回傳 `Result`；`SmartProtocol::git_upload_pack` 與 `PackGenerator::generate_full_pack` / `generate_incremental_pack` 的串流項目改為 `Result<Vec<u8>, ProtocolError>`；新增 `PackGenerator::new_with_hash_kind` / `hash_kind()`、`SmartProtocol::ensure_hash_kind_consistency`；`ObjectHash::from_bytes_infer_kind` deprecated；`IndexEntry::new` 的 CRC 語義登記為 FIX-03（見 §11）。
- 下游升級步驟：(1) 修正窮舉 `match` 編譯錯誤；(2) 以 `object_hash_kind()` 覆寫 `RepositoryAccess`；(3) 移除所有 `ObjectHash::from_str` / `from_bytes_infer_kind`（長度推斷），並在 context 不安全的邊界——async task、callback、可能服務多個 repository 的程式碼、接收字串 ID 的入口（CLI / API / DB / protocol）——把無 kind 參數的 thread-local 建構子（`from_bytes`、`new`、`Blob::from_content` 等）換成顯式 kind API；單 repository、同 thread 先 `set_hash_kind` 的流程可保留並加註解（§2.2、§12）；(4) 移除其餘以寬度推斷演算法的判斷；(5) 跑本文件 §12 的檢查清單。

---

## 6. 不變契約（除非另開相容性版本）

1. **AI `IntegrityHash` 維持 SHA-256**（ADR-GI-B3-04）：`internal/object/integrity.rs` 的 `IntegrityHash` 與 AI object 內對 commit 的引用不隨 repository `HashKind` 改變；BLAKE3 repository 中的 AI object 仍以 SHA-256 完整性欄位存放。
2. **Monoengine Buck manifest 固定 `sha1:40HEX`（契約不變，解析器必須收緊）**：`../monoengine/src/ceres/model/buck.rs`（`parse_sha1_hash` / `ManifestFile::parse_hash`）的契約是 `sha1:` 前綴 + 恰好 40 hex；但目前實作在剝掉 `sha1:` 後交給 legacy `ObjectHash::from_str`，而 `from_str` 以長度推斷，因此 `sha1:` + 64 hex 會被接受並得到一個 `ObjectHash::Sha256`——這與契約矛盾。接手方必須把解析改為 `ObjectHash::from_hex_for_kind(HashKind::Sha1, hex)`（其固定長度檢查保證「恰好 40 hex」；`from_hex_for_kind` 本身接受大小寫混合，因此可保留現有「大小寫不敏感、正規化為小寫」的行為，先 `to_ascii_lowercase()` 再解析），拒絕任何其他寬度；契約本身不擴充：BLAKE3 repository 不得把 `blake3:` 寫入 Buck manifest。若未來需要，另開帶版本的 manifest 契約，不在本移交範圍。
3. **應用層 digest**（manifests、policies、HMAC、`start_seed_digest` 等）不隨 repository kind 改變。

---

## 7. Migration 與 interoperability 限制

- **既有 SHA-1 / SHA-256 repository 不原地 migration**：不提供、也不允許把現有 repository 的 object ID 轉為 BLAKE3；BLAKE3 只用於以 `core.objectformat=blake3` 新建的 repository。
- **BLAKE3 peer 只能與 git-internal / Libra peer 互通**：未修改的 Git（client 或 server）不理解 `object-format=blake3`，git-internal 不宣稱、也不模擬（不會以 `sha256` capability 偽裝 BLAKE3）。
- **不以寬度推斷**：64 hex 在沒有 kind context 時既可能是 SHA-256 也可能是 BLAKE3；任何「`len() == 64 → sha256`」的程式碼在 BLAKE3 repository 中都是錯的，且會產生不可驗證的資料。
- 標準 Git upstream 的 BLAKE3 規範出現前（DEFER-04），以上限制維持。

---

## 8. 移交給 Libra 的修改邊界（DEP-OUT-01）

錨點以 `../libra` HEAD `b800de73b4a82fe2c77ef68a20e5525a00d7d89f` 為準（計劃卡片中的 `d57a908…` 錨點已由此版本取代；行號可能漂移，以符號名為主）。

| 邊界 | 現況（Libra） | 必要修改 |
|---|---|---|
| **config `core.objectformat`** | `src/cli.rs` `set_local_hash_kind_for_storage` / `set_hash_kind_from_object_format` 與 `src/command/init.rs` `resolve_object_format` 只接受 `sha1` / `sha256` | 接受 `blake3`（精確小寫），`libra init --object-format blake3`；把 kind 由 thread-local 提升為 repository context，並在每個 storage / protocol 入口以 `object_hash_kind()` 傳遞 |
| **loose object storage** | `src/utils/storage/local.rs`（`ObjectHash::from_str(&oid_hex)`）、`src/utils/storage/tiered.rs`（thread-local 註記） | 以 `from_hex_for_kind(repo kind, …)` 解析目錄名 / 檔名；`ClientStorage` 帶 kind |
| **pack / idx** | `src/internal/pack_writer.rs`（`set_hash_kind` + `Commit::from_bytes(&data, *hash)`）、`src/command/verify_pack_index_v2.rs`（`infer_idx_v2_hash_kind` 只在 `[Sha1, Sha256]` 候選中猜） | 以 `Pack::new_with_hash_kind` / `PackEncoder::new_with_hash_kind` / `encode_and_output_to_files_with_hash_kind`；idx 驗證改用 `PackStats::analyze_with_hash_kind(repo kind)` 或 `pack_index::parse_idx_v2_from(…, repo kind, len)`，不再候選推斷 |
| **remote / cloud object index 與 cloud clone** | `src/internal/model/object_index.rs`（`o_id TEXT`，註解「SHA-1 or SHA-256」）、`src/utils/client_storage.rs` `expected_index_repair_oid_len`（`sha1 → 40, sha256 → 64`）、`src/command/clone.rs` `cloud_object_format`（任一 `o_id.len() == 64` → `"sha256"`，否則 `"sha1"`；cloud clone 據此設定 `core.objectformat`） | schema 增加 kind 欄位（或改存 tagged ID `blake3:HEX`）；repair 判據改為「kind + 寬度」而非寬度；cloud clone 的 object format 必須來自 cloud metadata / kind 欄位（缺失時 fail-closed），不得由 `o_id` 長度推斷——否則 BLAKE3 repository 會被 clone 成 SHA-256；D1 / R2 / SQLite 遷移由接手方規劃 |
| **protocol（fetch / clone / push）** | `src/internal/protocol/mod.rs` `parse_discovered_references` 以 `hash.len()` 40/64 推斷 `HashKind`；`src/command/fetch.rs` `ObjectFormatMismatch`、`src/command/push.rs` `HashKindMismatch`；`src/internal/protocol/local_client.rs` `HashKindRestoreGuard` | 以 `object-format` capability（`HashKind::from_str` 精確值）決定 wire kind，缺 capability 時預設 `sha1`；`blake3` 只在本地 repository 亦為 BLAKE3 時接受，否則 mismatch fail-closed；ref ID 以 `from_hex_for_kind(wire kind)` 解析 |
| **bundle** | `src/command/bundle.rs`（`ObjectHash::from_str`、`set_hash_kind(kind)`） | bundle header 記錄 object-format，讀取時以顯式 kind 解析 |
| **fsck / maintenance** | `src/command/fsck.rs`（`ObjectHash::from_bytes(&bytes).ok()`）、`src/command/maintenance.rs`（`hash_version: u8` 只區分 Sha256、`sha2::Sha256::digest` 直接呼叫） | 以 `from_bytes_for_kind(repo kind)`；multi-pack-index / hash_version 對 BLAKE3 需定義新值或拒絕；digest 一律經 `HashAlgorithm::new_for_kind` |
| **AI / agent 路徑** | `src/internal/ai/util.rs`（`len() == 64` 視為 SHA-256、40 補零到 64）、`src/internal/ai/history.rs`（64-hex 檢查） | AI object 內的 commit 引用維持 `IntegrityHash`（SHA-256，§6）；repository commit ID 改存 tagged ID 或加 kind 欄位，不再補零 |
| **其他 `ObjectHash::from_str` 呼叫點** | `command/{commit,rebase,stash,replace,reflog,for_each_ref}.rs`、`command/agent/*` 等（見 `rg -n 'ObjectHash::from_str' ../libra/src`） | 逐一改為 `from_hex_for_kind(repo kind, …)`；使用者輸入的 ID 於 CLI 邊界解析一次後以 `ObjectHash` 傳遞 |

---

## 9. 移交給 Monoengine 的修改邊界（DEP-OUT-01）

錨點以 `../monoengine` HEAD `80ddff4ad2832595b594dbb6852729d6af59ca6e` 為準。

| 邊界 | 現況（Monoengine） | 必要修改 |
|---|---|---|
| **repository context** | `src/ceres/api_service/mono_api_service.rs`（`ObjectHash::from_str(&p_ref.ref_commit_hash).unwrap()` 等 50+ 處）、`src/ceres/api_service/un19_fail_closed.rs` | 每個 repository / mono path 帶 `HashKind`（由 repository 設定或 DB 欄位提供）；`RepositoryAccess::object_hash_kind()` 覆寫；`from_str(...).unwrap()` 改為 `from_hex_for_kind(kind, …)?` |
| **converter** | `src/jupiter/utils/converter.rs:39-51`（commit / tree / parent 以無 context `ObjectHash::from_str(...).unwrap()`） | 以 model 記錄的 kind 呼叫 `from_hex_for_kind`；缺 kind 欄位時視為 fail-closed（不得預設 SHA-256） |
| **ref / API / DB 解析點** | `src/ceres/pack/monorepo.rs`（`from_str(&m.tree_id)`）、`src/ceres/pack/push_chain.rs`、`src/ceres/build_trigger/changes_calculator.rs`、`src/ceres/diff/tree_diff.rs`、`src/ceres/code_edit/utils.rs` | DB 的 commit / tree / blob ID 欄位增加 kind 欄位或改存 tagged ID；API 輸入以 tagged ID 或 `(kind, hex)` 接收；測試 fixture 中的 40-hex 字面值改以 `HashKind::Sha1` 顯式建構 |
| **pack import / push** | `src/ceres/pack/import_repo.rs`、`push_chain.rs` | 以 `Pack::new_with_hash_kind(repo kind)` 解碼、`PackEncoder::new_with_hash_kind` 編碼 |
| **Buck manifest** | `src/ceres/model/buck.rs`（`parse_sha1_hash` 剝掉 `sha1:` 後以 legacy `from_str` 解析，接受 64 hex → `Sha256`） | 契約不變（`sha1:40HEX`），但解析器 **必須** 改為 `from_hex_for_kind(HashKind::Sha1, hex)` 並拒絕非 40 hex（§6）；BLAKE3 repository 的 Buck 流程若需要檔案 hash，另開契約 |

---

## 10. DEP-OUT-01：接手判據、回落行為、不重做範圍

**接手判據（接收方 plan 必須同時滿足）**

1. 引用 git-internal **0.9.0**（pinned），並通過本文件 §12 檢查清單。
2. Libra：`core.objectformat=blake3` 可 `init`、寫 loose / pack / idx、`fsck` 通過，且 `rg -n 'len\(\) == 64|len\(\) == 40' src` 中的 hash 長度推斷全部移除或改為「kind + 寬度」判據；protocol 以 capability 決定 wire kind。
3. Monoengine：`rg -n 'ObjectHash::from_str' src` 於非測試碼零命中，converter / API / DB 皆帶 kind。
4. 兩者都保留 §6 的不變契約，並在文件中標記 BLAKE3 為 extension（不宣稱標準 Git 互通）。

**未接手時的回落行為**

- 下游繼續使用 SHA-1 / SHA-256 工作流；git-internal 0.9.0 對既有 SHA-1 / SHA-256 行為完全相容（GC-07 回歸門）。
- 未覆寫 `object_hash_kind()` 的 `RepositoryAccess` 仍以 thread-local kind 運作（單 repository 流程）。
- 以 0.9.0 建立的 BLAKE3 repository 不能被未接手的下游讀取：`from_str` 不會產生 BLAKE3，protocol 對未知 / 不符的 object-format fail-closed。

**不重做範圍（已由 git-internal 完成，接收方不得重新實作）**

- BLAKE3 hasher、`ObjectHash::Blake3`、context parser、tagged ID、`HashError`。
- pack / idx v2 的 BLAKE3 讀寫與交叉驗證、cache spill namespace、`.git/index` 顯式 kind 讀寫。
- smart protocol 的 `object-format=blake3` 協商、三向一致性檢查、wire ID 校驗。

---

## 11. 已知限制與後續

- `PackStats::analyze_with_hash_kind` 不解析 delta 鏈：delta 物件的 idx name 由 `Pack::decode_file_full_without_callback`（或任何解析 delta 的 decode）校驗。
- `IndexEntry::new`（`src/internal/pack/index_entry.rs`）仍以解壓內容計算 CRC（FIX-03 候補）；encoder 寫出時已以編碼位元組覆寫，下游不應直接以 `IndexEntry::new` 的 CRC 寫 idx。
- `CLAUDE.md` 仍指向不存在的 `docs/ai.md`（實際為 `docs/agent.md`；FIX-04 候補，README 已於 B3-06 修正）。
- 標準 Git 的 BLAKE3 規範出現時另開 ADR（DEFER-04）。

---

## 12. 下游驗收檢查清單

```text
[ ] cargo update -p git-internal --precise 0.9.0；窮舉 match 補 Blake3 分支後編譯通過
[ ] rg -n 'ObjectHash::from_str|from_bytes_infer_kind' src      # 非測試碼零命中：兩者都是長度推斷、不讀 thread-local、永不 BLAKE3，任何保留都會把 BLAKE3 ID 靜默標成 SHA-256
[ ] rg -n 'ObjectHash::(new|from_bytes|from_stream|from_type_and_data)\(|HashAlgorithm::new\(' src   # 每處都在單 repository、同 thread 先 set_hash_kind 的流程內並有註解；async task / callback / 多 repository 服務一律用 *_for_kind
[ ] rg -n 'len\(\) == 64|len\(\) == 40|64 => .*Sha256' src        # 在 repository ObjectHash 解析路徑（§8/§9 列出的檔案：objectformat 設定、object index/repair、cloud clone、protocol、idx 驗證、AI 的 commit 引用）零命中；應用層固定 SHA-256 digest（media 校驗、manifest、seed digest 等，§6 第 3 點）不在此列並須以註解標明
[ ] RepositoryAccess::object_hash_kind() 已覆寫並回傳 repository 的真實格式
[ ] BLAKE3 repository：init / add / commit / pack / idx / fsck / fetch / push（Libra ↔ Libra）全綠
[ ] SHA-1 與 SHA-256 repository 回歸全綠（行為與 0.8.7 相同）
[ ] AI IntegrityHash 仍為 SHA-256；Buck manifest 仍為 sha1:40HEX
[ ] 文件標記 object-format=blake3 為 git-internal / Libra extension；不宣稱與未修改 Git 互通；不提供原地 migration
```
