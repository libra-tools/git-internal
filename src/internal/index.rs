//! Minimal Git index (.git/index) reader/writer that maps working tree metadata to `IndexEntry`
//! records, including POSIX timestamp handling and hash serialization helpers.

#[cfg(unix)]
use std::os::unix::fs::MetadataExt;
#[cfg(unix)]
use std::time::Duration;
use std::{
    collections::BTreeMap,
    fmt::{Display, Formatter},
    fs::{self, File},
    io,
    io::{BufReader, Read, Write},
    path::{Path, PathBuf},
    time::{SystemTime, UNIX_EPOCH},
};

use byteorder::{BigEndian, ReadBytesExt, WriteBytesExt};

use crate::{
    errors::GitError,
    hash::{ObjectHash, get_hash_kind},
    internal::pack::wrapper::Wrapper,
    utils::{self, HashAlgorithm},
};

/// POSIX time with seconds and nanoseconds
#[derive(PartialEq, Eq, Debug, Clone)]
pub struct Time {
    seconds: u32,
    nanos: u32,
}
impl Time {
    /// Read Time from stream
    pub fn from_stream(stream: &mut impl Read) -> Result<Self, GitError> {
        let seconds = stream.read_u32::<BigEndian>()?;
        let nanos = stream.read_u32::<BigEndian>()?;
        Ok(Time { seconds, nanos })
    }

    /// Convert to SystemTime
    #[allow(dead_code)]
    fn to_system_time(&self) -> SystemTime {
        UNIX_EPOCH + std::time::Duration::new(self.seconds.into(), self.nanos)
    }

    /// Create Time from SystemTime
    pub fn from_system_time(system_time: SystemTime) -> Self {
        match system_time.duration_since(UNIX_EPOCH) {
            Ok(duration) => {
                let seconds = duration
                    .as_secs()
                    .try_into()
                    .expect("Time is too far in the future");
                let nanos = duration.subsec_nanos();
                Time { seconds, nanos }
            }
            Err(_) => panic!("Time is before the UNIX epoch"),
        }
    }
}
impl Display for Time {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}:{}", self.seconds, self.nanos)
    }
}

#[cfg(unix)]
fn index_ctime(meta: &fs::Metadata) -> SystemTime {
    unix_metadata_time(meta.ctime(), meta.ctime_nsec())
}

#[cfg(not(unix))]
fn index_ctime(meta: &fs::Metadata) -> SystemTime {
    meta.created()
        .or_else(|_| meta.modified())
        .unwrap_or(UNIX_EPOCH)
}

#[cfg(unix)]
fn index_mtime(meta: &fs::Metadata) -> SystemTime {
    unix_metadata_time(meta.mtime(), meta.mtime_nsec())
}

#[cfg(not(unix))]
fn index_mtime(meta: &fs::Metadata) -> SystemTime {
    meta.modified()
        .or_else(|_| meta.created())
        .unwrap_or(UNIX_EPOCH)
}

#[cfg(unix)]
fn unix_metadata_time(seconds: i64, nanos: i64) -> SystemTime {
    if seconds < 0 {
        return UNIX_EPOCH;
    }

    let nanos = u32::try_from(nanos)
        .ok()
        .filter(|nanos| *nanos < 1_000_000_000)
        .unwrap_or(0);

    UNIX_EPOCH + Duration::new(seconds as u64, nanos)
}

/// 16 bits
#[derive(Debug)]
pub struct Flags {
    pub assume_valid: bool,
    pub extended: bool,   // must be 0 in v2
    pub stage: u8,        // 2-bit during merge
    pub name_length: u16, // 12-bit
}

impl From<u16> for Flags {
    fn from(flags: u16) -> Self {
        Flags {
            assume_valid: flags & 0x8000 != 0,
            extended: flags & 0x4000 != 0,
            stage: ((flags & 0x3000) >> 12) as u8,
            name_length: flags & 0xFFF,
        }
    }
}

impl TryInto<u16> for &Flags {
    type Error = &'static str;
    fn try_into(self) -> Result<u16, Self::Error> {
        let mut flags = 0u16;
        if self.assume_valid {
            flags |= 0x8000; // 16
        }
        if self.extended {
            flags |= 0x4000; // 15
        }
        flags |= (self.stage as u16) << 12; // 13-14
        if self.name_length > 0xFFF {
            return Err("Name length is too long");
        }
        flags |= self.name_length; // 0-11
        Ok(flags)
    }
}

impl Flags {
    pub fn new(name_len: u16) -> Self {
        Flags {
            assume_valid: true,
            extended: false,
            stage: 0,
            name_length: name_len,
        }
    }
}

/// An entry in the Git index file.
pub struct IndexEntry {
    pub ctime: Time,
    pub mtime: Time,
    pub dev: u32,  // 0 for windows
    pub ino: u32,  // 0 for windows
    pub mode: u32, // 0o100644 // 4-bit object type + 3-bit unused + 9-bit unix permission
    pub uid: u32,  // 0 for windows
    pub gid: u32,  // 0 for windows
    pub size: u32,
    pub hash: ObjectHash,
    pub flags: Flags,
    pub name: String,
}
impl Display for IndexEntry {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "IndexEntry {{ ctime: {}, mtime: {}, dev: {}, ino: {}, mode: {:o}, uid: {}, gid: {}, size: {}, hash: {}, flags: {:?}, name: {} }}",
            self.ctime,
            self.mtime,
            self.dev,
            self.ino,
            self.mode,
            self.uid,
            self.gid,
            self.size,
            self.hash,
            self.flags,
            self.name
        )
    }
}

impl IndexEntry {
    /** Metadata must be got by [fs::symlink_metadata] to avoid following symlink */
    pub fn new(meta: &fs::Metadata, hash: ObjectHash, name: String) -> Self {
        let mut entry = IndexEntry {
            ctime: Time::from_system_time(index_ctime(meta)),
            mtime: Time::from_system_time(index_mtime(meta)),
            dev: 0,
            ino: 0,
            uid: 0,
            gid: 0,
            size: meta.len() as u32,
            hash,
            flags: Flags::new(name.len() as u16),
            name,
            mode: 0o100644,
        };
        #[cfg(unix)]
        {
            entry.dev = meta.dev() as u32;
            entry.ino = meta.ino() as u32;
            entry.uid = meta.uid();
            entry.gid = meta.gid();

            entry.mode = match meta.mode() & 0o170000/* file mode */ {
                0o100000 => {
                    match meta.mode() & 0o111 {
                        0 => 0o100644, // no execute permission
                        _ => 0o100755, // with execute permission
                    }
                }
                0o120000 => 0o120000, // symlink
                _ =>  entry.mode, // keep the original mode
            }
        }
        #[cfg(windows)]
        {
            if meta.is_symlink() {
                entry.mode = 0o120000;
            }
        }
        entry
    }

    /// - `file`: **to workdir path**
    /// - `workdir`: absolute or relative path
    pub fn new_from_file(file: &Path, hash: ObjectHash, workdir: &Path) -> io::Result<Self> {
        let name = file.to_str().unwrap().to_string();
        let file_abs = workdir.join(file);
        let meta = fs::symlink_metadata(file_abs)?; // without following symlink
        let index = IndexEntry::new(&meta, hash, name);
        Ok(index)
    }

    /// Create IndexEntry from blob object
    pub fn new_from_blob(name: String, hash: ObjectHash, size: u32) -> Self {
        IndexEntry {
            ctime: Time {
                seconds: 0,
                nanos: 0,
            },
            mtime: Time {
                seconds: 0,
                nanos: 0,
            },
            dev: 0,
            ino: 0,
            mode: 0o100644,
            uid: 0,
            gid: 0,
            size,
            hash,
            flags: Flags::new(name.len() as u16),
            name,
        }
    }
}

/// see [index-format](https://git-scm.com/docs/index-format)
/// <br> to Working Dir relative path
pub struct Index {
    entries: BTreeMap<(String, u8), IndexEntry>,
}

impl Index {
    pub fn new() -> Self {
        Index {
            entries: BTreeMap::new(),
        }
    }

    fn check_header(file: &mut impl Read) -> Result<u32, GitError> {
        let mut magic = [0; 4];
        file.read_exact(&mut magic)?;
        if magic != *b"DIRC" {
            return Err(GitError::InvalidIndexHeader(
                String::from_utf8_lossy(&magic).to_string(),
            ));
        }

        let version = file.read_u32::<BigEndian>()?;
        // only support v2 now
        if version != 2 {
            return Err(GitError::InvalidIndexHeader(version.to_string()));
        }

        let entries = file.read_u32::<BigEndian>()?;
        Ok(entries)
    }

    pub fn size(&self) -> usize {
        self.entries.len()
    }

    pub fn from_file(path: impl AsRef<Path>) -> Result<Self, GitError> {
        let file = File::open(path.as_ref())?; // read-only
        let total_size = file.metadata()?.len();
        let file = &mut Wrapper::new(BufReader::new(file)); // TODO move Wrapper & utils to a common module

        let num = Index::check_header(file)?;
        let mut index = Index::new();

        for _ in 0..num {
            let mut entry = IndexEntry {
                ctime: Time::from_stream(file)?,
                mtime: Time::from_stream(file)?,
                dev: file.read_u32::<BigEndian>()?, //utils::read_u32_be(file)?,
                ino: file.read_u32::<BigEndian>()?,
                mode: file.read_u32::<BigEndian>()?,
                uid: file.read_u32::<BigEndian>()?,
                gid: file.read_u32::<BigEndian>()?,
                size: file.read_u32::<BigEndian>()?,
                hash: utils::read_sha(file)?,
                flags: Flags::from(file.read_u16::<BigEndian>()?),
                name: String::new(),
            };
            let name_len = entry.flags.name_length as usize;
            let mut name = vec![0; name_len];
            file.read_exact(&mut name)?;
            // The exact encoding is undefined, but the '.' and '/' characters are encoded in 7-bit ASCII
            entry.name =
                String::from_utf8(name).map_err(|e| GitError::ConversionError(e.to_string()))?; // TODO check the encoding
            index
                .entries
                .insert((entry.name.clone(), entry.flags.stage), entry);

            // 1-8 nul bytes as necessary to pad the entry to a multiple of eight bytes
            // while keeping the name NUL-terminated.
            let hash_len = get_hash_kind().size();
            let entry_len = hash_len + 2 + name_len;
            let padding = 1 + ((8 - ((entry_len + 1) % 8)) % 8); // at least 1 byte nul
            utils::read_bytes(file, padding)?;
        }

        // Extensions
        while file.bytes_read() + get_hash_kind().size() < total_size as usize {
            // The remaining bytes must be the pack checksum (size = get_hash_kind().size())
            let sign = utils::read_bytes(file, 4)?;
            println!(
                "{:?}",
                String::from_utf8(sign.clone())
                    .map_err(|e| GitError::ConversionError(e.to_string()))?
            );
            // If the first byte is 'A'...'Z' the extension is optional and can be ignored.
            if sign[0] >= b'A' && sign[0] <= b'Z' {
                // Optional extension
                let size = file.read_u32::<BigEndian>()?;
                utils::read_bytes(file, size as usize)?; // Ignore the extension
            } else {
                // 'link' or 'sdir' extension
                return Err(GitError::InvalidIndexFile(
                    "Unsupported extension".to_string(),
                ));
            }
        }

        // check sum
        let file_hash = file.final_hash();
        let check_sum = utils::read_sha(file)?;
        if file_hash != check_sum {
            return Err(GitError::InvalidIndexFile("Check sum failed".to_string()));
        }
        assert_eq!(index.size(), num as usize);
        Ok(index)
    }

    pub fn to_file(&self, path: impl AsRef<Path>) -> Result<(), GitError> {
        let mut file = File::create(path)?;
        let mut hash = HashAlgorithm::new();

        let mut header = Vec::new();
        header.write_all(b"DIRC")?;
        header.write_u32::<BigEndian>(2u32)?; // version 2
        header.write_u32::<BigEndian>(self.entries.len() as u32)?;
        file.write_all(&header)?;
        hash.update(&header);

        for (_, entry) in self.entries.iter() {
            let mut entry_bytes = Vec::new();
            entry_bytes.write_u32::<BigEndian>(entry.ctime.seconds)?;
            entry_bytes.write_u32::<BigEndian>(entry.ctime.nanos)?;
            entry_bytes.write_u32::<BigEndian>(entry.mtime.seconds)?;
            entry_bytes.write_u32::<BigEndian>(entry.mtime.nanos)?;
            entry_bytes.write_u32::<BigEndian>(entry.dev)?;
            entry_bytes.write_u32::<BigEndian>(entry.ino)?;
            entry_bytes.write_u32::<BigEndian>(entry.mode)?;
            entry_bytes.write_u32::<BigEndian>(entry.uid)?;
            entry_bytes.write_u32::<BigEndian>(entry.gid)?;
            entry_bytes.write_u32::<BigEndian>(entry.size)?;
            entry_bytes.write_all(entry.hash.as_ref())?;
            entry_bytes.write_u16::<BigEndian>((&entry.flags).try_into().unwrap())?;
            entry_bytes.write_all(entry.name.as_bytes())?;
            let hash_len = get_hash_kind().size();
            let entry_len = hash_len + 2 + entry.name.len();
            let padding = 1 + ((8 - ((entry_len + 1) % 8)) % 8); // at least 1 byte nul
            entry_bytes.write_all(&vec![0; padding])?;
            file.write_all(&entry_bytes)?;
            hash.update(&entry_bytes);
        }

        // Extensions

        // check sum
        let file_hash =
            ObjectHash::from_bytes(&hash.finalize()).map_err(GitError::InvalidIndexFile)?;
        file.write_all(file_hash.as_ref())?;
        Ok(())
    }

    pub fn refresh(&mut self, file: impl AsRef<Path>, workdir: &Path) -> Result<bool, GitError> {
        let path = file.as_ref();
        let name = path
            .to_str()
            .ok_or(GitError::InvalidPathError(format!("{path:?}")))?;

        if let Some(entry) = self.entries.get_mut(&(name.to_string(), 0)) {
            let abs_path = workdir.join(path);
            let meta = fs::symlink_metadata(&abs_path)?;
            let new_ctime = Time::from_system_time(index_ctime(&meta));
            let new_mtime = Time::from_system_time(index_mtime(&meta));
            let new_size = meta.len() as u32;

            // re-calculate SHA1/SHA256
            let mut file = File::open(&abs_path)?;
            let mut hasher = HashAlgorithm::new();
            io::copy(&mut file, &mut hasher)?;
            let new_hash = ObjectHash::from_bytes(&hasher.finalize()).unwrap();

            // refresh index
            if entry.ctime != new_ctime
                || entry.mtime != new_mtime
                || entry.size != new_size
                || entry.hash != new_hash
            {
                entry.ctime = new_ctime;
                entry.mtime = new_mtime;
                entry.size = new_size;
                entry.hash = new_hash;
                return Ok(true);
            }
        }
        Ok(false)
    }
}

impl Default for Index {
    fn default() -> Self {
        Self::new()
    }
}

impl Index {
    /// Load index. If it does not exist, return an empty index.
    pub fn load(index_file: impl AsRef<Path>) -> Result<Self, GitError> {
        let path = index_file.as_ref();
        if !path.exists() {
            return Ok(Index::new());
        }
        Index::from_file(path)
    }

    pub fn update(&mut self, entry: IndexEntry) {
        self.add(entry)
    }

    pub fn add(&mut self, entry: IndexEntry) {
        self.entries
            .insert((entry.name.clone(), entry.flags.stage), entry);
    }

    pub fn remove(&mut self, name: &str, stage: u8) -> Option<IndexEntry> {
        self.entries.remove(&(name.to_string(), stage))
    }

    pub fn get(&self, name: &str, stage: u8) -> Option<&IndexEntry> {
        self.entries.get(&(name.to_string(), stage))
    }

    pub fn tracked(&self, name: &str, stage: u8) -> bool {
        self.entries.contains_key(&(name.to_string(), stage))
    }

    pub fn get_hash(&self, file: &str, stage: u8) -> Option<ObjectHash> {
        self.get(file, stage).map(|entry| entry.hash)
    }

    pub fn verify_hash(&self, file: &str, stage: u8, hash: &ObjectHash) -> bool {
        let inner_hash = self.get_hash(file, stage);
        if let Some(inner_hash) = inner_hash {
            &inner_hash == hash
        } else {
            false
        }
    }
    /// is file modified after last `add` (need hash to confirm content change)
    /// - `workdir` is used to rebuild absolute file path
    pub fn is_modified(&self, file: &str, stage: u8, workdir: &Path) -> bool {
        if let Some(entry) = self.get(file, stage) {
            let path_abs = workdir.join(file);
            let meta = path_abs.symlink_metadata().unwrap();
            // TODO more fields
            let same = entry.ctime == Time::from_system_time(index_ctime(&meta))
                && entry.mtime == Time::from_system_time(index_mtime(&meta))
                && entry.size == meta.len() as u32;

            !same
        } else {
            panic!("File not found in index");
        }
    }

    /// Get all entries with the same stage
    pub fn tracked_entries(&self, stage: u8) -> Vec<&IndexEntry> {
        // ? should use stage or not
        self.entries
            .iter()
            .filter(|(_, entry)| entry.flags.stage == stage)
            .map(|(_, entry)| entry)
            .collect()
    }

    /// Get all tracked files(stage = 0)
    pub fn tracked_files(&self) -> Vec<PathBuf> {
        self.tracked_entries(0)
            .iter()
            .map(|entry| PathBuf::from(&entry.name))
            .collect()
    }

    /// Judge if the file(s) of `dir` is in the index
    /// - false if `dir` is a file
    pub fn contains_dir_file(&self, dir: &str) -> bool {
        let dir = Path::new(dir);
        self.entries.iter().any(|((name, _), _)| {
            let path = Path::new(name);
            path.starts_with(dir) && path != dir // TODO change to is_sub_path!
        })
    }

    /// remove all files in `dir` from index
    /// - do nothing if `dir` is a file
    pub fn remove_dir_files(&mut self, dir: &str) -> Vec<String> {
        let dir = Path::new(dir);
        let mut removed = Vec::new();
        self.entries.retain(|(name, _), _| {
            let path = Path::new(name);
            if path.starts_with(dir) && path != dir {
                removed.push(name.clone());
                false
            } else {
                true
            }
        });
        removed
    }

    /// saved to index file
    pub fn save(&self, index_file: impl AsRef<Path>) -> Result<(), GitError> {
        self.to_file(index_file)
    }
}

#[cfg(test)]
mod tests {
    use std::io::Cursor;

    use super::*;
    use crate::hash::{HashKind, set_hash_kind_for_test};

    /// Test Time conversion
    #[test]
    fn test_time() {
        let time = Time {
            seconds: 0,
            nanos: 0,
        };
        let system_time = time.to_system_time();
        let new_time = Time::from_system_time(system_time);
        assert_eq!(time, new_time);
    }

    /// Test Flags conversion
    #[test]
    fn test_check_header() {
        let mut source = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        source.push("tests/data/index/index-2");

        let file = File::open(source).unwrap();
        let entries = Index::check_header(&mut BufReader::new(file)).unwrap();
        assert_eq!(entries, 2);
    }

    /// Test IndexEntry creation
    #[test]
    fn test_index() {
        let _guard = set_hash_kind_for_test(HashKind::Sha1);
        let mut source = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        source.push("tests/data/index/index-760");

        let index = Index::from_file(source).unwrap();
        assert_eq!(index.size(), 760);
        for (_, entry) in index.entries.iter() {
            println!("{entry}");
        }
    }

    /// Test IndexEntry creation with SHA256
    #[test]
    fn test_index_sha256() {
        let _guard = set_hash_kind_for_test(HashKind::Sha256);
        let mut source = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        source.push("tests/data/index/index-9-256");

        let index = Index::from_file(source).unwrap();
        assert_eq!(index.size(), 9);
        for (_, entry) in index.entries.iter() {
            println!("{entry}");
        }
    }

    /// Flags bit packing/unpacking covers all fields and enforces name length limit.
    #[test]
    fn flags_round_trip_and_length_limit() {
        let mut flags = Flags {
            assume_valid: true,
            extended: true,
            stage: 2,
            name_length: 0x0ABC,
        };
        let packed: u16 = (&flags).try_into().expect("should pack");
        let unpacked = Flags::from(packed);
        assert_eq!(unpacked.assume_valid, flags.assume_valid);
        assert_eq!(unpacked.extended, flags.extended);
        assert_eq!(unpacked.stage, flags.stage);
        assert_eq!(unpacked.name_length, flags.name_length);

        flags.name_length = 0x1FFF;
        let overflow: Result<u16, _> = (&flags).try_into();
        assert!(overflow.is_err(), "length overflow should err");
    }

    /// IndexEntry::new_from_blob populates fields and sets flags length.
    #[test]
    fn index_entry_new_from_blob_populates_fields() {
        let hash = ObjectHash::from_bytes(&[0u8; 20]).unwrap();
        let entry = IndexEntry::new_from_blob("file.txt".to_string(), hash, 42);
        assert_eq!(entry.name, "file.txt");
        assert_eq!(entry.size, 42);
        assert_eq!(entry.hash, hash);
        assert_eq!(entry.flags.name_length, "file.txt".len() as u16);
        assert_eq!(entry.mode, 0o100644);
    }

    /// Index container operations: add/get/tracked/dir helpers.
    #[test]
    fn index_add_and_query_helpers() {
        let _guard = set_hash_kind_for_test(HashKind::Sha1);
        let mut index = Index::new();
        let hash = ObjectHash::from_bytes(&[1u8; 20]).unwrap();
        let entry = IndexEntry::new_from_blob("a/b.txt".to_string(), hash, 10);
        index.add(entry);

        // get finds stage-0 by name
        let got = index.get("a/b.txt", 0).expect("entry exists");
        assert_eq!(got.hash, hash);

        // tracked_entries/files return stage-0 paths
        let tracked = index.tracked_entries(0);
        assert_eq!(tracked.len(), 1);
        let files = index.tracked_files();
        assert_eq!(files, vec![PathBuf::from("a/b.txt")]);

        // contains_dir_file true for subpath, false for exact file
        assert!(index.contains_dir_file("a"));
        assert!(!index.contains_dir_file("a/b.txt"));

        // remove_dir_files removes under dir and returns removed names
        let removed = index.remove_dir_files("a");
        assert_eq!(removed, vec!["a/b.txt".to_string()]);
        assert!(index.get("a/b.txt", 0).is_none());
    }

    /// check_header should reject bad magic/versions and accept valid header.
    #[test]
    fn check_header_validation() {
        // valid header: "DIRC" + version 2 + 0 entries
        let mut valid = Cursor::new(b"DIRC\0\0\0\x02\0\0\0\0".to_vec());
        let entries = Index::check_header(&mut valid).expect("valid header");
        assert_eq!(entries, 0);

        // bad magic
        let mut bad_magic = Cursor::new(b"XXXX\0\0\0\x02\0\0\0\0".to_vec());
        assert!(Index::check_header(&mut bad_magic).is_err());

        // bad version
        let mut bad_version = Cursor::new(b"DIRC\0\0\0\x01\0\0\0\0".to_vec());
        assert!(Index::check_header(&mut bad_version).is_err());
    }

    /// Test saving Index to file
    #[test]
    fn test_index_to_file() {
        let temp_dir = tempfile::tempdir().unwrap();
        let temp_path = temp_dir.path().join("index-760");

        let mut source = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        source.push("tests/data/index/index-760");

        let index = Index::from_file(source).unwrap();
        index.to_file(&temp_path).unwrap();
        let new_index = Index::from_file(temp_path).unwrap();
        assert_eq!(index.size(), new_index.size());
    }

    /// Test IndexEntry creation from file
    #[test]
    fn test_index_entry_create() {
        let _guard = set_hash_kind_for_test(HashKind::Sha1);
        let mut source = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        source.push("Cargo.toml");

        let file = Path::new(source.as_path()); // use as a normal file
        let hash = ObjectHash::from_bytes(&[0; 20]).unwrap();
        let workdir = Path::new("../");
        let entry = IndexEntry::new_from_file(file, hash, workdir).unwrap();
        println!("{entry}");
    }

    /// Test IndexEntry creation from file with SHA256
    #[test]
    fn test_index_entry_create_sha256() {
        let _guard = set_hash_kind_for_test(HashKind::Sha256);
        let mut source = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        source.push("Cargo.toml");

        let file = Path::new(source.as_path());
        let hash = ObjectHash::from_bytes(&[0u8; 32]).unwrap();
        let workdir = Path::new("../");
        let entry = IndexEntry::new_from_file(file, hash, workdir).unwrap();
        println!("{entry}");
    }
}
