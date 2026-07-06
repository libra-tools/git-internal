//! Multi-tier cache for pack decoding that combines an in-memory LRU with spill-to-disk storage and
//! bookkeeping for concurrent rebuild tasks.

use std::{
    fs, io,
    path::{Path, PathBuf},
    sync::{
        Arc, Mutex, Once,
        atomic::{AtomicBool, Ordering},
    },
    thread::sleep,
};

use dashmap::{DashMap, DashSet};
use lru_mem::{LruCache, entry_size};
use threadpool::ThreadPool;

use crate::{
    hash::ObjectHash,
    internal::pack::cache_object::{ArcWrapper, CacheObject, FileLoadStore, MemSizeRecorder},
    time_it,
};

/// Cache format version appended to the disk path so that caches written with an
/// incompatible serialization format (for example the previous bincode layout)
/// are ignored instead of causing deserialization errors.
const CACHE_LAYOUT_VERSION: &str = "rkyv-v1";

/// Trait defining the interface for a multi-tier cache system.
/// This cache supports insertion and retrieval of objects by both offset and hash,
/// as well as memory usage tracking and clearing functionality.
pub trait _Cache {
    fn new(mem_size: Option<usize>, tmp_path: PathBuf, thread_num: usize) -> Self
    where
        Self: Sized;
    fn get_hash(&self, offset: usize) -> Option<ObjectHash>;
    fn insert(&self, offset: usize, hash: ObjectHash, obj: CacheObject) -> Arc<CacheObject>;
    fn get_by_offset(&self, offset: usize) -> Option<Arc<CacheObject>>;
    fn get_by_hash(&self, h: ObjectHash) -> Option<Arc<CacheObject>>;
    fn total_inserted(&self) -> usize;
    fn memory_used(&self) -> usize;
    fn clear(&self);
}

impl lru_mem::HeapSize for ObjectHash {
    fn heap_size(&self) -> usize {
        0
    }
}

/// Multi-tier cache implementation combining an in-memory LRU cache with spill-to-disk storage.
/// It uses a DashMap for offset-to-hash mapping and a DashSet to track cached hashes.
/// The cache supports concurrent rebuild tasks using a thread pool.
pub struct Caches {
    map_offset: DashMap<usize, ObjectHash>, // offset to hash
    hash_set: DashSet<ObjectHash>,          // item in the cache
    resident_hash_set: DashSet<ObjectHash>, // item currently held in the in-memory LRU
    // dropping large lru cache will take a long time on Windows without multi-thread IO
    // because "multi-thread IO" clone Arc<CacheObject>, so it won't be dropped in the main thread,
    // and `CacheObjects` will be killed by OS after Process ends abnormally
    // Solution: use `mimalloc`
    lru_cache: Mutex<LruCache<ObjectHash, ArcWrapper<CacheObject>>>,
    unbounded_cache: Option<DashMap<ObjectHash, Arc<CacheObject>>>,
    unbounded_offset_cache: Option<DashMap<usize, Arc<CacheObject>>>,
    mem_size: Option<usize>,
    tmp_path: PathBuf,
    path_prefixes: [Once; 256],
    pool: Arc<ThreadPool>,
    complete_signal: Arc<AtomicBool>,
}

impl Caches {
    /// only get object from memory, not from tmp file
    fn try_get(&self, hash: ObjectHash) -> Option<Arc<CacheObject>> {
        let mut map = self.lru_cache.lock().unwrap();
        map.get(&hash).map(|x| x.data.clone())
    }

    fn insert_lru_resident(
        &self,
        map: &mut LruCache<ObjectHash, ArcWrapper<CacheObject>>,
        hash: ObjectHash,
        obj: ArcWrapper<CacheObject>,
    ) {
        let size = entry_size(&hash, &obj);
        if size <= map.max_size() {
            while map.current_size() + size > map.max_size() {
                if let Some((evicted_hash, _)) = map.remove_lru() {
                    self.resident_hash_set.remove(&evicted_hash);
                } else {
                    break;
                }
            }
        }

        if map.insert(hash, obj).is_ok() {
            self.resident_hash_set.insert(hash);
        } else {
            self.resident_hash_set.remove(&hash);
        }
    }

    /// !IMPORTANT: because of the process of pack, the file must be written / be writing before, so it won't be dead lock
    /// fall back to temp to get item. **invoker should ensure the hash is in the cache, or it will block forever**
    fn get_fallback(&self, hash: ObjectHash) -> io::Result<Arc<CacheObject>> {
        let path = self.generate_temp_path(&self.tmp_path, hash);
        // read from tmp file
        let obj = {
            loop {
                match Self::read_from_temp(&path) {
                    Ok(x) => break x,
                    Err(e) if e.kind() == io::ErrorKind::NotFound => {
                        sleep(std::time::Duration::from_millis(10));
                        continue;
                    }
                    Err(e) => return Err(e), // other error
                }
            }
        };

        let mut map = self.lru_cache.lock().unwrap();
        let obj = Arc::new(obj);
        let mut x = ArcWrapper::new(
            obj.clone(),
            self.complete_signal.clone(),
            Some(self.pool.clone()),
        );
        x.set_store_path(path);
        self.insert_lru_resident(&mut map, hash, x);
        Ok(obj)
    }

    /// generate the temp file path, hex string of the hash
    fn generate_temp_path(&self, tmp_path: &Path, hash: ObjectHash) -> PathBuf {
        // Reserve capacity for base path, 2-char subdir, hex hash string, and separators
        let mut path =
            PathBuf::with_capacity(self.tmp_path.capacity() + hash.to_string().len() + 5);
        path.push(tmp_path);
        path.push(CACHE_LAYOUT_VERSION);
        let hash_str = hash._to_string();
        path.push(&hash_str[..2]); // use first 2 chars as the directory
        self.path_prefixes[hash.as_ref()[0] as usize].call_once(|| {
            // Check if the directory exists, if not, create it
            if !path.exists() {
                fs::create_dir_all(&path).unwrap();
            }
        });
        path.push(hash_str);
        path
    }

    /// read CacheObject from temp file
    fn read_from_temp(path: &Path) -> io::Result<CacheObject> {
        let obj = CacheObject::f_load(path)?;
        // Deserializing will also create an object but without Construction outside and `::new()`
        // So if you want to do sth. while Constructing, impl Deserialize trait yourself
        obj.record_mem_size();
        Ok(obj)
    }

    /// number of queued tasks in the thread pool
    pub fn queued_tasks(&self) -> usize {
        self.pool.queued_count()
    }

    pub(crate) fn is_unbounded(&self) -> bool {
        self.mem_size.is_none()
    }

    /// memory used by the index (exclude lru_cache which is contained in CacheObject::get_mem_size())
    pub fn memory_used_index(&self) -> usize {
        let hash_cache_size = if let Some(cache) = &self.unbounded_cache {
            cache.capacity()
                * (std::mem::size_of::<ObjectHash>() + std::mem::size_of::<Arc<CacheObject>>())
        } else {
            self.hash_set.capacity() * std::mem::size_of::<ObjectHash>()
        };
        let offset_cache_size = if let Some(cache) = &self.unbounded_offset_cache {
            cache.capacity()
                * (std::mem::size_of::<usize>() + std::mem::size_of::<Arc<CacheObject>>())
        } else {
            self.map_offset.capacity()
                * (std::mem::size_of::<usize>() + std::mem::size_of::<ObjectHash>())
        };
        hash_cache_size + offset_cache_size
    }

    pub(crate) fn shutdown(&self) {
        time_it!("Caches clear", {
            self.complete_signal.store(true, Ordering::Release);
            self.pool.join();
            self.lru_cache
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .clear();
            if let Some(cache) = &self.unbounded_cache {
                cache.clear();
                cache.shrink_to_fit();
            }
            if let Some(cache) = &self.unbounded_offset_cache {
                cache.clear();
                cache.shrink_to_fit();
            }
            self.hash_set.clear();
            self.hash_set.shrink_to_fit();
            self.resident_hash_set.clear();
            self.resident_hash_set.shrink_to_fit();
            self.map_offset.clear();
            self.map_offset.shrink_to_fit();
        });
    }

    /// remove the tmp dir
    pub fn remove_tmp_dir(&self) -> io::Result<()> {
        time_it!("Remove tmp dir", {
            if self.tmp_path.exists() {
                match fs::remove_dir_all(&self.tmp_path) {
                    Ok(()) => {}
                    Err(e) if e.kind() == io::ErrorKind::NotFound => {}
                    Err(e) => return Err(e),
                }

                if let Some(parent) = self.tmp_path.parent() {
                    let is_cache_temp = parent
                        .file_name()
                        .and_then(|n| n.to_str())
                        .map(|n| n == ".cache_temp")
                        .unwrap_or(false);
                    if is_cache_temp {
                        match fs::remove_dir(parent) {
                            Ok(()) => {}
                            Err(e)
                                if matches!(
                                    e.kind(),
                                    io::ErrorKind::DirectoryNotEmpty | io::ErrorKind::NotFound
                                ) => {}
                            Err(e) => return Err(e),
                        }
                    }
                }
            }

            Ok(())
        })
    }

    pub fn remove_unbounded(&self, offset: usize, hash: ObjectHash) {
        if self.unbounded_cache.is_some() && self.lru_cache.lock().unwrap().remove(&hash).is_some()
        {
            self.resident_hash_set.remove(&hash);
        }
        if let Some(cache) = &self.unbounded_offset_cache {
            cache.remove(&offset);
        }
        if let Some(cache) = &self.unbounded_cache {
            cache.remove(&hash);
        }
    }
}

impl _Cache for Caches {
    /// @param size: the size of the memory lru cache. **None means no limit**
    /// @param tmp_path: the path to store the cache object in the tmp file
    fn new(mem_size: Option<usize>, tmp_path: PathBuf, thread_num: usize) -> Self
    where
        Self: Sized,
    {
        // `None` means no limit, so no need to create the tmp dir
        if mem_size.is_some() {
            fs::create_dir_all(&tmp_path).unwrap();
        }

        Caches {
            map_offset: DashMap::new(),
            hash_set: DashSet::new(),
            resident_hash_set: DashSet::new(),
            lru_cache: Mutex::new(LruCache::new(mem_size.unwrap_or(usize::MAX))),
            unbounded_cache: mem_size.is_none().then(DashMap::new),
            unbounded_offset_cache: mem_size.is_none().then(DashMap::new),
            mem_size,
            tmp_path,
            path_prefixes: [const { Once::new() }; 256],
            pool: Arc::new(ThreadPool::new(thread_num)),
            complete_signal: Arc::new(AtomicBool::new(false)),
        }
    }

    fn get_hash(&self, offset: usize) -> Option<ObjectHash> {
        if let Some(cache) = &self.unbounded_offset_cache {
            return cache.get(&offset).and_then(|obj| obj.base_object_hash());
        }
        self.map_offset.get(&offset).map(|x| *x)
    }

    fn insert(&self, offset: usize, hash: ObjectHash, obj: CacheObject) -> Arc<CacheObject> {
        let obj_arc = Arc::new(obj);
        if let Some(cache) = &self.unbounded_cache {
            cache.insert(hash, obj_arc.clone());
            if let Some(offset_cache) = &self.unbounded_offset_cache {
                offset_cache.insert(offset, obj_arc.clone());
            }
            let mut map = self.lru_cache.lock().unwrap();
            let a_obj = ArcWrapper::new(
                obj_arc.clone(),
                self.complete_signal.clone(),
                Some(self.pool.clone()),
            );
            self.insert_lru_resident(&mut map, hash, a_obj);
        } else {
            // ? whether insert to cache directly or only write to tmp file
            //
            // Scope the `lru_cache` guard so it is released BEFORE we write
            // `map_offset` below. Holding lru across the `map_offset` DashMap
            // write, while get_by_offset() takes the `map_offset` shard read
            // lock and then locks lru, is an ABBA lock-order inversion that
            // deadlocks concurrent pack decoding. (This inner scope existed in
            // 0.7.6 and was lost when insert was refactored to use
            // `insert_lru_resident`; its removal introduced the deadlock.)
            {
                let mut map = self.lru_cache.lock().unwrap();
                let mut a_obj = ArcWrapper::new(
                    obj_arc.clone(),
                    self.complete_signal.clone(),
                    Some(self.pool.clone()),
                );
                if self.mem_size.is_some() {
                    a_obj.set_store_path(self.generate_temp_path(&self.tmp_path, hash));
                }
                self.insert_lru_resident(&mut map, hash, a_obj);
            }
            self.hash_set.insert(hash);
            // order matters as for reading in 'get_by_offset()': the object is
            // made resident in lru above before its offset becomes visible here.
            self.map_offset.insert(offset, hash);
        }

        obj_arc
    }

    /// get object by offset, from memory or tmp file
    fn get_by_offset(&self, offset: usize) -> Option<Arc<CacheObject>> {
        // IMPORTANT: never hold a `map_offset` / `unbounded_offset_cache`
        // DashMap shard read-guard across a `lru_cache` lock. `insert()` holds
        // the `lru_cache` mutex across a `map_offset` write (lru -> shard), so
        // taking the shard read-lock here and then locking `lru_cache`
        // (shard -> lru) forms an ABBA lock-order inversion that deadlocks
        // concurrent pack decoding. Copy the hash out and drop the shard
        // read-guard BEFORE calling into `try_get` / `get_by_hash` (both of
        // which lock `lru_cache`).
        if let Some(cache) = &self.unbounded_offset_cache {
            let hash = cache.get(&offset).and_then(|obj| obj.base_object_hash());
            return hash.and_then(|hash| self.try_get(hash));
        }

        let hash = self.map_offset.get(&offset).map(|x| *x);
        hash.and_then(|hash| self.get_by_hash(hash))
    }

    /// get object by hash, from memory or tmp file
    fn get_by_hash(&self, hash: ObjectHash) -> Option<Arc<CacheObject>> {
        if self.mem_size.is_none() {
            if let Some(cache) = &self.unbounded_cache
                && !cache.contains_key(&hash)
            {
                return None;
            }
            return self.try_get(hash);
        }

        // check if the hash is in the cache( lru or tmp file)
        if self.hash_set.contains(&hash) {
            if !self.resident_hash_set.contains(&hash) {
                return self.get_fallback(hash).ok();
            }
            match self.try_get(hash) {
                Some(x) => Some(x),
                None => {
                    if self.mem_size.is_none() {
                        panic!("should not be here when mem_size is not set")
                    }
                    self.get_fallback(hash).ok()
                }
            }
        } else {
            None
        }
    }

    fn total_inserted(&self) -> usize {
        if self.mem_size.is_some() {
            self.hash_set.len()
        } else if let Some(cache) = &self.unbounded_offset_cache {
            cache.len()
        } else {
            self.map_offset.len()
        }
    }
    fn memory_used(&self) -> usize {
        self.lru_cache.lock().unwrap().current_size() + self.memory_used_index()
    }
    fn clear(&self) {
        self.shutdown();

        assert_eq!(self.pool.queued_count(), 0);
        assert_eq!(self.pool.active_count(), 0);
        assert_eq!(self.lru_cache.lock().unwrap().len(), 0);
    }
}

#[cfg(test)]
mod test {
    use std::{env, sync::Arc, thread};

    use super::*;
    use crate::{
        hash::{HashKind, ObjectHash, set_hash_kind_for_test},
        internal::{object::types::ObjectType, pack::cache_object::CacheObjectInfo},
    };

    /// Helper to build a base CacheObject with given size and hash.
    fn make_obj(size: usize, hash: ObjectHash) -> CacheObject {
        CacheObject {
            info: CacheObjectInfo::BaseObject(ObjectType::Blob, hash),
            data_decompressed: vec![0; size],
            mem_recorder: None,
            offset: 0,
            crc32: 0,
            is_delta_in_pack: false,
            known_hash: None,
        }
    }

    /// test single-threaded cache behavior with different hash kinds and capacities
    #[test]
    fn test_cache_single_thread() {
        for (kind, cap, size_ab, size_c, tmp_dir) in [
            (
                HashKind::Sha1,
                2048usize,
                800usize,
                1700usize,
                "tests/.cache_tmp",
            ),
            (
                HashKind::Sha256,
                4096usize,
                1500usize,
                3000usize,
                "tests/.cache_tmp_sha256",
            ),
        ] {
            let _guard = set_hash_kind_for_test(kind);
            let source = PathBuf::from(env::current_dir().unwrap().parent().unwrap());
            let tmp_path = source.clone().join(tmp_dir);
            if tmp_path.exists() {
                fs::remove_dir_all(&tmp_path).unwrap();
            }

            let cache = Caches::new(Some(cap), tmp_path, 1);
            let a_hash = ObjectHash::new(String::from("a").as_bytes());
            let b_hash = ObjectHash::new(String::from("b").as_bytes());
            let c_hash = ObjectHash::new(String::from("c").as_bytes());

            let a = make_obj(size_ab, a_hash);
            let b = make_obj(size_ab, b_hash);
            let c = make_obj(size_c, c_hash);

            // insert a
            cache.insert(a.offset, a_hash, a.clone());
            assert!(cache.hash_set.contains(&a_hash));
            assert!(cache.try_get(a_hash).is_some());

            // insert b, a should still be in cache
            cache.insert(b.offset, b_hash, b.clone());
            assert!(cache.hash_set.contains(&b_hash));
            assert!(cache.try_get(b_hash).is_some());
            assert!(cache.try_get(a_hash).is_some());

            // insert c which will evict both a and b
            cache.insert(c.offset, c_hash, c.clone());
            assert!(cache.try_get(a_hash).is_none());
            assert!(cache.try_get(b_hash).is_none());
            assert!(cache.try_get(c_hash).is_some());
            assert!(cache.get_by_hash(c_hash).is_some());
        }
    }

    /// consider the multi-threaded scenario where different threads use different hash kinds
    #[test]
    fn test_cache_multi_thread_mixed_hash_kinds() {
        let base = PathBuf::from(env::current_dir().unwrap().parent().unwrap());
        let tmp_path = base.join("tests/.cache_tmp_mixed");
        if tmp_path.exists() {
            fs::remove_dir_all(&tmp_path).unwrap();
        }

        let cache = Arc::new(Caches::new(Some(4096), tmp_path, 2));

        let cache_sha1 = Arc::clone(&cache);
        let handle_sha1 = thread::spawn(move || {
            let _g = set_hash_kind_for_test(HashKind::Sha1);
            let hash = ObjectHash::new(b"sha1-entry");
            let obj = CacheObject {
                info: CacheObjectInfo::BaseObject(ObjectType::Blob, hash),
                data_decompressed: vec![0; 800],
                mem_recorder: None,
                offset: 1,
                crc32: 0,
                is_delta_in_pack: false,
                known_hash: None,
            };
            cache_sha1.insert(obj.offset, hash, obj.clone());
            assert!(cache_sha1.hash_set.contains(&hash));
            assert!(cache_sha1.try_get(hash).is_some());
        });

        let cache_sha256 = Arc::clone(&cache);
        let handle_sha256 = thread::spawn(move || {
            let _g = set_hash_kind_for_test(HashKind::Sha256);
            let hash = ObjectHash::new(b"sha256-entry");
            let obj = CacheObject {
                info: CacheObjectInfo::BaseObject(ObjectType::Blob, hash),
                data_decompressed: vec![0; 1500],
                mem_recorder: None,
                offset: 2,
                crc32: 0,
                is_delta_in_pack: false,
                known_hash: None,
            };
            cache_sha256.insert(obj.offset, hash, obj.clone());
            assert!(cache_sha256.hash_set.contains(&hash));
            assert!(cache_sha256.try_get(hash).is_some());
        });

        handle_sha1.join().unwrap();
        handle_sha256.join().unwrap();

        assert_eq!(cache.total_inserted(), 2);
    }

    #[test]
    fn test_remove_tmp_dir_does_not_panic_when_cleanup_fails() {
        let dir = tempfile::tempdir().unwrap();
        let tmp_path = dir.path().join("not-a-directory");
        fs::write(&tmp_path, b"cache marker").unwrap();
        let cache = Caches::new(None, tmp_path, 1);

        let result =
            std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| cache.remove_tmp_dir()));

        assert!(result.is_ok(), "cache cleanup should not panic");
        assert!(
            result.unwrap().is_err(),
            "cleanup failure should be returned"
        );
    }

    #[test]
    fn test_unbounded_cache_skips_hash_set_index() {
        let _guard = set_hash_kind_for_test(HashKind::Sha1);
        let base = PathBuf::from(env::current_dir().unwrap().parent().unwrap());
        let tmp_path = base.join("tests/.cache_tmp_unbounded");
        let cache = Caches::new(None, tmp_path, 1);
        let hash = ObjectHash::new(b"unbounded-entry");
        let obj = make_obj(64, hash);

        cache.insert(obj.offset, hash, obj);

        assert!(cache.hash_set.is_empty());
        assert!(cache.resident_hash_set.contains(&hash));
        assert_eq!(cache.total_inserted(), 1);
        assert_eq!(cache.get_hash(0), Some(hash));
        assert!(cache.try_get(hash).is_some());
        assert!(cache.get_by_hash(hash).is_some());
        assert!(
            cache
                .get_by_hash(ObjectHash::new(b"missing-entry"))
                .is_none()
        );
        assert!(cache.get_by_offset(0).is_some());
        assert!(cache.memory_used_index() > 0);
    }

    #[test]
    fn test_bounded_cache_tracks_resident_entries() {
        let _guard = set_hash_kind_for_test(HashKind::Sha1);
        let base = PathBuf::from(env::current_dir().unwrap().parent().unwrap());
        let tmp_path = base.join("tests/.cache_tmp_resident");
        if tmp_path.exists() {
            fs::remove_dir_all(&tmp_path).unwrap();
        }

        let cache = Caches::new(Some(2048), tmp_path, 1);
        let a_hash = ObjectHash::new(b"resident-a");
        let b_hash = ObjectHash::new(b"resident-b");
        let a = make_obj(1800, a_hash);
        let b = make_obj(1800, b_hash);

        cache.insert(a.offset, a_hash, a);
        assert!(cache.hash_set.contains(&a_hash));
        assert!(cache.resident_hash_set.contains(&a_hash));

        cache.insert(b.offset + 1, b_hash, b);
        assert!(cache.hash_set.contains(&a_hash));
        assert!(cache.hash_set.contains(&b_hash));
        assert!(!cache.resident_hash_set.contains(&a_hash));
        assert!(cache.resident_hash_set.contains(&b_hash));
    }

    /// Regression test for the ABBA lock-order inversion between the `lru_cache`
    /// `Mutex` and the `map_offset` `DashMap` shard lock that deadlocked pack
    /// decoding (git-internal <= 0.8.2).
    ///
    /// Two code paths acquired the two locks in opposite order:
    ///   * `insert()` (bounded path): lock `lru_cache`, then — while still
    ///     holding it — write `map_offset`  (order: lru -> shard).
    ///   * `get_by_offset()`: hold the `map_offset` shard read-guard across
    ///     `get_by_hash()`/`try_get()`, which lock `lru_cache` (order: shard -> lru).
    ///
    /// When a base `insert()` and a delta `get_by_offset()` hit the same
    /// `DashMap` shard concurrently they wait on each other forever. This test
    /// hammers both paths on a tiny offset space (so they collide on the same
    /// shard) from many threads and fails via a watchdog timeout if they wedge.
    /// It completes near-instantly once the inversion is fixed.
    #[test]
    fn test_cache_concurrent_insert_get_by_offset_no_deadlock() {
        let _guard = set_hash_kind_for_test(HashKind::Sha1);
        let tmp = std::env::temp_dir().join(format!(
            "gi_cache_abba_{}_{:?}",
            std::process::id(),
            thread::current().id()
        ));
        if tmp.exists() {
            let _ = fs::remove_dir_all(&tmp);
        }

        // Bounded cache (mem_size = Some) exercises the buggy lru -> map_offset
        // ordering in insert(). Sized large enough that every object stays
        // resident, so get_by_offset() resolves via try_get() (which locks
        // lru_cache) rather than the disk fallback — keeping the race tight and
        // deterministic without depending on eviction.
        let cache = Arc::new(Caches::new(Some(1 << 20), tmp.clone(), 8));

        // A small offset space keeps writers and readers colliding on the same
        // DashMap shards, which is what the inversion needs to wedge.
        const OFFSETS: usize = 8;
        const ITERS: usize = 20_000;
        const WRITERS: usize = 6;
        const READERS: usize = 6;

        let hashes: Arc<Vec<ObjectHash>> = Arc::new(
            (0..OFFSETS)
                .map(|i| ObjectHash::new(format!("obj-{i}").as_bytes()))
                .collect(),
        );

        let (done_tx, done_rx) = std::sync::mpsc::channel();
        let mut handles = Vec::new();

        for _ in 0..WRITERS {
            let cache = cache.clone();
            let hashes = hashes.clone();
            let done_tx = done_tx.clone();
            handles.push(thread::spawn(move || {
                let _g = set_hash_kind_for_test(HashKind::Sha1);
                for k in 0..ITERS {
                    let o = k % OFFSETS;
                    let obj = CacheObject {
                        info: CacheObjectInfo::BaseObject(ObjectType::Blob, hashes[o]),
                        data_decompressed: vec![0u8; 64],
                        mem_recorder: None,
                        offset: o,
                        crc32: 0,
                        is_delta_in_pack: false,
                        known_hash: None,
                    };
                    cache.insert(o, hashes[o], obj);
                }
                let _ = done_tx.send(());
            }));
        }

        for _ in 0..READERS {
            let cache = cache.clone();
            let done_tx = done_tx.clone();
            handles.push(thread::spawn(move || {
                let _g = set_hash_kind_for_test(HashKind::Sha1);
                for k in 0..ITERS {
                    let o = k % OFFSETS;
                    let _ = cache.get_by_offset(o);
                }
                let _ = done_tx.send(());
            }));
        }
        drop(done_tx);

        // Watchdog: every worker must finish well within the timeout. On the
        // pre-fix code the pool wedges (lru_cache <-> map_offset) and this times
        // out; on fixed code all workers finish in well under a second.
        let workers = WRITERS + READERS;
        for finished in 0..workers {
            if done_rx
                .recv_timeout(std::time::Duration::from_secs(30))
                .is_err()
            {
                panic!(
                    "cache deadlock: only {finished}/{workers} workers finished within 30s — \
                     the lru_cache <-> map_offset ABBA lock-order inversion has regressed"
                );
            }
        }

        for h in handles {
            h.join().unwrap();
        }
        // Drain the spill thread-pool before deleting the temp dir so in-flight
        // f_save tasks don't race with cleanup.
        cache.clear();
        let _ = fs::remove_dir_all(&tmp);
    }
}
