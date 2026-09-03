//! Pack file encoder/decoder implementations, caches, waitlists, and stream wrappers that faithfully
//! follow the [pack-format spec](https://git-scm.com/docs/pack-format).

pub mod cache;
pub mod cache_object;
pub mod channel_reader;
pub mod decode;
pub mod encode;
pub mod entry;
mod index_entry;
pub mod pack_index;
pub mod stats;
pub mod utils;
pub mod waitlist;
pub mod wrapper;
use std::sync::{Arc, atomic::AtomicUsize};

use threadpool::ThreadPool;

use crate::{
    hash::{HashKind, ObjectHash},
    internal::{
        object::ObjectTrait,
        pack::{cache::Caches, waitlist::Waitlist},
    },
};

const DEFAULT_TMP_DIR: &str = "./.cache_temp";

/// Representation of a Git pack file in memory.
pub struct Pack {
    /// Repository hash kind used for every object ID, ref-delta base, pack trailer and idx
    /// checksum this pack touches (explicit; never read from a worker's thread-local).
    pub hash_kind: HashKind,
    pub number: usize,
    pub signature: ObjectHash,
    pub objects: Vec<Box<dyn ObjectTrait>>,
    pub pool: Arc<ThreadPool>,
    pub waitlist: Arc<Waitlist>,
    pub caches: Arc<Caches>,
    pub mem_limit: Option<usize>,
    pub cache_objs_mem: Arc<AtomicUsize>,
    pub clean_tmp: bool,
}

#[cfg(test)]
pub(crate) mod test_pack_download;

#[cfg(test)]
mod tests {
    use tracing_subscriber::util::SubscriberInitExt;

    /// CAUTION: This two is same
    /// 1.
    /// tracing_subscriber::fmt().init();
    ///
    /// 2.
    /// env::set_var("RUST_LOG", "debug"); // must be set if use `fmt::init()`, or no output
    /// tracing_subscriber::fmt::init();
    pub(crate) fn init_logger() {
        let _ = tracing_subscriber::fmt::Subscriber::builder()
            .with_target(false)
            .without_time()
            .with_level(true)
            .with_max_level(tracing::Level::DEBUG)
            .finish()
            .try_init(); // avoid multi-init
    }
}
