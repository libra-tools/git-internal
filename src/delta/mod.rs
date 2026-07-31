//! Custom delta engine roughly mirroring Git's ref/offset-delta encoding plus heuristics that decide
//! when it's worthwhile to delta compress blobs.

#![allow(dead_code)]

use std::hash::{DefaultHasher, Hash, Hasher};

use encode::DeltaDiff;
use rayon::prelude::*;

mod decode;
mod encode;
mod errors;
mod utils;

pub(crate) use decode::delta_decode;

const SAMPLE_STEP: usize = 64;
const MIN_DELTA_RATE: f64 = 0.5;

/// Approximate match rate between two buffers using sampled hashing; returns 0.0 if early exit below threshold.
#[allow(clippy::manual_div_ceil)]
pub fn heuristic_encode_rate(old_data: &[u8], new_data: &[u8]) -> f64 {
    let old_len = old_data.len();
    let new_len = new_data.len();

    if old_len == 0 && new_len == 0 {
        return 1.0;
    }
    if old_len == 0 || new_len == 0 {
        return 0.0;
    }

    let step = SAMPLE_STEP;
    let mut match_count = 0;
    let mut sample_count = 0;

    let min_len = old_len.min(new_len);

    let total_samples = (min_len + step - 1) / step;
    let mut i = 0;
    while i < min_len {
        let old_chunk = &old_data[i..(i + step).min(old_len)];
        let new_chunk = &new_data[i..(i + step).min(new_len)];

        if hash_chunk(old_chunk) == hash_chunk(new_chunk) {
            match_count += 1;
        }
        sample_count += 1;

        // Early stopping condition:
        // If all remaining samples matched, the rate would still not reach MIN_DELTA_RATE, so return 0 early
        let remaining_samples = total_samples - sample_count;
        let max_possible_rate = (match_count + remaining_samples) as f64 / total_samples as f64;
        if max_possible_rate < MIN_DELTA_RATE {
            return 0.0;
        }

        i += step;
    }

    match_count as f64 / sample_count as f64
}

/// Hash a sample chunk for quick equality check (used by heuristic sampling).
fn hash_chunk(chunk: &[u8]) -> u64 {
    let mut hasher = DefaultHasher::new();
    chunk.hash(&mut hasher);
    hasher.finish()
}

/// Parallel heuristic match rate for large inputs; adjusts sample step size based on length.
pub fn heuristic_encode_rate_parallel(old_data: &[u8], new_data: &[u8]) -> f64 {
    let old_len = old_data.len();
    let new_len = new_data.len();

    if old_len == 0 && new_len == 0 {
        return 1.0;
    }
    if old_len == 0 || new_len == 0 {
        return 0.0;
    }

    let min_len = old_len.min(new_len);

    let step = if min_len > 10_000_000 {
        1024
    } else if min_len > 1_000_000 {
        512
    } else if min_len > 100_000 {
        128
    } else {
        16
    };

    let chunks: Vec<_> = old_data[..min_len]
        .chunks(step)
        .zip(new_data[..min_len].chunks(step))
        .collect();

    let match_count: usize = chunks.par_iter().filter(|(a, b)| a == b).count();

    let rate = match_count as f64 / chunks.len() as f64;
    if rate < MIN_DELTA_RATE { 0.0 } else { rate }
}

/// Compute a more accurate similarity rate by building a full delta (shared bytes / new_data len).
pub fn encode_rate(old_data: &[u8], new_data: &[u8]) -> f64 {
    let differ = DeltaDiff::new(old_data, new_data);
    differ.get_ssam_rate()
}

/// Produce a Git-style delta instruction stream from two buffers.
pub fn encode(old_data: &[u8], new_data: &[u8]) -> Vec<u8> {
    let differ = DeltaDiff::new(old_data, new_data);
    differ.encode()
}

/// Produce a Git-style delta using Rabin fingerprint matching (available with `diff_rabin` feature).
#[cfg(feature = "diff_rabin")]
pub fn encode_rabin(old_data: &[u8], new_data: &[u8]) -> Vec<u8> {
    encode::rabin::encode_rabin(old_data, new_data)
}

/// Compute exact similarity rate via Rabin fingerprint delta (available with `diff_rabin` feature).
#[cfg(feature = "diff_rabin")]
pub fn rabin_encode_rate(old_data: &[u8], new_data: &[u8]) -> f64 {
    encode::rabin::rabin_encode_rate(old_data, new_data)
}

/// Fast heuristic similarity screening using Rabin hashes (available with `diff_rabin` feature).
#[cfg(feature = "diff_rabin")]
pub fn heuristic_encode_rate_rabin(old_data: &[u8], new_data: &[u8]) -> f64 {
    encode::rabin::heuristic_encode_rate_rabin(old_data, new_data)
}

// ── Re-exports for index-caching and optimized delta APIs ───────────────

/// Re-export `RabinDeltaIndex` for external index caching.
#[cfg(feature = "diff_rabin")]
pub use encode::rabin::RabinDeltaIndex;

/// Build a Rabin fingerprint index from source data (available with `diff_rabin`).
///
/// The index can be cached and reused across multiple delta computations
/// against the same source, avoiding redundant index construction.
#[cfg(feature = "diff_rabin")]
pub fn create_delta_index(source: &[u8]) -> Option<RabinDeltaIndex> {
    encode::rabin::create_delta_index(source)
}

/// Build a Rabin fingerprint index from an `Arc<[u8]>` (available with `diff_rabin`).
///
/// This avoids copying the source buffer — the index shares ownership via `Arc`
/// reference counting. Preferred when the caller already holds an `Arc<[u8]>`,
/// e.g., from a delta window entry that can share the buffer with the index.
#[cfg(feature = "diff_rabin")]
pub fn create_delta_index_arc(source: std::sync::Arc<[u8]>) -> Option<RabinDeltaIndex> {
    encode::rabin::create_delta_index_arc(source)
}

/// Produce a delta using a pre-built index (available with `diff_rabin`).
///
/// Skips index construction — the caller supplies a cached `RabinDeltaIndex`.
#[cfg(feature = "diff_rabin")]
pub fn encode_rabin_with_index(index: &RabinDeltaIndex, target: &[u8]) -> Vec<u8> {
    encode::rabin::encode_rabin_with_index(index, target)
}

/// Produce a delta with early termination if output exceeds `max_size`
/// (available with `diff_rabin`).
///
/// Returns `None` if the delta was aborted because it would exceed `max_size`.
/// This is the fast path for candidate scoring: try many bases, abort early
/// when a candidate can't beat the current best.
#[cfg(feature = "diff_rabin")]
pub fn encode_rabin_with_index_and_max_size(
    index: &RabinDeltaIndex,
    target: &[u8],
    max_size: usize,
) -> Option<Vec<u8>> {
    encode::rabin::encode_rabin_with_index_and_max_size(index, target, max_size)
}

/// Git-compatible name hash for delta-friendly object sorting.
///
/// Implements git's `pack_name_hash` for use in `magic_sort` to cluster
/// files with similar paths together, maximizing delta opportunities.
///
/// Always available regardless of feature flags — this is a standalone
/// hash function that doesn't depend on rabin.
///
/// Accepts raw bytes to avoid any allocation overhead in sort comparators.
/// Git paths are always valid UTF-8 / ASCII.
pub fn pack_name_hash(path_bytes: &[u8]) -> u32 {
    // Extract the last path component by scanning for '/' from the end.
    // This avoids any string allocation overhead.
    let start = path_bytes
        .iter()
        .rposition(|&b| b == b'/')
        .map(|i| i + 1)
        .unwrap_or(0);
    let name = &path_bytes[start..];

    let mut hash: u32 = 0;
    for &c in name {
        if c == b' ' || c == b'\t' || c == b'\n' || c == b'\r' {
            continue;
        }
        hash = (hash >> 2).wrapping_add((c as u32) << 24);
    }
    hash
}

#[cfg(test)]
mod tests {
    use super::{encode_rate, heuristic_encode_rate, heuristic_encode_rate_parallel};

    /// Heuristic vs accurate rates on small strings and edge cases:
    /// - identical buffers => 1.0
    /// - minor edits => partial rate between (0.5,1.0)
    /// - totally different => low rate
    /// - empty/empty => 1.0; empty vs non-empty => 0.0.
    #[test]
    fn test_heuristic_encode_rate() {
        let data1 = b"hello world, this is a test for delta rate";
        let data2 = b"hello world, this is a test for delta rate";
        let rate = heuristic_encode_rate(data1, data2);
        println!("rate = {}", rate);
        assert!((rate - 1.0).abs() < 1e-6, "Expected 1.0 for identical data");

        let data3 = b"hello world, this is a test for delta rate";
        let data4 = b"hello worll, this is a test for delta rate";
        let rate = encode_rate(data3, data4);
        println!("rate = {}", rate);
        assert!(
            rate > 0.5 && rate < 1.0,
            "Expected partial match for similar data"
        );

        let data5 = b"abcdefghijklmno";
        let data6 = b"1234567890!@#";
        let rate = heuristic_encode_rate(data5, data6);
        println!("rate = {}", rate);
        assert!(rate < 0.2, "Expected low match rate for different data");

        let data7 = b"";
        let data8 = b"";
        let rate = heuristic_encode_rate(data7, data8);
        println!("rate = {}", rate);
        assert_eq!(rate, 1.0, "Empty slices should be fully matching");

        let rate = heuristic_encode_rate(data7, data1);
        assert_eq!(rate, 0.0, "Empty vs non-empty should give 0 rate");
    }

    /// Heuristic rates on large buffers:
    /// - completely different large slices should early-stop to 0
    /// - partially different large slices: parallel heuristic vs accurate rate should be close.
    #[test]
    fn test_heuristic_encode_rate_large_files() {
        let data1 = vec![0u8; 100_000];
        let data2 = vec![1u8; 100_000];
        let rate = heuristic_encode_rate(&data1, &data2);
        println!("Large non-matching data rate = {}", rate);
        assert_eq!(
            rate, 0.0,
            "Large completely different data should early stop with 0 rate"
        );

        let data3 = vec![0u8; 100];
        let mut data4 = vec![0u8; 100];

        for i in data4.iter_mut().take(2) {
            *i = 1;
        }

        let rate1 = heuristic_encode_rate_parallel(&data3, &data4);
        let rate2 = encode_rate(&data3, &data4);

        println!(
            "Large partially matching data rate = {}, accurate rate = {}",
            rate1, rate2
        );

        assert!(
            (rate2 - rate1).abs() < 0.2,
            "Large partially matching data should preserve partial rate"
        );
    }
}
