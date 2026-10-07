//! A small Bloom filter used to skip the FST walk for most names.
//!
//! It hashes with a fast, per-filter randomly seeded mixer rather than
//! `SipHash`: a collision only costs one FST walk, so the hash needs speed,
//! not cryptographic strength, and the random seed keeps clients from
//! predicting which names collide.

use std::hash::{BuildHasher, RandomState};

/// Bits per inserted item; about 1% false positives with `HASHES` probes.
const BITS_PER_ITEM: usize = 10;

/// Probes per lookup.
const HASHES: u64 = 7;

/// A fixed-size Bloom filter over byte strings.
pub(crate) struct Bloom {
    bits: Vec<u64>,
    /// `bits` holds `mask + 1` bits, a power of two, so `& mask` is the
    /// modulo.
    mask: u64,
    seed: u64,
}

impl Bloom {
    /// A filter sized for `items` insertions.
    pub(crate) fn with_capacity(items: usize) -> Self {
        let bits = items
            .saturating_mul(BITS_PER_ITEM)
            .max(64)
            .checked_next_power_of_two()
            .unwrap_or(1 << 40);
        let words = bits / 64;
        Self {
            bits: vec![0; words],
            mask: u64::try_from(bits).map_or(u64::MAX, |bits| bits.saturating_sub(1)),
            // A random seed from the standard library's per-process keys.
            seed: RandomState::new().hash_one(0x5eed_u64),
        }
    }

    pub(crate) fn insert(&mut self, item: &[u8]) {
        for bit in self.probes(item) {
            if let Some(word) = self.bits.get_mut(word_index(bit)) {
                *word |= 1 << (bit % 64);
            }
        }
    }

    /// False means `item` was certainly never inserted.
    pub(crate) fn may_contain(&self, item: &[u8]) -> bool {
        self.probes(item).all(|bit| {
            self.bits
                .get(word_index(bit))
                .is_some_and(|word| word & (1 << (bit % 64)) != 0)
        })
    }

    /// Bytes used by the bit array.
    pub(crate) fn size(&self) -> usize {
        self.bits.len().saturating_mul(8)
    }

    /// Double hashing (Kirsch and Mitzenmacher): probe i is `h1 + i * h2`,
    /// with both halves taken from one 64-bit hash.
    fn probes(&self, item: &[u8]) -> impl Iterator<Item = u64> + use<> {
        let hash = mix(self.seed, item);
        let h1 = hash;
        let h2 = hash.rotate_left(32) | 1;
        let mask = self.mask;
        (0..HASHES).map(move |i| h1.wrapping_add(i.wrapping_mul(h2)) & mask)
    }
}

/// A fast 64-bit hash: multiply-rotate per 8-byte word, then the `MurmurHash3`
/// finalizer.
fn mix(seed: u64, bytes: &[u8]) -> u64 {
    const K: u64 = 0x9e37_79b9_7f4a_7c15;
    let len = u64::try_from(bytes.len()).unwrap_or(u64::MAX);
    let mut hash = seed ^ len.wrapping_mul(K);
    let (words, rest) = bytes.as_chunks::<8>();
    for word in words {
        hash = (hash ^ u64::from_le_bytes(*word))
            .wrapping_mul(K)
            .rotate_left(29);
    }
    let mut tail = [0_u8; 8];
    for (slot, byte) in tail.iter_mut().zip(rest) {
        *slot = *byte;
    }
    hash = (hash ^ u64::from_le_bytes(tail)).wrapping_mul(K);
    hash ^= hash >> 33;
    hash = hash.wrapping_mul(0xff51_afd7_ed55_8ccd);
    hash ^= hash >> 33;
    hash = hash.wrapping_mul(0xc4ce_b9fe_1a85_ec53);
    hash ^ (hash >> 33)
}

fn word_index(bit: u64) -> usize {
    usize::try_from(bit / 64).unwrap_or(usize::MAX)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn no_false_negatives_and_few_false_positives() {
        let mut bloom = Bloom::with_capacity(10_000);
        for i in 0..10_000_u32 {
            bloom.insert(&i.to_be_bytes());
        }
        assert!((0..10_000_u32).all(|i| bloom.may_contain(&i.to_be_bytes())));
        let false_positives = (10_000..110_000_u32)
            .filter(|i| bloom.may_contain(&i.to_be_bytes()))
            .count();
        assert!(false_positives < 2_000, "{false_positives} in 100,000");
    }

    #[test]
    fn empty_filter_contains_nothing() {
        let bloom = Bloom::with_capacity(0);
        assert!(!bloom.may_contain(b"anything"));
        assert_eq!(bloom.size(), 8);
    }
}
