//! `lut-view` — the LUT-view: a content-addressed vector of token hashes.
//!
//! # v1 contract
//!
//! - **Leaves** = SHA-1 of token bytes (`[u8; 20]`), in materialization
//!   order — a *vector*, not a set (order is part of the identity for now).
//! - **Identity** = `digest = SHA-1(leaf_0 ‖ leaf_1 ‖ … ‖ leaf_n)`, exposed
//!   as the view key `v:<40-hex>`.
//! - **Update rule** = recompute, compare digests, replace iff changed
//!   ([`LutView::refresh`]).
//! - **Ephemeral** = the view is a derived, disposable cache; dropping it
//!   loses only a recomputation, never data. The LUT it mirrors stays whole
//!   and append-only.
//!
//! # Upgrade path (deliberately not v1)
//!
//! 1. canonical form (sorted, deduplicated) for set semantics — then the
//!    digest identifies the vocabulary regardless of materialization order;
//! 2. Merkle tree over the leaves (levels kept, membership proofs,
//!    subtree-level diff/merge) — the flat digest remains a valid root of
//!    the flat tree;
//! 3. per-LUT provenance tags (`LutKind`) and view composition (union).

use sha1::{Digest, Sha1};

/// A leaf hash: SHA-1 of one token's bytes.
pub type Hash = [u8; 20];

/// A view digest: SHA-1 over the concatenated leaves.
pub type ViewDigest = [u8; 20];

/// Digest a slice of leaves in order (the v1 identity rule).
pub fn digest_of(hashes: &[Hash]) -> ViewDigest {
    let mut hasher = Sha1::new();
    for hash in hashes {
        hasher.update(hash);
    }
    hasher.finalize().into()
}

/// Hash one token's bytes.
pub fn hash_token(token: &[u8]) -> Hash {
    Sha1::digest(token).into()
}

/// A LUT-view: the vector of token hashes + its content address.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct LutView {
    hashes: Vec<Hash>,
    digest: ViewDigest,
}

impl LutView {
    /// Build a view from leaf hashes (order preserved).
    pub fn from_hashes(hashes: impl IntoIterator<Item = Hash>) -> Self {
        let hashes: Vec<Hash> = hashes.into_iter().collect();
        let digest = digest_of(&hashes);
        Self { hashes, digest }
    }

    /// Build a view from token bytes: each token is SHA-1-hashed into a leaf.
    pub fn from_tokens(tokens: impl IntoIterator<Item = Vec<u8>>) -> Self {
        Self::from_hashes(tokens.into_iter().map(|t| hash_token(&t)))
    }

    /// The update rule: rebuild from the new leaf vector; return a new view
    /// only if the digest changed, otherwise `None` (callers keep the old
    /// instance — no churn).
    pub fn refresh(&self, hashes: &[Hash]) -> Option<Self> {
        let digest = digest_of(hashes);
        if digest == self.digest {
            return None;
        }
        Some(Self {
            hashes: hashes.to_vec(),
            digest,
        })
    }

    /// The leaves, in materialization order.
    pub fn hashes(&self) -> &[Hash] {
        &self.hashes
    }

    /// The view digest (its content address).
    pub fn digest(&self) -> &ViewDigest {
        &self.digest
    }

    /// The view key: `v:<40-hex sha1>`.
    pub fn key(&self) -> String {
        format!("v:{}", hex::encode(self.digest))
    }

    pub fn len(&self) -> usize {
        self.hashes.len()
    }

    pub fn is_empty(&self) -> bool {
        self.hashes.is_empty()
    }

    /// Linear membership (v1 is a small vector; a sorted-set form brings
    /// binary search in the next revision).
    pub fn contains(&self, hash: &Hash) -> bool {
        self.hashes.contains(hash)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn h(bytes: &[u8]) -> Hash {
        hash_token(bytes)
    }

    #[test]
    fn build_is_deterministic_and_content_addressed() {
        let a = LutView::from_tokens([b"tid0".to_vec(), b"tid671".to_vec()]);
        let b = LutView::from_tokens([b"tid0".to_vec(), b"tid671".to_vec()]);
        assert_eq!(a, b);
        assert_eq!(a.digest(), b.digest());
        assert_eq!(a.key(), b.key());
        assert!(a.key().starts_with("v:"));
        assert_eq!(a.key().len(), 42, "v: + 40 hex");
    }

    #[test]
    fn digest_depends_on_content_and_order() {
        let ab = LutView::from_tokens([b"a".to_vec(), b"b".to_vec()]);
        let ba = LutView::from_tokens([b"b".to_vec(), b"a".to_vec()]);
        let ac = LutView::from_tokens([b"a".to_vec(), b"c".to_vec()]);
        assert_ne!(ab.digest(), ba.digest(), "order is part of the v1 identity");
        assert_ne!(ab.digest(), ac.digest(), "content is part of the identity");
    }

    #[test]
    fn refresh_replaces_only_when_the_digest_changes() {
        let view = LutView::from_hashes([h(b"a"), h(b"b")]);

        // Same leaves → no change.
        assert_eq!(view.refresh(&[h(b"a"), h(b"b")]), None);
        // New content → replaced.
        let next = view
            .refresh(&[h(b"a"), h(b"b"), h(b"c")])
            .expect("changed");
        assert_eq!(next.len(), 3);
        // Reordered → replaced (vector semantics).
        assert!(view.refresh(&[h(b"b"), h(b"a")]).is_some());
    }

    #[test]
    fn membership_and_empty_work() {
        let view = LutView::from_hashes([h(b"x"), h(b"y")]);
        assert!(view.contains(&h(b"x")));
        assert!(!view.contains(&h(b"z")));
        assert_eq!(LutView::from_hashes([]).len(), 0);
        assert!(LutView::from_hashes([]).is_empty());
    }
}
