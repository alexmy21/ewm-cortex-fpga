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

// ── v2: the relational view (LUT_VIEW.md §7) ─────────────────────────────

/// A relational LUT-view: `V_j(H_i) = M(H_i, L_j)` — the materialization of
/// one HLLSet through one LUT, with provenance.
///
/// - `h` — content key of the HLLSet (`h:<sha1>`);
/// - `l` — the LUT key (e.g. `"main"`, `"uni"`, `"seed0"`);
/// - `tokens` — the materialized token bytes, canonical (sorted, deduplicated);
/// - `digest` — the view key `v:<sha1>` over the canonical tokens.
///
/// The cache identity is the **pair** `(h, l)`, not the digest: `M` is
/// deterministic, so the pair is the key and the digest is a recomputable
/// checksum.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct ViewRecord {
    pub h: String,
    pub l: String,
    pub tokens: Vec<Vec<u8>>,
    pub digest: String,
}

impl ViewRecord {
    /// Build a view record from provenance + materialized token bytes.
    ///
    /// The tokens are canonicalized (sorted, deduplicated) so the digest
    /// identifies the *set* regardless of materialization order — the
    /// lattice-aligned (reversible) semantics of the relational model.
    pub fn new(h: impl Into<String>, l: impl Into<String>, tokens: Vec<Vec<u8>>) -> Self {
        let tokens = canonical_tokens(tokens);
        let digest = view_digest(&tokens);
        Self {
            h: h.into(),
            l: l.into(),
            tokens,
            digest,
        }
    }

    /// The cache identity: the `(h, l)` pair.
    pub fn cache_key(&self) -> (String, String) {
        (self.h.clone(), self.l.clone())
    }

    /// The view key: `v:<sha1>`.
    pub fn key(&self) -> &str {
        &self.digest
    }
}

/// Sort + deduplicate token bytes (the canonical token-set form).
pub fn canonical_tokens(mut tokens: Vec<Vec<u8>>) -> Vec<Vec<u8>> {
    tokens.sort();
    tokens.dedup();
    tokens
}

/// `v:<sha1>` over canonical token bytes (sorted, deduplicated, NUL-joined) —
/// the vendored `view_key_from_tokens` convention, reimplemented here.
pub fn view_digest(tokens: &[Vec<u8>]) -> String {
    let mut sorted = tokens.to_vec();
    sorted.sort();
    sorted.dedup();
    let mut canonical = Vec::new();
    for (i, token) in sorted.iter().enumerate() {
        if i > 0 {
            canonical.push(0u8);
        }
        canonical.extend_from_slice(token);
    }
    format!("v:{}", hex::encode(Sha1::digest(&canonical)))
}

#[cfg(test)]
mod v2_tests {
    use super::*;

    #[test]
    fn view_record_carries_provenance_and_is_canonical() {
        let a = ViewRecord::new("h:aaaa", "main", vec![b"tid2".to_vec(), b"tid0".to_vec()]);
        let b = ViewRecord::new("h:aaaa", "main", vec![b"tid0".to_vec(), b"tid2".to_vec()]);
        // Token order does not matter: the record is a set.
        assert_eq!(a.tokens, b.tokens);
        assert_eq!(a.digest, b.digest);

        // Provenance is preserved and part of the cache identity.
        assert_eq!(a.cache_key(), ("h:aaaa".to_string(), "main".to_string()));
        let other_lut = ViewRecord::new("h:aaaa", "extra", vec![b"tid0".to_vec(), b"tid2".to_vec()]);
        assert_eq!(a.digest, other_lut.digest, "same tokens, same output checksum");
        assert_ne!(a.cache_key(), other_lut.cache_key(), "different LUT, different identity");
    }

    #[test]
    fn view_digest_matches_the_vendored_convention() {
        // The vendored content-addr convention: sort, dedup, NUL-join, sha1.
        let tokens = vec![b"tid5".to_vec(), b"tid2".to_vec(), b"tid5".to_vec()];
        let key = view_digest(&tokens);
        assert!(key.starts_with("v:"));
        assert_eq!(key.len(), 42);
        // Manual check of the canonical form.
        let mut canonical = b"tid2".to_vec();
        canonical.push(0u8);
        canonical.extend_from_slice(b"tid5");
        assert_eq!(key, format!("v:{}", hex::encode(Sha1::digest(&canonical))));
    }
}
