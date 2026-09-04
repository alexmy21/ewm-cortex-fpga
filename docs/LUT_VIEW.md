# LUT-view — design discussion and v1 contract

> Status: **recorded design discussion** (2026-09-04). The reasoning matters as
> much as the outcome; do not re-derive it from scratch.

## 1. Origin

While reviewing where `ewm-cortex-fpga` should go after M4-fpga step 1/2, we
discussed the **LUT-view**: a structure derived from the active context that
lets us keep the *working vocabulary* in memory instead of touching the whole
LUT.

The five motivations, in the proposer's own words:

1. The LUT would grow (append-only, monotone TF).
2. The tokens (hashes) in the LUT are almost never all used at the same time.
3. Smaller memory → faster access.
4. Materialization already works well and brings all working/active tokens.
5. We can keep them in memory (cache).

The Merkle tree was mentioned as **an instinct, not a conclusion** — and was
explicitly dropped for v1. This document records both why it was dropped and
when it should return.

## 2. What the discussion settled

- **The LUT-view is a first-class, SHA-1-addressable structure that is used
  as a cache today** — not merely a cache, and not yet a Merkle tree.
- **v1 shape:** a *vector* of token hashes (`sha1(token_bytes)`),
  identified by `digest = sha1(leaves concatenated)`, keyed `v:<40-hex>`.
- **Update rule:** recompute on context change; replace the view **iff the
  digest changed** (`refresh` returns `Option`).
- **Ephemeral and transitional:** the view is derived and disposable; dropping
  it loses only a recomputation, never data. The LUT it mirrors stays whole
  and append-only — we make **no changes** to how LUTs are used.
- **The view belongs in the app layer** (`ewm-cortex-fpga`), not in
  `ewm-fpga-bridge`: the bridge emits `tokens_out` (`Slice` output / `Ground`
  prior); the view is the managed, hash-addressable version of that stream.

## 3. The design space (important distinctions, kept for later)

### 3.1 Three legitimate views, three leaf identities

| View | Leaves | Meaning | Purpose |
| --- | --- | --- | --- |
| **Vocabulary view** | `sha1(token)` | the active vocabulary slice | membership, versioning, sync — v1 is this |
| **Coverage view** | `murmur3(token)` (LUT position hash) | active positions the LUT resolves | coverage/confidence reporting |
| **Sequence view** | `sha1(token)` as an ordered vector | materialized token order | order recovery, De Bruijn partner |

Consequence: murmur3 leaves are **not wrong** — they are the coverage view,
not the vocabulary view. v1 ships the vocabulary view; the other two are
future types, not flags.

### 3.2 Set vs vector

- A **set** (sorted, deduplicated) ⇒ `root = f(content) only` ⇒ identity is
  order-independent. This is the future canonical form.
- A **vector** ⇒ order is part of the identity. v1 pins vector semantics
  (materialization order); the canonical-set form is the first upgrade.

### 3.3 The view is a function of the *resolved* stream

`tokens_out = materialize(H(cache))` is strategy-dependent: today's InLUT
returns all candidates for a collided bit; the future composed materializer
(upstream-first, see the bridge review 2026-09-04 §1.4) returns the TF winner.
So:

> The view is defined over the **resolved token stream**, not over raw HLLSet
> bits. On collided bits the v1 view is a superset and will narrow when the
> composed materializer lands.

### 3.4 The 7 LUTs map to view kinds, not seven identical views

| LUT | View kind | Feed to |
| --- | --- | --- |
| main token LUT ("original HLLSets") | vocabulary view | membership, versioning, gate |
| 1-gram LUT | vocabulary view (unigram provenance) | `tokens_out`, prior |
| 2-gram / 3-gram LUTs | transition views (NUL-joined n-gram hashes) | `ContextMatrix` edges |
| seed-0/1/2 catalog LUTs | catalog views (3 views of the same values) | consensus materialization |

Per-LUT views are separate `LutView` instances with a provenance tag — later.

## 4. Why not Merkle now — and when it returns

Reasons it was dropped for v1:

- The v1 view is **ephemeral and transitional**: it lives in one process's
  memory and is rebuilt on context change. No proofs, no persistence, no
  cross-tier sync, no version history are needed.
- A Merkle tree buys O(log n) membership proofs, subtree diffs, and syncable
  snapshots. None of those are the cache scenario.

Triggers that bring the Merkle tree back (as a deliberate feature, not an
instinct):

1. Views must cross process/tier boundaries (e.g. FPGA ↔ host ↔ disk).
2. Subtree-level diff/merge or membership proofs are needed.
3. View roots are pinned in `ewm-git` commit objects (vocabulary version per
   commit — the strongest long-term payoff).
4. Incremental refresh: reuse unchanged subtrees instead of full recompute
   (the Session 4.3 ladder: golden recompute → coalescing → incremental).

When it returns, the v1 flat digest remains a valid root of the flat tree —
no breaking change.

## 5. v1 contract (as implemented in `crates/lut-view`)

```rust
pub type Hash = [u8; 20];        // sha1(token bytes)
pub type ViewDigest = [u8; 20];  // sha1(leaves concatenated, in order)

pub struct LutView { /* hashes: Vec<Hash>, digest: ViewDigest */ }

impl LutView {
    pub fn from_hashes(iter) -> Self;
    pub fn from_tokens(iter_of_bytes) -> Self;
    pub fn refresh(&self, hashes: &[Hash]) -> Option<Self>; // Some only if changed
    pub fn hashes(&self) -> &[Hash];
    pub fn digest(&self) -> &ViewDigest;
    pub fn key(&self) -> String;          // "v:<40-hex>"
    pub fn len / is_empty / contains;
}
```

Wired into `cortex-fpga`: `view_from_tokens(&[TokenId])` builds the view from
a pass's materialized ids; the golden test asserts a stable corpus produces
zero view replacements and a new token produces exactly one.

## 6. Points to never forget

1. **LUTs stay whole and append-only.** The view never mutates the LUT.
2. **The view is the active vocabulary slice in hash form** — a memory cache,
   not a new persistent store.
3. **Replace iff digest changed** — content-addressing gives idempotence for
   free; no churn when the context is stable.
4. **v1 = vector semantics.** Order is part of the identity; the set form is
   an upgrade, and it changes what the digest means.
5. **The view is disposable.** Evict it freely; one materialization rebuilds
   it.
6. **The bridge stays view-agnostic.** It emits `tokens_out`; LUT-view is an
   app-layer structure.
7. **Merkle is a future feature with explicit triggers** (§4), not a default.

## 7. Related documents

- Bridge `docs/DECISIONS.md` Session 5.2 — two-structure rule, store-agnostic
  bridge, `ewm-cortex-fpga` boundary.
- Bridge `docs/DECISIONS.md` Session 6.1 — dual-encoding `SliceModule` +
  `ewm-cortex-fpga` creation.
- Bridge `docs/REVIEW_2026-09-04.md` §1.4 — the composed materializer gap
  (the view's resolved-stream semantics depend on it).
- This repo: `crates/lut-view/src/lib.rs` — v1 implementation + upgrade path.
