# Groundwork: the Graph `Discover` layer

The attack suite for paging, the cursor lifecycle, persistence ordering and
throttling — written before the implementation, then falsified.

`crates/hydration-graph/tests/discover.rs`: 54 tests, all failing against an
`unimplemented!()` skeleton. That is the acceptance criterion; a test that
survives an empty implementation is a test that cannot fail.

## The two failures this layer exists to prevent

Both come from the fourth review of this project and neither is hypothetical.

**The cursor has two sources of truth that are never reconciled.** The framework
does not persist it — `hydration-sync.rs` holds it in a local and hands
`Cursor::default()` after every restart — while a Graph provider persists its own
delta token and tree. Obeying the empty cursor means a full enumeration on every
restart; ignoring it discards the only signal the framework has.

**A deferred refusal could be consumed by silence.** On an incomplete pass the
driver re-calls with the same cursor. A provider that reads that as "resume"
returns an empty page, and the empty-batch arm advanced the cursor
unconditionally — so work deliberately held back was skipped and the service
never mentioned it again. Fixed in `hydration-sync.rs` in the same commit as this
document; a provider must not depend on that fix.

## The ordering rule, which is absolute

> Write the tree first, then the token. On any doubt discard the token, keep the
> tree.

A tree newer than its token is harmless — replayed items are no-ops. A token
newer than its tree is unrecoverable: every move in between is lost, and a delta
feed never re-reports an unchanged item.

The falsification below is kept verbatim, including everything it says about the
suite's own weaknesses. Three tests cannot discriminate what they claim, and the
stall path stops at the moment it is declared — what happens on the fourth repeat
is undefined, and both live behaviours pass everything written.

---

# API sketch and merge notes

Verified: compiles clean, 54 tests, 0 pass against `unimplemented!()`, all 60 existing `mapping.rs` tests unaffected by the API addition. Only `tests/discover.rs` was written to your project.

---

# 1. The additional public API these tests require

Signatures only. Two variants are added to the existing `Escalation` (non-breaking — verified against `mapping.rs`).

```rust
// ── the transport seam ─────────────────────────────────────────────────────
pub struct RawPage {
    pub status: u16,
    pub retry_after: Option<std::time::Duration>,  // the header, parsed; DeltaPage::parse
    pub body: Vec<u8>,                             // hardcodes Throttled{retry_after_secs:None}
}

pub trait PageSource: Send {
    fn first(&mut self, scope: &DriveScope) -> io::Result<RawPage>;
    fn next(&mut self, link: &NextLink) -> io::Result<RawPage>;
    fn resume(&mut self, link: &DeltaLink) -> io::Result<RawPage>;
    fn latest(&mut self, scope: &DriveScope) -> io::Result<RawPage>;
}

pub trait Sleeper: Send { fn sleep(&mut self, how_long: std::time::Duration); }

/// Pure, no `http` feature gate: the origin check is transport *policy* and must
/// be testable with no socket and no credentials.
pub fn delta_url(scope: &DriveScope) -> String;
pub const REQUIRED_SELECT: &[&str];

// ── persisted state ────────────────────────────────────────────────────────
pub struct TreeBlob(/* private */);        // Clone + Debug + PartialEq
impl TreeBlob {
    pub fn encode(drive: &DriveId, tags: TagSource, items: &[Item]) -> TreeBlob;
    pub fn from_bytes(bytes: Vec<u8>) -> TreeBlob;   // priming a corrupt blob
    pub fn as_bytes(&self) -> &[u8];                 // byte-identity assertions
    pub fn drive(&self) -> io::Result<DriveId>;      // state names its drive
    pub fn tag_source(&self) -> io::Result<TagSource>;
    pub fn items(&self) -> io::Result<Vec<Item>>;    // fallible: bytes may be junk
    pub fn mounts(&self) -> io::Result<Vec<MountPoint>>;
    pub fn with_mounts(self, mounts: &[MountPoint]) -> TreeBlob;
}

pub struct TokenBlob(/* private */);       // Clone + Debug + PartialEq + Default
impl TokenBlob {
    pub fn new() -> Self;
    pub fn one(drive: &DriveId, link: &str) -> Self;
    pub fn set(&mut self, drive: &DriveId, link: &str);
    pub fn get(&self, drive: &DriveId) -> Option<&str>;   // one token PER DRIVE
    pub fn drives(&self) -> Vec<DriveId>;
    pub fn is_empty(&self) -> bool;
    pub fn as_bytes(&self) -> Vec<u8>;
}

pub struct PersistedState { /* private */ }
impl PersistedState {
    /// A tree and a token that agree, as a completed round would have written
    /// them. Keeps the binding mechanism opaque to the tests.
    pub fn consistent(drive: &DriveId, tags: TagSource, items: &[Item], token: &TokenBlob) -> Self;
    pub fn tree_only(drive: &DriveId, tags: TagSource, items: &[Item]) -> Self;
    pub fn raw(tree: Option<TreeBlob>, token: Option<TokenBlob>) -> Self;  // deliberately unbound
    pub fn tree(&self) -> Option<&TreeBlob>;
    pub fn token(&self) -> Option<&TokenBlob>;
}

pub trait StateStore: Send {
    fn load(&mut self) -> io::Result<Option<PersistedState>>;
    fn save_tree(&mut self, tree: &TreeBlob) -> io::Result<()>;
    fn save_token(&mut self, token: &TokenBlob) -> io::Result<()>;
}

// ── the driver ─────────────────────────────────────────────────────────────
pub const MAX_PAGES_PER_ROUND: usize = 1024;   // ~204k items at Graph's $top=200
pub const STALL_LIMIT: u32 = 3;

pub struct GraphDiscover<P: PageSource, S: StateStore, K: Sleeper> { /* … */ }
impl<P, S, K> GraphDiscover<P, S, K> {
    /// No `TagSource` argument: the source is probed on the first enumeration
    /// and persisted in the tree, never re-probed per page.
    pub fn new(scope: DriveScope, pages: P, store: S, sleeper: K) -> Self;
    /// `Escalation` has no channel through `io::Result<(Vec<Change>, Cursor)>`.
    pub fn last_escalation(&self) -> Option<Escalation>;
}
impl<P, S, K> Discover for GraphDiscover<P, S, K> { /* fn changes */ }

pub fn guard_blast_radius(removals: usize, known: usize) -> Result<(), Escalation>;
pub fn deletions_since(before: &[Item], after: &Namespace) -> Result<Vec<Change>, Escalation>;

// ── added to the existing enum ─────────────────────────────────────────────
pub enum Escalation {
    /* … existing four … */
    StalledRetryable { passes: u32, failed: Vec<String> },
    BlastRadius { removals: usize, known: usize },
}
```

**Three behaviours the tests pin that are not visible in the signatures:**

- **The cursor discriminator.** A *fresh instance* starts from the store whatever cursor it is handed (a restart). The *same instance* handed the same **input** cursor again, after a call that returned `Ok`, is a repeat: re-serve the remembered batch from memory, issue no request, no sleep, return the same cursor, and count it toward `STALL_LIMIT`. Anything else runs the next round. A call that returned `Err` is not remembered, so a retry is a fresh round. This is forced by `hydration-sync.rs:483-496` — on a retryable pass the driver leaves `cursor` untouched, so what it repeats is the value it was *given*, not the one you returned.
- **The batch is always `listing()` + this round's removals** (+ diff removals on an enumeration path). Never `CompletedRound.changes`.
- **Token/tree binding is a monotone generation, not equality.** `a_crash_after_the_tree_write…` requires tree gen ≥ token gen to be *resumable*; `a_token_that_does_not_belong…` requires tree gen < token gen to be *discarded*. PROVIDER.md:198 states exactly this asymmetry ("a tree newer than its token is harmless").

# 2. The test file

`/home/frank/Projects/HydrationAPI/crates/hydration-graph/tests/discover.rs` — 54 tests in 8 damage classes, with `Pages` (scripted by request, last reply repeats, unscripted requests recorded-then-failed, 64-call panic cap), `GeneratedPages` (bounded or endless chains for the budget tests), `RecordingStore` (shared `Arc` disk so a second instance over the same state directory is expressible; `fail_tree` / `fail_token` / `fail_after_n_writes` / `swallow_tree_write`), `RecordingSleeper`, and one shared journal so request/sleep/write **interleaving** is observable.

Every fixture shape was checked against the real mapper: root, file, folder, package, tombstone and `remoteItem` all map with zero refusals; the fan-out round completes at `Team Files/y.txt`; the "parent NOWHERE" fixture yields exactly `Escalation::Incomplete { refusals: 0, pending: 1 }`; the null-element page is `Malformed`; 410/429 map as expected.

# 3. Tests dropped, merged or weakened

The JSON contained **57 entries**, not 76 — the last one is truncated mid-sentence. If entries were lost in transit, tell me which and I will add them.

**Dropped (4)**

| Proposed | Why |
|---|---|
| `a_429_with_retry_after_seconds_sleeps_exactly_that_and_refetches_the_same_link` (last entry) | Setup truncated mid-sentence. It also duplicates `a_429_mid_chain_retries_the_same_link…` and *contradicts* it on the seam: it demands `RawPage.retry_after` be the raw header string, the other a `Duration`. Kept the `Duration` version — nothing in the suite parses a header, so the raw form buys only a parser test that belongs below the seam. |
| `a_stored_token_with_no_tree_is_discarded_rather_than_resumed` | Same property and same assertions as `a_stored_token_with_no_stored_tree_…`. Merged; kept the stricter "zero `Removed`" clause from this one. |
| `a_stored_tree_with_no_token_diffs_the_full_enumeration_for_deletions` | Same property as `a_stored_tree_with_no_stored_token_enumerates_and_still_diffs…`. Merged. |
| `an_empty_cursor_from_the_framework_does_not_discard_the_persisted_token` | Same call sequence as test 1 plus test 36. Its distinctive half — round 1 *writes* the state and a fresh instance resumes it — survives as `positive_control_a_fresh_instance_resumes_the_token_its_predecessor_wrote`. |

**Weakened (3), each because the proposal contradicted another test**

- **`a_delta_link_on_the_first_page…`** asserted `Cursor(Some(<the exact deltaLink>))`, which is flatly incompatible with `two_batches_never_share_a_cursor_value…` (two rounds can carry the same deltaLink and must not carry the same cursor). Uniqueness is the load-bearing half — it is what makes repeat-vs-acknowledgement decidable — so the cursor assertions everywhere are now `is_some()` + *contains* the delta link + differs from the previous. Same weakening applied to `a_long_finite_enumeration…` and `a_resumed_round_still_follows_its_next_links`.
- **`two_scopes_interleaved_in_one_round…` and `a_delta_link_for_one_scope_does_not_end_another…`** cannot force an interleaving through `Discover::changes` — the implementation chooses request order. The script is keyed by request instead, so it answers whatever order the driver asks in; the falsifiable claim (a token per drive, and one scope's deltaLink not ending another's paging) is unchanged. A single-`token`-slot `Round` still fails both.
- **`a_removal_the_framework_could_not_apply_is_re_served…`, `a_repeated_cursor_is_served_from_memory…`, and the two stall tests** were written as `changes(&c1)` after `(b1, c1) = changes(&Cursor::default())` — but that is the same call sequence as the *acknowledgement* positive control, and the two demanded opposite behaviour. `hydration-sync.rs:483-490` never assigns `cursor = next` on a retryable pass, so the repeat carries `Cursor::default()`. The repeat tests now re-call with the input cursor; the acknowledgement control keeps `&c1`. Both properties are now testable at once.

**Not attempted:** anything keyed on `Applied` feedback (`StallDetector { last_failed }`, "non-shrinking failed set"). Nothing hands `Applied` back to the provider, so those assertions are unobservable by construction — which is precisely why the stall tests count cursor repeats instead.

---

# Falsification


## Report 1

# Tests that cannot fail

File: `/home/frank/Projects/HydrationAPI/crates/hydration-graph/tests/discover.rs`

Nothing in the suite is vacuous end-to-end (no test passes `unimplemented!()`), so "cannot fail" below means: **the named assertion is guaranteed by the fixture, the double, or a preceding assertion, and removing the code under test's freedom does not change the result.** Ordered by how much they cost.

---

## A. Whole tests that cannot discriminate what they claim

### 1. `a_crash_between_the_two_writes_costs_a_move_only_when_the_token_is_written_first` (2149)

**The fixture removes the condition.** Round three scripts `first_req(MINE)` (2190-2200) with the *correct post-move* state — `01A` already under `01W`. Enumerate the four candidate implementations against the assertions at 2204-2212:

| impl | round 3 path | verdict |
|---|---|---|
| tree-first + generation binding | resume `DELTA-1`, replay move | pass |
| tree-first, no binding | resume `DELTA-1` | pass |
| **token-first + generation binding** | tree gen < token gen → discard → `first()` → move arrives from the scripted enumeration | **pass** |
| token-first, no binding | resume `DELTA-2`, root only | fail |

Test 26 (`a_token_that_does_not_belong_to_the_stored_tree_is_discarded`) *mandates* the binding. So the only implementation this test catches is one the suite already forbids. The write order — the entire subject of the test — is unmeasured.

**Fix:** the discriminator is the request, not the path. Add before 2204:
```rust
let calls = rig.journal.calls();
assert!(calls.contains(&resume_req("DELTA-1")), "tree-first leaves a resumable pair: {calls:?}");
assert!(!calls.contains(&first_req(MINE)), "token-first forces a re-enumeration the tree-first order avoids");
```

### 2. `a_tree_write_failure_leaves_the_old_pair_intact` (2009)

Two problems, and together they leave nothing.

- **2050** `assert_eq!(rig.store.tree_bytes(), Some(tree_before))` — `RecordingStore::save_tree` (747-763) returns `Err` *before* `d.tree = Some(...)` whenever `fail_tree` is set. The disk tree is unwritable by construction. Asserting it is unchanged asserts the double.
- **2051** `token_bytes() == token_before` is implied by the preceding 2042-2049 assertion that no `SaveToken` was journalled — `save_token` is the only writer of `d.token`.
- **2052-2057** the only remaining claim sits behind `if let Ok((_, c)) = outcome`, and the expected implementation returns `Err`.

What survives is "no token write when the tree write failed" — which `a_tree_write_failure_writes_no_token_at_all` (1912) already asserts more strictly (`store_events() == [Load, SaveTreeFailed]`, exact, including the load count).

**Fix — or delete.** Give it independent value by proving the old pair is *usable*, not merely *present*:
```rust
assert!(outcome.is_err(), "a round whose tree could not be written did not complete");
rig.store.clear_faults();
rig.journal.clear();
let mut three = rig.provider();
three.changes(&Cursor::default()).expect("the surviving pair is resumable");
assert_eq!(rig.journal.calls().first(), Some(&resume_req("DELTA-1")));
```

### 3. `a_re_enumeration_that_did_not_finish_is_never_diffed_for_deletions` (3494)

The headline assertion is at 3533-3539, inside `if let Ok((changes, _)) = &outcome`. `next_req("NEXT-1")` is scripted to `ConnectionReset` (3526-3529), so a correct driver returns `Err` and **the diff claim is never evaluated**. What executes is 3540-3542, which duplicates `a_transport_failure_mid_chain_never_makes_a_next_link_a_cursor` (2771) — and of those three lines, the two `*_bytes()` comparisons are implied by `writes().is_empty()` on the line above.

**Fix:** make the claim reachable. Assert the failure explicitly, then run the retry to completion and check the diff there:
```rust
assert!(outcome.is_err());
assert!(rig.journal.writes().is_empty(), "{:?}", rig.journal.writes());
rig.script(next_req("NEXT-1"), vec![Reply::ok(body_delta(
    &["01C","01D","01E"].map(|id| file_json(MINE, id, &format!("{id}.txt"), ROOT, 10, "c:{G},x")), &lnk("DELTA-2")))]);
let (changes, _) = d.changes(&Cursor::default()).expect("the completed retry");
assert!(removed(&changes).is_empty(), "the truncated first attempt must leave no ghost removals");
```

### 4. `state_belonging_to_another_drive_is_discarded_whole_and_reports_no_deletions` (3298)

**Loop over a collection nothing forces to be non-empty.** 3341-3343:
```rust
for id in upserted(&changes) { assert!(id.starts_with(NEW), ...); }
```
There is no assertion that *anything* was upserted. `Ok((vec![], cursor))` plus a correctly-scoped tree write passes every line: `removed` is empty ✓, the loop is vacuous ✓, `calls()` contains `first_req(NEW)` ✓, `tree_ids(...).all(starts_with(NEW))` ✓.

**Fix:** anchor it. `assert_eq!(upserted(&changes), set(&[cloud(NEW, "01A2")]));` — which subsumes the loop, so delete 3341-3343.

### 5. `a_package_is_still_opaque_after_a_restart` (3707)

Same shape, worse. 3739-3742 loops over `paths(&changes)`. Round two's page carries only the root and `01SEC` — an item *inside* the opaque package. For the correct implementation `01SEC` is not placed, so `paths(&changes)` is **empty and the loop body never runs**. The "walked into a package" check is dead against every implementation except the one it is trying to catch, and there is nothing forcing the batch to be non-empty.

**Fix:** put a real file outside the package in round two's page so the loop is guaranteed to iterate, and pin the batch:
```rust
// round two page: root, 01SEC under 01NB, and folder 01D "Docs" + 01Z "z.txt" under it
assert_eq!(paths(&changes), set(&["Docs/z.txt".to_string()]),
    "the notebook's internals are not files; the ordinary file still is");
```

### 6. `a_round_the_blast_guard_refused_does_not_overwrite_the_tree_it_refused_to_trust` (3554)

**3590** `assert!(d.last_escalation().is_some(), "the refusal must be nameable")` — any escalation satisfies it. An implementation that refuses the round because it mistook a root-only page for `Malformed`, or that reports `Incomplete`, passes a test whose name is about the blast guard. `Escalation::BlastRadius { removals, known }` is required public API and **is never constructed or matched anywhere in the suite** (grep: 0 hits). `guard_blast_radius` is likewise never called.

**3591-3593** `tree_bytes()`/`token_bytes()` are implied by `writes().is_empty()` on 3591.

**Fix:**
```rust
assert_eq!(d.last_escalation(), Some(Escalation::BlastRadius { removals: 500, known: 501 }));
```
and delete 3592-3593. Compare `a_round_that_escalates_writes_no_token_and_returns_no_new_cursor` (2471-2477), which does assert the exact variant — this test should match that standard.

---

## B. Individual assertions that cannot fail

| Test (line) | Assertion | Why it cannot fail | Action |
|---|---|---|---|
| `two_scopes_in_one_round_each_get_their_own_token` (3198) | `assert_ne!(blob.get(MINE), blob.get(THEIRS))` | 3193 and 3194-3197 already pin them to `link_on(MINE,"DM")` and `link_on(THEIRS,"DT")` — distinct string literals. Inequality of two things you just proved equal to two different constants. | Delete |
| `a_crash_after_the_tree_write_…` (2104-2110) | `stored_token() == Some(lnk("DELTA-1"))`, *"the token did not move"* | `fail_token` is set; `save_token` (766-780) returns `Err` before `d.token = ...`. The token is immovable by fixture. | Delete, or replace with the observable form: assert round three issues `resume_req("DELTA-1")` (already at 2122 — so just delete) |
| `a_repeated_cursor_is_served_from_memory_…` (1613-1618) | `for (b,_) in &batches { assert!(!upserted(b).contains(01C)) }` | 1602-1606 already asserts `calls() == [resume_req("D9")]`. `01C` only exists in the body of `resume_req("D10")`, which was never fetched. | Delete |
| `a_long_finite_enumeration_…` (2622-2628) | `for t in &tokens { assert!(!bytes.contains("token=P")) }` | 2620 pins `tokens.len() == 1` and 2621 pins `tokens[0].get(MINE)` to exactly `lnk("D0")`. | Delete |
| `a_resumed_round_still_follows_its_next_links` (1447-1450) | `!upserted(&changes).contains(cloud(MINE,"01BIG0"))` | 1441-1445 asserts `calls() == [resume D1, next P1]`; `first()` was never issued, so the drive-sized page was never parsed. | Delete |
| `a_delta_link_on_the_first_page_…` (2747-2750) | `removed(&changes).is_empty()` | 2746 asserts `calls().len() == 1`; the massacre body is behind four requests none of which were made. | Delete |
| `a_stored_token_with_no_stored_tree_…` (1089-1092) | `!calls().contains(&resume_req("D9"))` | 1088 already asserts `calls() == vec![first_req(MINE)]`. | Delete |
| `a_stored_token_with_no_stored_tree_…` (1097-1100) | `removed(&changes).is_empty()` | `preload_raw(None, …)` — there is no tree, so there is no diff input. No implementation can synthesise a removal from nothing. | Delete; the real risk (a resumed round starves `listing()` forever) is only observable one round later. Add that round: script `resume_req("D10")` empty and assert round two still reports `01A` **and** `01B`. |
| `a_tree_that_fails_to_deserialise_…` (3651) | `removed(&changes).is_empty()` | Same — the blob does not parse, so there is nothing to diff. `unwrap_or_default()` (the wrong impl the docstring names) also yields zero removals. | Delete. The teeth are already at 3649-3650. |
| `a_round_lost_to_a_bad_page_…` (2921) | `removed(&changes).is_empty()` | The store begins empty and the failed attempt writes nothing; even if it had written its 201 items, the retry enumerates the same 201. Zero removals is arithmetic. | Delete; 2919-2920 (`upsert_count == 201`, `upserted().len() == 201`) carry the actual claim |
| `a_restart_never_asks_for_token_latest` (1303-1306) | `!calls().contains(&latest_req(MINE))` | 1302 asserts `calls() == vec![resume_req("D9")]`. | Delete |
| `a_next_link_identical_to_the_one_just_followed_…` (2528-2531), `an_endless_chain_…` (2596) | `sleeps().is_empty()` | No fixture in either test returns 429 and `RawPage.retry_after` is `None` throughout; the only way to reach `Sleeper` is a driver that invents a backoff on a non-throttle error. Thin but non-zero teeth. | Keep, low value — or fold into a single `assert!(journal.sleeps().is_empty())` helper so it reads as a class invariant rather than a claim |

---

## C. Two weaknesses that aren't strictly tautologies but let the wrong thing through

**`a_token_write_failure_does_not_advance_the_in_memory_token` (1980)** — `let _ = d.changes(&Cursor::default());` discards the outcome. If the implementation returns `Ok` after `SaveTokenFailed`, the *next* call on the same instance is a **repeat** under the file's own discriminator (line 40-44), served from memory with no request, so `calls().first()` is `None` and the test fails at 1991-1995 with the message *"the token only advances once it is on disk"* — which is not the defect. Make it honest: `assert!(d.changes(&Cursor::default()).is_err(), "a round whose token could not be written did not complete");`

**`an_empty_cursor_with_persisted_state_resumes_the_stored_token` (976)** — the batch is bound to `_` (994). `resume(D9)` then `Ok((vec![], Cursor(Some("x"))))` passes. Cheap fix: `assert_eq!(upserted(&changes), set(&[cloud(MINE,"01A")]))` — the fixture already has one file.

**`a_second_provider_instance_over_the_same_store_does_not_write_back_a_stale_tree` (2392)** — proves *lazy load on first use*, not *re-read per round*. An implementation that loads once on the first `changes` and caches forever passes, then writes a stale tree on instance `one`'s **second** round. Add it: after instance `two`'s round, run `one.changes(&Cursor::default())` and assert it issues `resume_req("DELTA-2")`, not `resume_req("DELTA-1")`.

---

## D. Required API with no test at all

Grep over the file returns zero hits for: `guard_blast_radius`, `deletions_since` (one hit, in a doc comment at 1219), `Escalation::BlastRadius`, `REQUIRED_SELECT`, `STALL_LIMIT`, `MountPoint`, `TreeBlob::encode` / `mounts()` / `with_mounts()` / `drive()` / `tag_source()`, `TokenBlob::new()` / `set()` / `is_empty()`.

Two of these are load-bearing:

- **`REQUIRED_SELECT`.** `a_legitimate_next_link_reaches_the_source_byte_for_byte`'s own docstring (3076-3077) says an over-tight repair "drops `$select` (which turns deletes into no-ops)" — and no assertion anywhere checks that `delta_url` emits it. The only `delta_url` assertion is 3023, `starts_with("https://graph.microsoft.com/")`, satisfied by `fn delta_url(_: &DriveScope) -> String { "https://graph.microsoft.com/".into() }`. That is a smuggled unit test that tests nothing. Replace with:
  ```rust
  let url = delta_url(&primary(MINE));
  assert!(url.starts_with("https://graph.microsoft.com/v1.0/drives/b!mine/root/delta"));
  for field in REQUIRED_SELECT { assert!(url.contains(field), "$select is missing {field}"); }
  ```
  (Better still, in its own test — it has nothing to do with foreign-host refusal.)

- **`guard_blast_radius` / `deletions_since`.** Both are public, pure, and total; both are the exact code paths that Class G refuses to trust. They should have direct table-driven tests (`removals` at the boundary `max(64, known/10)`, both sides), which would also make `Escalation::BlastRadius`'s fields load-bearing rather than decorative.

`STALL_LIMIT` and `MountPoint` are harmless dead surface — the threshold is pinned behaviourally by tests 17/18 (stall at 3, none at 2) regardless of the constant's value. Either delete the constant from the required API or assert `passes == STALL_LIMIT` at 1752 instead of the literal `3`.

## Report 2

## Verdict on the two named items

**#8 (retryable refusal consumed by an empty batch) — mechanism pinned, lifecycle not.**
The core is genuinely closed: `a_removal_the_framework_could_not_apply_is_re_served_not_forgotten`, `a_repeated_cursor_is_served_from_memory_with_no_request_and_no_backoff`, `two_batches_never_share_a_cursor_value_even_when_graph_repeats_its_delta_link`, `a_quiet_steady_state_round_reports_the_tree_rather_than_an_empty_batch`, plus both positive controls. What is missing is everything after the third repeat.

**#9 (cursor/state unreconciled) — one half pinned, the other never exercised.**
The header fixes a three-clause discriminator; Class A pins clause 1 **only for `Cursor::default()`**. Every `Cursor` in all 3804 lines is either `Cursor::default()` or a value the provider itself just returned (`grep -n "Cursor("` finds no hand-built cursor outside doc comments). The clause that reads "starts from the store, *whatever cursor it is handed*" has no test for the "whatever", and the cursor-as-input path — the one place a `DeltaLink` re-enters this layer as a bare `String` — gets none of the Class E scrutiny that the identical string gets when it arrives in a page body.

---

## Gaps, each with the test that closes it

### 1. The stall is declared and then the file stops. (#8)
`three_repeats_of_one_cursor_are_reported_as_a_stall` asserts the escalation and ends. Call #4 is untested, and both live behaviours pass everything currently written: keep re-serving forever (drive never advances again), or force `first()` and drop the batch. The second is what §1.13 prescribes and it is *lossy here* — 01X's tombstone was consumed in round one, the provider's tree no longer holds 01X, so a from-scratch enumeration diffs against a tree that already agrees the file is gone and the framework's placeholder for a deleted object is permanent. That is the exact failure the headline test exists to prevent, reached three passes later.

`a_stall_does_not_discard_the_batch_it_was_raised_about` — the `three_repeats` rig, extended to calls 4 and 5. Script `first_req(MINE)` with a complete enumeration lacking 01X so the re-enumeration branch succeeds quietly. Assert the removal for 01X is still in the batch afterwards, which forces the diff to be taken against the *pre-round* tree rather than the post-round one.

### 2. The stall never clears. (#8)
No test acknowledges after a stall. An implementation that latches `last_escalation` or never resets `passes` passes the whole file, and turns the second retryable pass in the process's life into an instant escalation.

`an_acknowledgement_after_a_stall_clears_it_and_the_next_deferral_gets_its_full_budget` — three repeats, then hand back `c1`, then a later round that defers again; assert two repeats of the new cursor are still not a stall.

### 3. A deferred batch is memory-only, and two existing assertions quietly certify that. (#8 ∩ #9)
`a_repeated_cursor_is_served_from_memory…` and `three_repeats…` both assert `token_writes().len() == 1` — round one persists tree **and** token past a tombstone the framework never applied. The only copy of that removal is a `Vec<Change>` in RAM. Crash the daemon mid-stall (the delta thread is spawned bare, `hydration-sync.rs:446`) and the fresh instance loads a tree without 01X and a token at D10: the removal is unreachable forever, because `listing()` cannot express it and Graph will not replay a consumed tombstone. The file has chosen "unacknowledged work is lost on restart" without ever saying so.

`a_removal_a_restart_interrupted_before_it_was_applied_is_still_reported` — round one over the shared `RecordingStore` (the double already clones onto one disk), drop the instance, build a fresh one, script `resume_req("D10")` with an empty page so the wrong branch returns `Ok`. Assert 01X is still `Removed`. Whichever way it is made to pass — withhold the token until acknowledged, or persist the unacknowledged batch — the decision gets made on purpose. Note this test **contradicts** the two `token_writes().len() == 1` assertions; one of the three has to change.

### 4. The cursor is never treated as untrusted input. (#9, and critique 2 #6)
`Cursor(pub Option<String>)`. The shortest implementation of clause 3 is `Some(s) => self.resume(DeltaLink(s))`, which hands an arbitrary caller-supplied string to `PageSource::resume` as a URL. Class E establishes that a link from the cloud must be origin-checked *before* it is fetched; the cursor is the one link that re-enters through a different door and gets no check.

`a_cursor_the_provider_did_not_mint_is_never_fetched` — fresh instance, good state (tree + D9), handed `Cursor(Some("https://evil.example/v1.0/drives/b!mine/root/delta?token=D9"))`. Script the foreign URL to answer with a well-formed deltaLink page so following it succeeds. Assert `calls() == [resume_req("D9")]`. Then the four near-misses from `a_next_link_that_only_resembles_the_endpoint_is_refused` applied to the cursor argument.

### 5. No fresh instance is ever handed a legitimate non-empty cursor. (#9)
Even the benign reconciliation is untested: instance B is handed `c1` minted by instance A while the store holds D9. The store must win. An implementation reading "non-empty cursor ⇒ resume point" replays or skips a window depending on which is older, silently.

`a_fresh_instance_ignores_a_non_empty_cursor_and_starts_from_the_store` — preload tree + D9, hand `Cursor(Some(lnk("D5")))`, script *both* `resume_req("D5")` and `resume_req("D9")` to succeed, assert only D9 is fetched.

### 6. "An `Err` is not remembered" is pinned only for a first-round failure. (#9)
`a_round_interrupted_mid_enumeration_…` covers a failure with nothing yet in memory. The daemon's real sequence: round one succeeds (`c1`), round two is handed `c1` and fails at the transport (`hydration-sync.rs:529` logs and leaves `cursor` untouched), round three is handed `c1` again. A repeat-detector recording the input unconditionally calls that a repeat: re-serves batch one, issues no request, and after three offline passes reports `StalledRetryable` — a laptop on a train diagnosed as a wedged framework, with the network never retried.

`a_transport_failure_does_not_make_the_next_call_a_repeat` — script `resume_req("D10")` as `[Fail(ConnectionReset), ok(...)]`, call twice with `c1`; assert the second call issues the request, returns the new batch, and `last_escalation()` is `None`.

---

## From the hostile-input list, applicable here, no test anywhere

### 7. The incurable, recurring refusal — the token gate has no exit. (critique 1(c) #7; critique 2 #13/#14)
`grep -c quarantin tests/discover.rs` → 0. `src/lib.rs:1118` `Report` has `refusals` ("Withholds the token") and no `quarantined` field, and its own doc for `deferred` names the wedge — "a refusal that recurs every round is cleared by nothing and pins the cursor forever" — while leaving `refusals` sitting in it. `mapping.rs` pins the single-round rule (`a_file_under_a_parent_the_service_never_describes_withholds_the_token`, `a_shape_flip_over_children_escalates_and_withholds_the_token`). Nothing tests round 2..N. Worse, `a_round_that_escalates_writes_no_token_and_returns_no_new_cursor` (line 2479) actively asserts the *first repetition* of the wedge and no exit — the suite currently certifies a permanent outage. Trigger: one Mac-authored `Q1\Q2.xlsx`, or one permanent `PathCollision`. Every five seconds forever: resume D9, fetch, refuse, `Err`, log "could not list the cloud".

`an_item_refused_every_round_is_quarantined_so_the_drive_keeps_syncing` — `resume_req("D9")` returns `[bad item, good item]` ending at D10; `resume_req("D10")` returns a third file. Call N times; assert the token advances past D9 by call ≤3, both good files reach a batch, the refused id appears in a durable quarantine, and it is never emitted as a `Change`. Positive control: `a_refusal_that_clears_itself_is_not_quarantined_on_sight`. Requires the accessor critique 2 #12 asks for — `last_escalation()` exists, `last_report()` does not.

### 8. A 429 without `Retry-After`, and a 429 that never stops. (critique 1(c) #5)
One throttling test in 3804 lines, and `Reply::throttled(n)` always sets `retry_after: Some(n)`. The file's own comment at line 2934 says `DeltaPage::parse` hardcodes it to `None` — so `None` on a 429 is the *common* shape. `retry_after.unwrap_or_default()` sleeps zero and re-issues immediately: a hot loop against a throttling endpoint, which is what earns the app registration a ban for every user of the client. Nothing bounds retries either; a permanent 429 pins `cloud.changes` inside a thread with no timeout, and the double's `cap` fires as a panic rather than the round failing.

`a_429_without_a_retry_after_still_backs_off` (`Reply::status(429, …)`; assert `sleeps()` non-empty and never `Duration::ZERO`) and `a_scope_throttled_without_end_gives_up_the_round_rather_than_the_thread` (assert `Err` within a bounded call/sleep count, no token write, stored bytes unchanged).

### 9. 5xx and 401 have no policy anywhere.
Only 410 and 429 appear in the whole file. A 503/504 is routine from Graph — retried with backoff like a 429, or round lost like a parse failure? Both defensible, neither pinned, so whatever gets written is right by default. And a 401 mid-chain (token expiry between page 3 and page 400) must not be retried blind forever and must not be confused with a 410, which would re-enumerate the whole drive on every access-token expiry.

`a_503_mid_chain_is_retried_with_backoff_and_the_round_still_completes`; `a_401_mid_chain_loses_the_round_and_is_not_a_resync` — script `first_req` to succeed so the wrong branch passes quietly and is caught by the call log.

### 10. Blast radius: what `removals` counts, and the legitimate bulk delete. (critique 1(c) #6)
One folder tombstone over a 900-file folder is a single removal on the wire and 900 `Change::Removed` out of `Namespace`. A guard counting tombstones lets it through; one counting emitted changes refuses it. No test distinguishes, and the difference is "the user's deliberate project-folder delete is applied" vs "the drive wedges". There is also no path by which a genuine bulk deletion is *ever* applied — refuse, withhold, re-fetch, re-refuse: gap 7 again, reached by an ordinary user action.

`a_single_folder_tombstone_expanding_to_many_removals_is_applied` (positive control: 1000 known, one tombstone over 900 → `Ok`, 900 `Removed`, token advances); `exactly_the_blast_radius_limit_is_allowed_and_one_more_is_refused`; `a_bulk_deletion_the_guard_refused_has_a_way_through` — whatever the mechanism, the round after the refusal must reach a state that is not the refused one.

### 11. The tag-source *probe*, as opposed to the pin. (critique 1(c) #8)
`the_pinned_tag_source_is_persisted_and_never_re_probed` covers persistence. The probe ("the first 64 file-shaped items", §1.6) is a driver concern because those 64 span pages, and no test exercises it. Missing: a first page with **zero files** (pins nothing, or pins a default that then refuses every file that arrives); a drive with **no tag of any kind** (must escalate and write no token — pinning `CTag` on a hash-only drive refuses every file on the drive forever, with no cause in any log); and the **>10% divergent tail** rule, which has no test at all.

`a_first_page_with_no_files_does_not_pin_a_tag_source`; `a_drive_with_no_tag_of_any_kind_escalates_and_writes_no_token`; `a_tag_source_missing_on_more_than_a_tenth_of_a_round_withholds_the_token`.

### 12. Mount edges — one happy shape, three unguarded ones. (critique 1(c) #9)
Class F covers per-drive tokens, independent paging, per-drive resume, and a changed account. Not covered, all driver-level:

- **A mounted scope that 403s or 410s mid-round.** Permission revoked on a shared library is routine. `a_re_enumeration_that_did_not_finish_is_never_diffed_for_deletions` is written for the primary only; the far drive failing is a different path to the same mass local deletion. `a_mounted_scope_that_403s_loses_neither_the_primary_token_nor_the_far_subtree` — assert zero `Removed` under `Team Files/`, primary token written, the far drive's entry absent rather than emptied, mount retried next round.
- **A mount cycle or self-mount.** `MAX_PAGES_PER_ROUND` bounds pages within a scope; nothing bounds scopes per round. A far feed carrying a placeholder back to `b!mine` recurses until the process dies — silently, which is Class D's entire premise. `a_mount_pointing_back_at_a_scope_already_in_this_round_is_not_followed`, plus a scope budget mirroring `an_endless_chain_of_fresh_next_links_stops_at_the_page_budget`.
- **A placeholder deleted while its token survives.** The token blob keeps a `b!theirs` entry, so the far drive is enumerated every round into a scope with no anchor and its items land in `waiting` on a parent that no longer exists — which under gap 7 withholds the token permanently. `a_token_for_a_drive_no_placeholder_points_at_is_dropped`.

### 13. A poison element inside a well-formed page. (critique 1(c) #2)
`a_page_that_fails_to_parse_loses_the_round_and_is_not_refetched` uses a wholly bad body. The shape that matters is a good page with one bad element — `{"value":[{good},null,{good}],"@odata.deltaLink":"D10"}` — because `Vec<DriveItem>` fails wholesale. `mapping.rs` makes the choice (`a_non_string_item_id_fails_the_page_rather_than_dropping_the_item`, per-page); the *driver consequence* of that choice is untested: per-page failure plus a withheld token is a permanent wedge on one `null` in an array, against a body that is byte-identical every time it is re-fetched.

`a_single_junk_element_does_not_wedge_the_drive_forever` — assert the round either quarantines the page's junk and advances, or fails in a bounded way, but never re-fetches the same body indefinitely.

---

Files: `/home/frank/Projects/HydrationAPI/crates/hydration-graph/tests/discover.rs`, `/home/frank/Projects/HydrationAPI/crates/hydration-graph/tests/mapping.rs`, `/home/frank/Projects/HydrationAPI/crates/hydration-graph/src/lib.rs`, `/home/frank/Projects/HydrationAPI/docs/GRAPH-GROUNDWORK.md`, `/home/frank/Projects/HydrationAPI/crates/hydration-client/src/bin/hydration-sync.rs`.

The existing doubles already support gaps 3, 4, 5, 6, 8, 9, 10, 13 unchanged. Gaps 1, 2, 7 need a `last_report()`/quarantine accessor on `GraphDiscover`; gap 12 needs the `Pages` double to script per-scope failures (it already keys on drive).
