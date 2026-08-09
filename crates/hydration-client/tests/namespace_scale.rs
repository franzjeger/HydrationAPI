//! What a folder move costs on a real drive.
//!
//! The namespace exists because one remote change can mean a hundred thousand
//! local ones, so the interesting question is not whether it is correct — the
//! unit tests answer that — but whether the expansion is affordable at the size
//! a real OneDrive actually is. A tree of five files proves nothing here.
//!
//! Measured on this machine (btrfs, kernel 7.1.6, release build), 100,000 files
//! in a three-deep tree:
//!
//! ```text
//!   built 100000 files                          60 ms
//!   root-level folder move -> 100000 changes    47 ms
//!   full listing           -> 100000 changes    48 ms
//!   root-level folder delete -> 100000 changes  49 ms
//! ```
//!
//! So the expansion itself is not where a real deployment will hurt; applying
//! 100,000 renames to the filesystem afterwards is, and that is work that has to
//! happen either way. What matters here is that the cost stays *linear* — a
//! quadratic walk would be invisible at five files and fatal at a hundred
//! thousand, which is exactly the kind of thing that only shows up in
//! production.

use hydration_client::namespace::{Item, Kind, Namespace};
use std::time::Instant;

/// A tree `depth` levels deep with `per` entries at each level, and files at the
/// bottom. Returns the namespace and the file count.
fn build(fanout: usize, files_per_leaf: usize) -> (Namespace, usize) {
    let mut ns = Namespace::new();
    ns.apply(Item::Root { id: "R".into() });
    ns.apply(Item::Upsert {
        id: "TOP".into(),
        parent: "R".into(),
        name: "Documents".into(),
        kind: Kind::Folder,
    });

    let mut files = 0;
    for a in 0..fanout {
        let fa = format!("d{a}");
        ns.apply(Item::Upsert {
            id: fa.clone(),
            parent: "TOP".into(),
            name: fa.clone(),
            kind: Kind::Folder,
        });
        for b in 0..fanout {
            let fb = format!("d{a}_{b}");
            ns.apply(Item::Upsert {
                id: fb.clone(),
                parent: fa.clone(),
                name: fb.clone(),
                kind: Kind::Folder,
            });
            for c in 0..files_per_leaf {
                ns.apply(Item::Upsert {
                    id: format!("f{a}_{b}_{c}"),
                    parent: fb.clone(),
                    name: format!("f{c}.bin"),
                    kind: Kind::File {
                        size: 4096,
                        ctag: Some("v1".into()),
                    },
                });
                files += 1;
            }
        }
    }
    (ns, files)
}

fn move_top(ns: &mut Namespace, to: &str) -> usize {
    ns.apply(Item::Upsert {
        id: "TOP".into(),
        parent: "R".into(),
        name: to.into(),
        kind: Kind::Folder,
    })
    .len()
}

/// Out-of-order arrivals cost time proportional to the input, not its square.
///
/// This is the measurement the first version of this file could not take: its
/// tree builder fed strictly parent-first input, so the held-item path was empty
/// in every number it produced — while the module's own documentation says a
/// delta page is *not* guaranteed to be parent-first. The documented-expected
/// input was the untested one, and it was quadratic: 2k items took 22 ms, 16k
/// took 1.56 s.
#[test]
fn a_reversed_page_costs_time_proportional_to_its_length() {
    fn reversed(n: usize) -> std::time::Duration {
        let mut ns = Namespace::new();
        // Every file first, each waiting on a folder that has not arrived, then
        // the folders, then the root — the worst order a page can have.
        let t = Instant::now();
        for i in 0..n {
            ns.apply(Item::Upsert {
                id: format!("f{i}"),
                parent: format!("d{}", i % 50),
                name: format!("f{i}.bin"),
                kind: Kind::File {
                    size: 1,
                    ctag: None,
                },
            });
        }
        for d in 0..50 {
            ns.apply(Item::Upsert {
                id: format!("d{d}"),
                parent: "R".into(),
                name: format!("d{d}"),
                kind: Kind::Folder,
            });
        }
        ns.apply(Item::Root { id: "R".into() });
        assert_eq!(ns.pending(), 0, "the reversed page never resolved");
        t.elapsed()
    }

    let small = reversed(2_000).as_secs_f64().max(1e-6);
    let large = reversed(16_000).as_secs_f64();
    let ratio = large / small;
    assert!(
        ratio < 8.0 * 4.0,
        "8x the items took {ratio:.1}x the time — that is quadratic, and a page          this shape is what the module documents as normal"
    );
}

/// A set of items held for a parent that never arrives must not tax unrelated
/// traffic.
///
/// The earlier implementation rescanned every held item on every call, so a
/// permanently stuck set made ordinary in-order work quadratic for the life of
/// the process: two thousand upserts took 0.9 ms with nothing stuck and 568 ms
/// with twenty thousand stuck.
#[test]
fn items_stuck_forever_do_not_slow_down_everything_else() {
    fn ordinary_work_with_stuck(stuck: usize) -> std::time::Duration {
        let mut ns = Namespace::new();
        ns.apply(Item::Root { id: "R".into() });
        ns.apply(Item::Upsert {
            id: "D".into(),
            parent: "R".into(),
            name: "Docs".into(),
            kind: Kind::Folder,
        });
        for i in 0..stuck {
            ns.apply(Item::Upsert {
                id: format!("s{i}"),
                parent: "NEVER".into(),
                name: format!("s{i}.bin"),
                kind: Kind::File {
                    size: 1,
                    ctag: None,
                },
            });
        }
        let t = Instant::now();
        for i in 0..2_000 {
            ns.apply(Item::Upsert {
                id: format!("f{i}"),
                parent: "D".into(),
                name: format!("f{i}.bin"),
                kind: Kind::File {
                    size: 1,
                    ctag: None,
                },
            });
        }
        t.elapsed()
    }

    let clean = ordinary_work_with_stuck(0).as_secs_f64().max(1e-6);
    let taxed = ordinary_work_with_stuck(20_000).as_secs_f64();
    let ratio = taxed / clean;
    assert!(
        ratio < 5.0,
        "twenty thousand permanently stuck items made unrelated work {ratio:.0}x          slower; they should cost nothing"
    );
}

/// The expansion is linear in the subtree, not quadratic.
///
/// Quadratic here would be invisible in the unit tests and fatal in production:
/// a hundredfold more files would cost ten thousand times as much, and the first
/// anyone would hear of it is a sync daemon that stopped responding after
/// someone dragged a folder.
#[test]
fn a_folder_move_costs_time_proportional_to_what_it_moves() {
    let (mut small, small_files) = build(6, 20);
    let (mut large, large_files) = build(12, 40);
    assert!(large_files > small_files * 7, "the sizes are too close to compare");

    // Warm, then measure. Both trees are already built, so this times the
    // expansion alone.
    assert_eq!(move_top(&mut small, "warm"), small_files);
    assert_eq!(move_top(&mut large, "warm"), large_files);

    let t = Instant::now();
    assert_eq!(move_top(&mut small, "A"), small_files);
    let small_time = t.elapsed().as_secs_f64().max(1e-6);

    let t = Instant::now();
    assert_eq!(move_top(&mut large, "A"), large_files);
    let large_time = t.elapsed().as_secs_f64();

    let ratio = large_time / small_time;
    let files_ratio = large_files as f64 / small_files as f64;
    // Tight enough to catch a regression. The previous bound allowed six times
    // the growth, which would have passed a six-fold slowdown without a word.
    assert!(
        ratio < files_ratio * 2.5,
        "a {files_ratio:.0}x larger subtree took {ratio:.1}x longer — that is not \
         linear, and at a hundred thousand files it will not finish"
    );
}

/// Nothing beneath an unchanged folder is re-reported.
///
/// The expensive direction is not a move: it is a delta feed that replays
/// folders every pass. If an unchanged folder expanded its subtree, a hundred
/// thousand files would be re-placed every few seconds — and for hydrated files
/// re-placing means discarding the local copy.
#[test]
fn an_unchanged_folder_costs_nothing_however_large_its_subtree() {
    let (mut ns, files) = build(10, 30);
    assert!(files > 2000);
    move_top(&mut ns, "Archive");
    assert_eq!(
        move_top(&mut ns, "Archive"),
        0,
        "a folder reported again with nothing changed re-reported its whole subtree"
    );
}

/// The full-drive numbers in the module docs. Slow enough to keep out of the
/// ordinary run, precise enough to be worth having.
#[test]
#[ignore = "measures 100k files; run with --ignored --nocapture"]
fn hundred_thousand_files() {
    let t = Instant::now();
    let (mut ns, files) = build(40, 62);
    eprintln!("built {files} files in {:?}", t.elapsed());

    let t = Instant::now();
    let moved = move_top(&mut ns, "Archive");
    eprintln!("root-level folder move -> {moved} changes in {:?}", t.elapsed());

    let t = Instant::now();
    let all = ns.listing().len();
    eprintln!("full listing -> {all} changes in {:?}", t.elapsed());

    let t = Instant::now();
    let gone = ns.apply(Item::Delete { id: "TOP".into() }).len();
    eprintln!("root-level folder delete -> {gone} changes in {:?}", t.elapsed());

    assert_eq!(moved, files);
    assert_eq!(gone, files);
}
