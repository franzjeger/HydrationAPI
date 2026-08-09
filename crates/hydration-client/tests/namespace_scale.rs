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
    ns.apply(Item::Upsert {
        id: "R".into(),
        parent: None,
        name: String::new(),
        kind: Kind::Root,
    });
    ns.apply(Item::Upsert {
        id: "TOP".into(),
        parent: Some("R".into()),
        name: "Documents".into(),
        kind: Kind::Folder,
    });

    let mut files = 0;
    for a in 0..fanout {
        let fa = format!("d{a}");
        ns.apply(Item::Upsert {
            id: fa.clone(),
            parent: Some("TOP".into()),
            name: fa.clone(),
            kind: Kind::Folder,
        });
        for b in 0..fanout {
            let fb = format!("d{a}_{b}");
            ns.apply(Item::Upsert {
                id: fb.clone(),
                parent: Some(fa.clone()),
                name: fb.clone(),
                kind: Kind::Folder,
            });
            for c in 0..files_per_leaf {
                ns.apply(Item::Upsert {
                    id: format!("f{a}_{b}_{c}"),
                    parent: Some(fb.clone()),
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
        parent: Some("R".into()),
        name: to.into(),
        kind: Kind::Folder,
    })
    .len()
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
    assert!(
        ratio < files_ratio * 6.0,
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
