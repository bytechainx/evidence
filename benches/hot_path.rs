#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::unreachable
)]
//! evidence 热路径：MemoryEvidenceStore 追加。
use std::hint::black_box;
use std::time::Instant;

use evidence::{sha256_hex, EvidenceRecord, EvidenceStore, MemoryEvidenceStore};

fn iters() -> u32 {
    if std::env::args().any(|a| a == "--quick") {
        1_000
    } else {
        50_000
    }
}

fn main() {
    let n = iters();
    let store = MemoryEvidenceStore::new();
    let record = EvidenceRecord::new(
        "bench_event",
        "0.1.0",
        "snap",
        vec!["batch".into()],
        sha256_hex(b"payload"),
        "accepted",
    )
    .expect("record");
    // 预热
    for _ in 0..n.min(10) {
        let _ = store.append(&record);
    }
    let start = Instant::now();
    for _i in 0..n {
        let receipt = store.append(&record).expect("append");
        let _ = black_box(receipt.seq);
    }
    let elapsed = start.elapsed();
    println!(
        "bench_evidence_append: iters={n} total={elapsed:?} per_iter={:?}",
        elapsed / n
    );
}
