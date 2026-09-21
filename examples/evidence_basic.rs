#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::unreachable
)]
//! 最小生产消费者路径：本地 durable 追加 + ReceiptBinding。
//!
//! ```bash
//! EVIDENCE_LIVE_PROFILE=production EVIDENCE_SOURCE_COMMIT=$(git rev-parse HEAD) \
//!   cargo run --example evidence_basic
//! ```

use evidence::{sha256_hex, EvidenceRecord, EvidenceStore, FileEvidenceStore, ReceiptBinding};

fn main() {
    let profile = std::env::var("EVIDENCE_LIVE_PROFILE").unwrap_or_else(|_| "development".into());
    let source_commit = std::env::var("EVIDENCE_SOURCE_COMMIT")
        .unwrap_or_else(|_| "0000000000000000000000000000000000000001".into());

    let path = std::env::temp_dir().join(format!("evidence-live-{}.log", std::process::id()));
    let store = FileEvidenceStore::open(&path).expect("open file store");

    let artifact_digest = sha256_hex(format!("evidence-consumer:{profile}").as_bytes());
    let record = EvidenceRecord::new(
        "evidence_consumer_smoke",
        concat!("evidence-", env!("CARGO_PKG_VERSION")),
        "live-snapshot",
        vec!["fixture-batch-001".into()],
        sha256_hex(b"evidence-consumer:v1|outcome=accepted"),
        "accepted",
    )
    .expect("valid record");

    let binding =
        ReceiptBinding::new(&source_commit, &profile, artifact_digest).expect("valid binding");
    let receipt = store
        .append_with_binding(&record, &binding)
        .expect("append with binding");

    assert_eq!(receipt.seq, 1);
    assert!(receipt.binding.is_some());

    println!(
        "evidence-consumer: ok seq={} durability=local_durable profile={profile}",
        receipt.seq
    );
}
