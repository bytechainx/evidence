#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::unreachable
)]
use evidence::{
    sha256_hex, sign_canonical, verify_canonical, EvidenceReader, EvidenceRecord, EvidenceStore,
    FileEvidenceStore, MemoryEvidenceStore, SignatureRole, TestSigningKey,
};

fn sample_record(snapshot: &str) -> EvidenceRecord {
    EvidenceRecord::new(
        "regime_decision",
        "commit-b2-skeleton",
        snapshot,
        vec!["batch-b2-fixture".into()],
        sha256_hex(format!("decision:{snapshot}").as_bytes()),
        "accepted",
    )
    .expect("fixture record is valid")
}

#[test]
fn memory_store_query_and_sign_roundtrip() {
    let store = MemoryEvidenceStore::new();
    let record = sample_record("snapshot-query-sign");

    let receipt = store.append(&record).expect("append");
    assert_eq!(store.len().expect("len"), 1);
    assert_eq!(store.get(1).expect("get").expect("receipt"), receipt);
    assert_eq!(
        store.find_by_record(&record).expect("find"),
        Some(receipt.clone())
    );
    assert!(store.get(2).expect("missing seq").is_none());

    let payload = record.canonical_bytes();
    let owner = sign_canonical(
        &TestSigningKey,
        SignatureRole::Owner,
        "owner-test",
        &payload,
    )
    .expect("sign owner");
    verify_canonical(&TestSigningKey, &owner, &payload).expect("verify owner");
    assert_eq!(owner.role(), SignatureRole::Owner);
    assert_eq!(owner.signer_id(), "owner-test");

    let reviewer = sign_canonical(
        &TestSigningKey,
        SignatureRole::Reviewer,
        "reviewer-test",
        &payload,
    )
    .expect("sign reviewer");
    verify_canonical(&TestSigningKey, &reviewer, &payload).expect("verify reviewer");
}

#[test]
fn file_store_query_and_sign_roundtrip() {
    let directory = tempfile::tempdir().expect("temporary directory");
    let path = directory.path().join("query-sign.log");
    let record = sample_record("snapshot-file-query-sign");

    let receipt = {
        let store = FileEvidenceStore::open(&path).expect("open file store");
        store.append(&record).expect("append")
    };

    let store = FileEvidenceStore::open(&path).expect("reopen file store");
    assert_eq!(store.len().expect("len"), 1);
    assert_eq!(
        store.get(receipt.seq).expect("get").expect("receipt"),
        receipt
    );
    assert_eq!(store.find_by_record(&record).expect("find"), Some(receipt));

    let payload = record.canonical_bytes();
    let signature = sign_canonical(
        &TestSigningKey,
        SignatureRole::Owner,
        "file-owner",
        &payload,
    )
    .expect("sign");
    verify_canonical(&TestSigningKey, &signature, &payload).expect("verify");
}
