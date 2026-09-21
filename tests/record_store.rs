#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::unreachable
)]
use evidence::{
    artifact_manifest_digest, parse_line, sha256_hex, EvidenceDurability, EvidenceRecord,
    EvidenceStore, FileEvidenceStore, MemoryEvidenceStore, ReceiptBinding,
};

fn record() -> EvidenceRecord {
    EvidenceRecord::new(
        "regime_decision",
        "commit-20260801",
        "snapshot-abc",
        vec!["fred-fixture-20260726".into()],
        sha256_hex(b"decision-card:v1|action=A|risk=1"),
        "accepted",
    )
    .expect("fixture record is valid")
}

#[test]
fn memory_store_preserves_decision_provenance() {
    let store = MemoryEvidenceStore::new();
    assert_eq!(store.durability(), EvidenceDurability::Volatile);
    let expected = record();

    let receipt = store.append(&expected).expect("memory append");

    assert_eq!(receipt.seq, 1);
    assert_eq!(receipt.record, expected);
    assert_eq!(store.entries().expect("memory entries"), vec![receipt]);
}

#[test]
fn file_store_recovers_sequence_and_records_after_reopen() {
    let directory = tempfile::tempdir().expect("temporary directory");
    let path = directory.path().join("evidence.log");
    let first = record();

    {
        let store = FileEvidenceStore::open(&path).expect("open file store");
        assert_eq!(store.durability(), EvidenceDurability::LocalDurable);
        assert_eq!(store.append(&first).expect("first append").seq, 1);
    }

    let second = EvidenceRecord::new(
        "regime_decision",
        "commit-20260801",
        "snapshot-def",
        vec![
            "fred-fixture-20260726".into(),
            "market-fixture-20260726".into(),
        ],
        sha256_hex(b"decision-card:v1|action=C|risk=3"),
        "rejected",
    )
    .expect("second record is valid");
    let store = FileEvidenceStore::open(&path).expect("reopen file store");
    let receipt = store.append(&second).expect("second append");

    assert_eq!(receipt.seq, 2);
    assert_eq!(
        store.entries().expect("file entries"),
        vec![
            evidence::AppendReceipt {
                seq: 1,
                record: first,
                binding: None
            },
            receipt,
        ]
    );
}

#[test]
fn invalid_record_is_rejected_before_append() {
    let error = EvidenceRecord::new(
        "regime|decision",
        "commit-20260801",
        "snapshot-abc",
        vec!["fred-fixture-20260726".into()],
        sha256_hex(b"decision-card:v1"),
        "accepted",
    )
    .expect_err("wire delimiter must be rejected");

    assert!(error.to_string().contains("非法字符"));
}

#[test]
fn checked_wire_samples_remain_forward_readable() {
    let sample = include_str!("fixtures/2026-07-25_bootstrap.txt");
    let entries: Vec<_> = sample
        .lines()
        .map(parse_line)
        .collect::<Result<_, _>>()
        .expect("wire samples");

    assert_eq!(entries.len(), 2);
    assert_eq!(entries[0].seq, 1);
    assert_eq!(entries[1].seq, 2);
    assert_eq!(entries[1].record.raw_batch_ids.len(), 2);
}

#[test]
fn b1_wire_sample_remains_forward_readable() {
    let sample = include_str!("fixtures/2026-08-22_b1-binding.txt");
    let receipt = parse_line(sample.trim()).expect("b1 wire sample");
    assert_eq!(receipt.seq, 1);
    assert!(receipt.binding.is_some());
    assert_eq!(
        receipt.binding.as_ref().expect("binding").environment,
        "development"
    );
}

#[test]
fn file_store_idempotent_append_reuses_the_existing_receipt() {
    let directory = tempfile::tempdir().expect("temporary directory");
    let path = directory.path().join("idempotent.log");
    let expected = record();
    let store = FileEvidenceStore::open(&path).expect("open file store");

    let first = store.append_idempotent(&expected).expect("first append");
    let retry = store
        .append_idempotent(&expected)
        .expect("idempotent retry");

    assert_eq!(retry, first);
    assert_eq!(store.entries().expect("entries").len(), 1);
}

#[test]
fn file_store_rejects_a_second_opener_for_the_same_path() {
    let directory = tempfile::tempdir().expect("temporary directory");
    let path = directory.path().join("exclusive.log");
    let first = FileEvidenceStore::open(&path).expect("first opener");

    let second = FileEvidenceStore::open(&path);

    assert!(second.is_err(), "同一路径的第二个 opener 必须失败关闭");
    drop(first);
    FileEvidenceStore::open(&path).expect("首个 opener 释放后应允许重新打开");
}

#[cfg(unix)]
#[test]
fn file_store_rejects_a_second_opener_through_a_hard_link() {
    let directory = tempfile::tempdir().expect("temporary directory");
    let path = directory.path().join("exclusive.log");
    let alias = directory.path().join("exclusive-alias.log");
    let first = FileEvidenceStore::open(&path).expect("first opener");
    std::fs::hard_link(&path, &alias).expect("create hard link");

    let second = FileEvidenceStore::open(&alias);

    assert!(
        second.is_err(),
        "同一底层文件的 hard-link opener 必须失败关闭"
    );
    drop(first);
    FileEvidenceStore::open(&alias).expect("首个 opener 释放后 hard link 应可重新打开");
}

fn sample_binding() -> ReceiptBinding {
    let artifact_digest = artifact_manifest_digest(vec![(
        "artifacts/manifest.json",
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
    )])
    .expect("artifact digest");
    ReceiptBinding::new(
        "0000000000000000000000000000000000000001",
        "development",
        artifact_digest,
    )
    .expect("binding valid")
}

#[test]
fn b1_receipt_binding_roundtrips_through_file_store() {
    let directory = tempfile::tempdir().expect("temporary directory");
    let path = directory.path().join("b1.log");
    let expected = record();
    let binding = sample_binding();
    let receipt = {
        let store = FileEvidenceStore::open(&path).expect("open file store");
        store
            .append_with_binding(&expected, &binding)
            .expect("append with binding")
    };

    assert_eq!(receipt.binding.as_ref(), Some(&binding));

    let reopened = FileEvidenceStore::open(&path).expect("reopen");
    assert_eq!(reopened.entries().expect("reopened entries"), vec![receipt]);
}

#[test]
fn b1_idempotent_append_rejects_conflicting_binding() {
    let store = MemoryEvidenceStore::new();
    let expected = record();
    let binding = sample_binding();
    let other = ReceiptBinding::new(
        "0000000000000000000000000000000000000002",
        "development",
        binding.artifact_digest.clone(),
    )
    .expect("alternate commit");

    store
        .append_idempotent_with_binding(&expected, &binding)
        .expect("first bound append");
    let error = store
        .append_idempotent_with_binding(&expected, &other)
        .expect_err("conflicting binding must fail");

    assert!(error.to_string().contains("绑定"));
}
