#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::unreachable
)]
//! TDD 行为契约（特性 002）。
//!
//! 逐公开入口的先红后绿：下表每个入口先在 `/tmp` 变异副本上观测红、再在本树观测绿；
//! 红绿过程（变异描述 + 复现命令）见 PR 描述。
//!
//! // TDD-PROBE: EvidenceStore::append | 变异：next_seq 不递增（第二条回执序号仍为 1） | 红=append_assigns_monotonic_seq | 绿=append_assigns_monotonic_seq
//! // TDD-PROBE: EvidenceStore::append_idempotent | 变异：幂等查找恒返回 None（每次新增） | 红=idempotent_append_reuses_receipt | 绿=idempotent_append_reuses_receipt
//! // TDD-PROBE: EvidenceStore::append_with_binding | 变异：回执 binding 恒置 None | 红=append_with_binding_records_binding | 绿=append_with_binding_records_binding
//! // TDD-PROBE: MemoryEvidenceStore::new | 变异：初始序号从 0 起（首条回执 seq=0） | 红=memory_seq_starts_at_one | 绿=memory_seq_starts_at_one
//! // TDD-PROBE: FileEvidenceStore::open | 变异：去掉 writer 锁 acquire（允许第二个 opener） | 红=file_open_is_exclusive | 绿=file_open_is_exclusive
//! // TDD-PROBE: EvidenceRecord::canonical_line | 变异：字段分隔符由竖线改为逗号 | 红=canonical_line_is_pipe_delimited | 绿=canonical_line_is_pipe_delimited
//! // TDD-PROBE: parse_line | 变异：去掉 seq==0 的拒绝分支 | 红=parse_line_rejects_zero_seq | 绿=parse_line_rejects_zero_seq
//! // TDD-PROBE: sha256_hex | 变异：十六进制编码改为大写 | 红=sha256_hex_matches_known_vectors | 绿=sha256_hex_matches_known_vectors
//! // TDD-PROBE: sign::sign_canonical | 变异：签名材料不纳入 payload | 红=signature_covers_payload | 绿=signature_covers_payload
//! // TDD-PROBE: sign::verify_canonical | 变异：verify 恒返回 Ok（跳过比较） | 红=verify_rejects_foreign_signature | 绿=verify_rejects_foreign_signature

use evidence::{
    artifact_manifest_digest, parse_line, sha256_hex, sign_canonical, verify_canonical,
    EvidenceDurability, EvidenceError, EvidenceRecord, EvidenceStore, FileEvidenceStore,
    MemoryEvidenceStore, ReceiptBinding, SignatureRole, TestSigningKey,
};

fn record(snapshot: &str) -> EvidenceRecord {
    EvidenceRecord::new(
        "regime_decision",
        "commit-002-test",
        snapshot,
        vec!["fred-fixture-002".into()],
        sha256_hex(format!("decision:{snapshot}").as_bytes()),
        "accepted",
    )
    .expect("夹具记录有效")
}

fn binding(commit: &str) -> ReceiptBinding {
    let artifact_digest = artifact_manifest_digest(vec![(
        "artifacts/manifest.json",
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
    )])
    .expect("artifact 摘要");
    ReceiptBinding::new(commit, "development", artifact_digest).expect("绑定有效")
}

/// `EvidenceStore::append`：序号从 1 起严格单调递增，记录原样回执。
#[test]
fn append_assigns_monotonic_seq() {
    let store = MemoryEvidenceStore::new();
    let first = store.append(&record("snapshot-1")).expect("首次追加");
    let second = store.append(&record("snapshot-2")).expect("二次追加");
    assert_eq!(first.seq, 1, "首个回执序号应为 1");
    assert_eq!(second.seq, 2, "序号应单调递增");
    assert_eq!(second.record, record("snapshot-2"), "回执应携带完整记录");
    assert_eq!(store.entries().expect("快照").len(), 2);
}

/// `EvidenceStore::append_idempotent`：同键复用例回执，不新增行。
#[test]
fn idempotent_append_reuses_receipt() {
    let store = MemoryEvidenceStore::new();
    let expected = record("snapshot-idempotent");
    let first = store.append_idempotent(&expected).expect("首次幂等追加");
    let retry = store.append_idempotent(&expected).expect("重放");
    assert_eq!(first.seq, 1);
    assert_eq!(retry, first, "重放应原样复用已有回执");
    assert_eq!(store.entries().expect("快照").len(), 1, "重放不得新增行");
}

/// `EvidenceStore::append_with_binding`：绑定随回执固化并可通过文件往返。
#[test]
fn append_with_binding_records_binding() {
    let directory = tempfile::tempdir().expect("临时目录");
    let path = directory.path().join("binding.log");
    let expected = record("snapshot-binding");
    let expected_binding = binding("0000000000000000000000000000000000000001");

    let receipt = {
        let store = FileEvidenceStore::open(&path).expect("打开文件存储");
        store
            .append_with_binding(&expected, &expected_binding)
            .expect("带绑定追加")
    };
    assert_eq!(receipt.binding.as_ref(), Some(&expected_binding));
    assert_eq!(receipt.seq, 1);

    let reopened = FileEvidenceStore::open(&path).expect("重开");
    assert_eq!(
        reopened.entries().expect("重开快照"),
        vec![receipt],
        "绑定应持久化并可回读"
    );
}

/// `MemoryEvidenceStore::new`：空存储首条回执序号为 1。
#[test]
fn memory_seq_starts_at_one() {
    let store = MemoryEvidenceStore::new();
    assert!(store.entries().expect("空快照").is_empty());
    assert_eq!(
        store.durability(),
        EvidenceDurability::Volatile,
        "内存实现应声明 Volatile"
    );
    assert_eq!(
        store.append(&record("snapshot-first")).expect("追加").seq,
        1
    );

    store.close().expect("关闭");
    assert!(
        matches!(
            store.append(&record("snapshot-after-close")),
            Err(EvidenceError::Closed)
        ),
        "关闭后追加必须 fail-closed"
    );
}

/// `FileEvidenceStore::open`：同一路径的第二个 opener 必须 fail-closed。
#[test]
fn file_open_is_exclusive() {
    let directory = tempfile::tempdir().expect("临时目录");
    let path = directory.path().join("exclusive.log");
    let first = FileEvidenceStore::open(&path).expect("首个 opener");
    assert_eq!(first.durability(), EvidenceDurability::LocalDurable);

    assert!(
        matches!(
            FileEvidenceStore::open(&path),
            Err(EvidenceError::PathAlreadyOpen)
        ),
        "同路径第二个 opener 必须被拒绝"
    );

    drop(first);
    FileEvidenceStore::open(&path).expect("首个 opener 释放后应可重开");
}

/// `EvidenceRecord::canonical_line`：固定 schema 与 `|` 分隔的七段形状。
#[test]
fn canonical_line_is_pipe_delimited() {
    let record = EvidenceRecord::new(
        "regime_decision",
        "commit-002",
        "snapshot-canonical",
        vec!["batch-a".into(), "batch-b".into()],
        sha256_hex(b"canonical"),
        "accepted",
    )
    .expect("记录有效");
    let line = record.canonical_line();
    assert_eq!(line.split('|').count(), 7, "规范行应为七段");
    assert!(line.starts_with("evidence-record/v1|"), "应以 schema 开头");
    assert!(line.contains("batch-a,batch-b"), "批次应以逗号连接");
    assert_eq!(
        line,
        format!(
            "evidence-record/v1|regime_decision|commit-002|snapshot-canonical|batch-a,batch-b|{}|accepted",
            sha256_hex(b"canonical")
        )
    );
    assert_eq!(record.canonical_bytes(), line.into_bytes());
}

/// `parse_line`：接受合法行并可往返，拒绝序号 0 与错误 schema。
#[test]
fn parse_line_rejects_zero_seq() {
    let expected = record("snapshot-parse");
    let line = format!("1\t{}", expected.canonical_line());
    let parsed = parse_line(&line).expect("合法行可解析");
    assert_eq!(parsed.seq, 1);
    assert_eq!(parsed.record, expected);
    assert_eq!(parsed.binding, None);

    assert!(
        matches!(
            parse_line(&format!("0\t{}", expected.canonical_line())),
            Err(EvidenceError::InvalidWire(_))
        ),
        "序号 0 必须被拒绝"
    );
    assert!(
        matches!(
            parse_line("1\tnot-a-record"),
            Err(EvidenceError::InvalidWire(_))
        ),
        "错误 schema 必须被拒绝"
    );
}

/// `sha256_hex`：小写 64 位，与权威已知向量一致。
#[test]
fn sha256_hex_matches_known_vectors() {
    assert_eq!(
        sha256_hex(b""),
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    );
    assert_eq!(
        sha256_hex(b"abc"),
        "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
    );
    let digest = sha256_hex(b"payload");
    assert_eq!(digest.len(), 64, "摘要必须是 64 位");
    assert_eq!(digest, digest.to_lowercase(), "摘要必须是小写十六进制");
    assert_eq!(digest, sha256_hex(b"payload"), "同一 payload 摘要恒定");
}

/// `sign::sign_canonical`：签名材料覆盖 payload（换 payload 验签必失败）。
#[test]
fn signature_covers_payload() {
    let payload_a = b"canonical-payload-a";
    let payload_b = b"canonical-payload-b";
    let signature = sign_canonical(
        &TestSigningKey,
        SignatureRole::Owner,
        "owner-002",
        payload_a,
    )
    .expect("签名");
    assert_eq!(signature.role(), SignatureRole::Owner);
    assert_eq!(signature.signer_id(), "owner-002");
    assert_eq!(signature.signature_hex().len(), 64);

    verify_canonical(&TestSigningKey, &signature, payload_a).expect("同 payload 验签通过");
    assert!(
        matches!(
            verify_canonical(&TestSigningKey, &signature, payload_b),
            Err(EvidenceError::SignatureInvalid)
        ),
        "换 payload 后验签必须失败"
    );
}

/// `sign::verify_canonical`：拒绝另一 payload 的签名冒充。
#[test]
fn verify_rejects_foreign_signature() {
    let payload = b"canonical-payload";
    let foreign = sign_canonical(
        &TestSigningKey,
        SignatureRole::Owner,
        "owner-002",
        b"other-payload",
    )
    .expect("签另一 payload");
    assert!(
        matches!(
            verify_canonical(&TestSigningKey, &foreign, payload),
            Err(EvidenceError::SignatureInvalid)
        ),
        "异 payload 签名必须被拒绝"
    );

    let legitimate = sign_canonical(
        &TestSigningKey,
        SignatureRole::Reviewer,
        "reviewer-002",
        payload,
    )
    .expect("签本 payload");
    verify_canonical(&TestSigningKey, &legitimate, payload).expect("合法签名通过");
}
