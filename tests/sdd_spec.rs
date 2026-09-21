#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::unreachable
)]
//! SDD 规格对照（特性 002）：把 `docs/标准.md` 的章节条款转成可执行断言。
//!
//! // SPEC-MAP: S-1 | 1. 定位 | assert_positioning
//! // SPEC-MAP: S-2 | 2. 数据模型标准 | assert_record_model
//! // SPEC-MAP: S-3 | 3. 追加语义标准 | assert_append_semantics
//! // SPEC-MAP: S-4 | 4. 完整性标准 | assert_integrity
//! // SPEC-MAP: S-5 | 5. 验收 | assert_acceptance

use evidence::{
    artifact_manifest_digest, parse_line, sha256_hex, sign_canonical, verify_approval,
    verify_binding, verify_canonical, AppendReceipt, EvidenceDurability, EvidenceError,
    EvidenceRecord, EvidenceStore, FileEvidenceStore, ImmutableBinding, LineageBinding,
    MemoryEvidenceStore, ReceiptBinding, SignatureRole, TestSigningKey,
};

fn record(snapshot: &str) -> EvidenceRecord {
    EvidenceRecord::new(
        "regime_decision",
        "commit-sdd-002",
        snapshot,
        vec!["fred-fixture-002".into()],
        sha256_hex(format!("decision:{snapshot}").as_bytes()),
        "accepted",
    )
    .expect("夹具记录有效")
}

fn binding() -> ReceiptBinding {
    let artifact_digest = artifact_manifest_digest(vec![(
        "artifacts/manifest.json",
        "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
    )])
    .expect("artifact 摘要");
    ReceiptBinding::new(
        "0000000000000000000000000000000000000002",
        "staging",
        artifact_digest,
    )
    .expect("绑定有效")
}

/// S-1：定位——零内部耦合，`EvidenceStore` 对象安全，只经 `dyn` 消费。
#[test]
fn assert_positioning() {
    // 只用本 crate 的公开类型即可完成一次完整追加（不牵引任何主工程 crate）。
    let store = MemoryEvidenceStore::new();
    let receipt = store.append(&record("snapshot-positioning")).expect("追加");
    assert_eq!(receipt.seq, 1);

    // 追加 seam 对象安全：可跨 `&dyn` 调用。
    let dyn_store: &dyn EvidenceStore = &store;
    assert_eq!(dyn_store.durability(), EvidenceDurability::Volatile);
    assert_eq!(
        dyn_store
            .append(&record("snapshot-dyn"))
            .expect("dyn 追加")
            .seq,
        2
    );
}

/// S-2：数据模型标准——六字段、保留字符、摘要格式与规范行形状。
#[test]
fn assert_record_model() {
    let valid = record("snapshot-model");
    assert_eq!(valid.canonical_line().split('|').count(), 7);
    assert!(valid.canonical_line().starts_with("evidence-record/v1|"));

    // 空字段 / 保留字符 / 批次含逗号 / 摘要非法 的构造校验。
    assert!(matches!(
        EvidenceRecord::new("", "c", "s", vec!["b".into()], sha256_hex(b"x"), "o"),
        Err(EvidenceError::EmptyField("event"))
    ));
    assert!(matches!(
        EvidenceRecord::new("e|bad", "c", "s", vec!["b".into()], sha256_hex(b"x"), "o"),
        Err(EvidenceError::InvalidCharacter("event"))
    ));
    assert!(matches!(
        EvidenceRecord::new("e", "c", "s", vec!["a,b".into()], sha256_hex(b"x"), "o"),
        Err(EvidenceError::InvalidCharacter("raw_batch_id"))
    ));
    assert!(matches!(
        EvidenceRecord::new("e", "c", "s", vec![], sha256_hex(b"x"), "o"),
        Err(EvidenceError::EmptyField("raw_batch_ids"))
    ));
    assert!(matches!(
        EvidenceRecord::new("e", "c", "s", vec!["b".into()], "short", "o"),
        Err(EvidenceError::InvalidDigest("result_digest"))
    ));

    // ReceiptBinding：commit 必须 40 位、artifact 摘要必须 64 位十六进制。
    assert!(matches!(
        ReceiptBinding::new("not-a-commit", "dev", sha256_hex(b"a")),
        Err(EvidenceError::InvalidDigest("source_commit"))
    ));
    assert!(matches!(
        ReceiptBinding::new("0000000000000000000000000000000000000001", "dev", "xyz"),
        Err(EvidenceError::InvalidDigest("artifact_digest"))
    ));
    assert_eq!(binding().canonical_line().split('|').count(), 4);

    // artifact 清单摘要与输入顺序无关（应先排序）。
    let digest_a = artifact_manifest_digest(vec![
        (
            "b.json",
            "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
        ),
        (
            "a.json",
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        ),
    ])
    .expect("清单摘要");
    let digest_b = artifact_manifest_digest(vec![
        (
            "a.json",
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        ),
        (
            "b.json",
            "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
        ),
    ])
    .expect("清单摘要");
    assert_eq!(digest_a, digest_b, "清单摘要应与顺序无关");
}

/// S-3：追加语义标准——序号、幂等、默认拒绝、持久性声明与 fail-closed。
#[test]
fn assert_append_semantics() {
    let store = MemoryEvidenceStore::new();
    assert_eq!(store.append(&record("s-1")).expect("追加").seq, 1);
    assert_eq!(store.append(&record("s-2")).expect("追加").seq, 2);

    // 幂等复用例回执，不新增行。
    let repeated = record("s-idempotent");
    let first = store.append_idempotent(&repeated).expect("首次");
    assert_eq!(store.append_idempotent(&repeated).expect("重放"), first);

    // 幂等键相同但 binding 冲突 → BindingMismatch。
    let bound = record("s-bound");
    store
        .append_idempotent_with_binding(&bound, &binding())
        .expect("带绑定首次");
    let conflict = ReceiptBinding::new(
        "0000000000000000000000000000000000000003",
        "staging",
        binding().artifact_digest.clone(),
    )
    .expect("另一绑定");
    assert!(matches!(
        store.append_idempotent_with_binding(&bound, &conflict),
        Err(EvidenceError::BindingMismatch)
    ));

    // 未实现幂等 / 绑定的适配器走默认拒绝，避免调用方误认为可重试。
    struct RejectOnly;
    impl EvidenceStore for RejectOnly {
        fn append(&self, _record: &EvidenceRecord) -> Result<AppendReceipt, EvidenceError> {
            Err(EvidenceError::Closed)
        }
    }
    let minimal = RejectOnly;
    assert_eq!(minimal.durability(), EvidenceDurability::Volatile);
    assert!(matches!(
        minimal.append_idempotent(&record("s-default")),
        Err(EvidenceError::IdempotencyUnsupported)
    ));
    assert!(matches!(
        minimal.append_with_binding(&record("s-default"), &binding()),
        Err(EvidenceError::BindingUnsupported)
    ));
    assert!(matches!(
        minimal.append_idempotent_with_binding(&record("s-default"), &binding()),
        Err(EvidenceError::BindingUnsupported)
    ));

    // 关闭后 fail-closed。
    store.close().expect("关闭");
    assert!(matches!(
        store.append(&record("s-closed")),
        Err(EvidenceError::Closed)
    ));

    // 文件行协议：重开时序号从最大序号继续，且逐行校验。
    let directory = tempfile::tempdir().expect("临时目录");
    let path = directory.path().join("semantics.log");
    {
        let file_store = FileEvidenceStore::open(&path).expect("打开");
        assert_eq!(file_store.durability(), EvidenceDurability::LocalDurable);
        file_store.append(&record("s-file-1")).expect("追加 1");
        file_store.append(&record("s-file-2")).expect("追加 2");
    }
    let reopened = FileEvidenceStore::open(&path).expect("重开");
    assert_eq!(reopened.append(&record("s-file-3")).expect("追加 3").seq, 3);
}

/// S-4：完整性标准——摘要、反解析、签名与溯源不变量。
#[test]
fn assert_integrity() {
    // sha256_hex 小写 64 位。
    let digest = sha256_hex(b"integrity");
    assert_eq!(digest.len(), 64);
    assert_eq!(digest, digest.to_lowercase());

    // parse_line 往返 + 拒绝零序号 / 错误 schema。
    let expected = record("snapshot-integrity");
    let line = format!("1\t{}", expected.canonical_line());
    assert_eq!(parse_line(&line).expect("解析").record, expected);
    assert!(matches!(
        parse_line("0\tanything"),
        Err(EvidenceError::InvalidWire(_))
    ));
    assert!(matches!(
        parse_line("1\tbad-schema"),
        Err(EvidenceError::InvalidWire(_))
    ));

    // 签名：空 signer 拒绝；换 payload 或换签名都失败。
    let payload = b"integrity-payload";
    assert!(matches!(
        sign_canonical(&TestSigningKey, SignatureRole::Owner, "", payload),
        Err(EvidenceError::EmptySignerId)
    ));
    let owner = sign_canonical(&TestSigningKey, SignatureRole::Owner, "owner-sdd", payload)
        .expect("Owner 签名");
    verify_canonical(&TestSigningKey, &owner, payload).expect("验签通过");
    assert!(matches!(
        verify_canonical(&TestSigningKey, &owner, b"other"),
        Err(EvidenceError::SignatureInvalid)
    ));

    // 审批状态机：角色必须 Owner → Reviewer。
    let reviewer = sign_canonical(
        &TestSigningKey,
        SignatureRole::Reviewer,
        "reviewer-sdd",
        payload,
    )
    .expect("Reviewer 签名");
    verify_approval(&TestSigningKey, &owner, &reviewer, payload).expect("审批通过");
    assert!(matches!(
        verify_approval(&TestSigningKey, &reviewer, &owner, payload),
        Err(EvidenceError::InvalidApprovalRole)
    ));

    // 不可变 binding：合法签名可独立复验；非法 commit / 摘要被拒。
    let immutable = ImmutableBinding::sign(
        "owner-sdd",
        "0123456789abcdef0123456789abcdef01234567",
        "evidence-record/v1",
        "development",
        sha256_hex(b"artifacts"),
    )
    .expect("签名 binding");
    immutable.verify().expect("独立复验通过");
    verify_binding(&immutable).expect("verifier 通过");
    assert!(matches!(
        ImmutableBinding::sign(
            "owner-sdd",
            "not-a-commit",
            "evidence-record/v1",
            "development",
            sha256_hex(b"artifacts"),
        ),
        Err(EvidenceError::InvalidDigest(_))
    ));

    // 溯源：raw_sha256 与 pit 的形状约束。
    LineageBinding::new(
        "provider-sdd",
        sha256_hex(b"raw"),
        "fred/series/2026-09-22",
        "2026-09-22T12:00:00Z",
    )
    .expect("RFC3339 pit 有效");
    assert!(matches!(
        LineageBinding::new("provider-sdd", sha256_hex(b"raw"), "lineage", "2026-09-22"),
        Err(EvidenceError::LineageInvalid(_))
    ));
    assert!(matches!(
        LineageBinding::new("", sha256_hex(b"raw"), "lineage", "2026-09-22T12:00:00Z"),
        Err(EvidenceError::EmptyField("provider_request_id"))
    ));
}

/// S-5：验收——标准.md §5 声明的覆盖域各取一条可执行断言。
#[test]
fn assert_acceptance() {
    // 覆盖域 1：构造校验。
    assert!(EvidenceRecord::new("e", "c", "s", vec!["b".into()], "bad", "o").is_err());
    // 覆盖域 2：canonical_line / parse_line 往返。
    let expected = record("snapshot-acceptance");
    assert_eq!(
        parse_line(&format!("1\t{}", expected.canonical_line()))
            .expect("往返")
            .record,
        expected
    );
    // 覆盖域 3：两类实现的序号单调与幂等复用。
    let memory = MemoryEvidenceStore::new();
    assert_eq!(memory.append(&expected).expect("追加").seq, 1);
    assert_eq!(memory.append_idempotent(&expected).expect("重放").seq, 1);
    // 覆盖域 4：文件 opener fail-closed。
    let directory = tempfile::tempdir().expect("临时目录");
    let path = directory.path().join("acceptance.log");
    let first = FileEvidenceStore::open(&path).expect("首个 opener");
    assert!(matches!(
        FileEvidenceStore::open(&path),
        Err(EvidenceError::PathAlreadyOpen)
    ));
    drop(first);
    // 覆盖域 5：签名与审批角色。
    let payload = expected.canonical_bytes();
    let owner = sign_canonical(&TestSigningKey, SignatureRole::Owner, "owner-acc", &payload)
        .expect("Owner");
    let reviewer = sign_canonical(
        &TestSigningKey,
        SignatureRole::Reviewer,
        "reviewer-acc",
        &payload,
    )
    .expect("Reviewer");
    verify_approval(&TestSigningKey, &owner, &reviewer, &payload).expect("审批通过");
}
