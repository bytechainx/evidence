#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::unreachable
)]
//! E2E（evidence）：端到端执行**全部**公开接口，不依赖外部真服务。
//!
//! 本仓是证据链契约仓：E2E 的端到端含义是「**写入 → 落盘 → 重新解析 → 读回 → 校验**」
//! 的完整闭环，而不是单点调用。因此：
//! - 内存存储走完整 `EvidenceStore` / `EvidenceReader` / `AsyncEvidenceStore` 三条契约；
//! - 文件存储用真实临时文件走 `open` → `append` → `entries` → `FileEvidenceIter` →
//!   `read_entries_page` → `parse_line` 磁盘往返，并断言 `was_truncated_on_open`；
//! - 签名与绑定走 `sign_canonical` → `verify_canonical` → `verify_approval` 以及
//!   `ImmutableBinding::sign` → 各访问器的完整路径。
//!
//! 对齐对象是 `cargo +nightly public-api --simplified` 导出的完整公开面：
//! `fn` / `type` / `field` / `const` / `variant` 五类逐条登记在 [`E2E_MANIFEST`]，
//! 运行期由 `cover` 登记表核对「声明 = 实际执行」（缺一即失败）。
//!
//! **独立核对**：`scripts/verify-e2e-coverage.mjs` 会重新派生公开面与清单双向 diff，
//! 并用 `-C instrument-coverage` + `llvm-cov report --show-functions` 断言每条公开
//! 函数执行次数 > 0；本文件内的登记表只是**声明**，不是唯一证据。
//!
//! ```text
//! cd /home/workspace/bytechainx/infra/evidence
//! cargo test --test e2e_evidence
//! node scripts/verify-e2e-coverage.mjs evidence --no-coverage
//! ```

use std::collections::BTreeSet;
use std::io::Write;

use evidence::{
    artifact_manifest_digest, parse_line, read_entries_page, sha256_hex, sign_canonical,
    verify_approval, verify_canonical, verify_composition, verify_lineage, AppendReceipt,
    AsyncEvidenceStore, DecisionComposition, EvidenceAppendOutcome, EvidenceDurability,
    EvidenceError, EvidenceReader, EvidenceRecord, EvidenceResult, EvidenceStore, FileEvidenceIter,
    FileEvidenceStore, ImmutableBinding, LineageBinding, MemoryEvidenceStore, ReceiptBinding,
    ResultUnknownReceipt, SignatureRole, SigningKey, BINDING_SCHEMA, IMMUTABLE_BINDING_SCHEMA,
    RECORD_SCHEMA,
};

/// 公开面清单：`(条目类别, 入口 id)`，由 `cargo +nightly public-api --simplified` 派生并冻结。
///
/// 类别取值域：`fn` / `type` / `field` / `const` / `variant`。
/// 该清单是运行时登记的**唯一事实源**——`cover::hit` 拒绝清单外的 id，收尾断言拒绝
/// 「声明了却没执行」的条目。清单本身的时效性由外部核对器与公开面 diff 保证。
#[rustfmt::skip]
const E2E_MANIFEST: &[(&str, &str)] = &[
    ("type", "EvidenceAppendOutcome"),
    ("variant", "EvidenceAppendOutcome::Appended"),
    ("variant", "EvidenceAppendOutcome::IdempotentReplay"),
    ("variant", "EvidenceAppendOutcome::ResultUnknown"),
    ("type", "EvidenceDurability"),
    ("variant", "EvidenceDurability::LocalDurable"),
    ("variant", "EvidenceDurability::RemoteDurable"),
    ("variant", "EvidenceDurability::Volatile"),
    ("type", "EvidenceError"),
    ("variant", "EvidenceError::BindingMismatch"),
    ("variant", "EvidenceError::BindingUnsupported"),
    ("variant", "EvidenceError::Closed"),
    ("variant", "EvidenceError::Durability"),
    ("variant", "EvidenceError::EmptyField"),
    ("variant", "EvidenceError::EmptySignerId"),
    ("variant", "EvidenceError::IdempotencyUnsupported"),
    ("variant", "EvidenceError::InvalidApprovalRole"),
    ("variant", "EvidenceError::InvalidCharacter"),
    ("variant", "EvidenceError::InvalidDigest"),
    ("variant", "EvidenceError::InvalidWire"),
    ("variant", "EvidenceError::LineageInvalid"),
    ("variant", "EvidenceError::LockPoisoned"),
    ("variant", "EvidenceError::PathAlreadyOpen"),
    ("variant", "EvidenceError::Remote"),
    ("variant", "EvidenceError::SignatureInvalid"),
    ("type", "SignatureRole"),
    ("variant", "SignatureRole::Owner"),
    ("variant", "SignatureRole::Reviewer"),
    ("type", "AppendReceipt"),
    ("field", "AppendReceipt::binding"),
    ("field", "AppendReceipt::record"),
    ("field", "AppendReceipt::seq"),
    ("type", "DecisionComposition"),
    ("fn", "DecisionComposition::composition"),
    ("fn", "DecisionComposition::decision_id"),
    ("fn", "DecisionComposition::new"),
    ("fn", "DecisionComposition::record_ref"),
    ("type", "EvidenceRecord"),
    ("field", "EvidenceRecord::code_version"),
    ("field", "EvidenceRecord::event"),
    ("field", "EvidenceRecord::input_snapshot"),
    ("field", "EvidenceRecord::outcome"),
    ("field", "EvidenceRecord::raw_batch_ids"),
    ("field", "EvidenceRecord::result_digest"),
    ("fn", "EvidenceRecord::canonical_bytes"),
    ("fn", "EvidenceRecord::canonical_line"),
    ("fn", "EvidenceRecord::new"),
    ("type", "FileEvidenceIter"),
    ("fn", "FileEvidenceIter::open"),
    ("fn", "FileEvidenceIter::parsed_count"),
    ("type", "FileEvidenceStore"),
    ("fn", "FileEvidenceStore::entries"),
    ("fn", "FileEvidenceStore::entry_count"),
    ("fn", "FileEvidenceStore::open"),
    ("fn", "FileEvidenceStore::path"),
    ("fn", "FileEvidenceStore::was_truncated_on_open"),
    ("type", "ImmutableBinding"),
    ("fn", "ImmutableBinding::artifact_digest"),
    ("fn", "ImmutableBinding::canonical_bytes"),
    ("fn", "ImmutableBinding::environment"),
    ("fn", "ImmutableBinding::owner_signature"),
    ("fn", "ImmutableBinding::schema"),
    ("fn", "ImmutableBinding::source_commit"),
    ("type", "LineageBinding"),
    ("fn", "LineageBinding::lineage"),
    ("fn", "LineageBinding::new"),
    ("fn", "LineageBinding::pit"),
    ("fn", "LineageBinding::provider_request_id"),
    ("fn", "LineageBinding::raw_sha256"),
    ("type", "MemoryEvidenceStore"),
    ("fn", "MemoryEvidenceStore::close"),
    ("fn", "MemoryEvidenceStore::entries"),
    ("fn", "MemoryEvidenceStore::new"),
    ("type", "ProtectedSignature"),
    ("fn", "ProtectedSignature::role"),
    ("fn", "ProtectedSignature::signature_hex"),
    ("fn", "ProtectedSignature::signed_at_ms"),
    ("fn", "ProtectedSignature::signer_id"),
    ("type", "ReceiptBinding"),
    ("field", "ReceiptBinding::artifact_digest"),
    ("field", "ReceiptBinding::environment"),
    ("field", "ReceiptBinding::source_commit"),
    ("fn", "ReceiptBinding::canonical_line"),
    ("fn", "ReceiptBinding::new"),
    ("type", "ResultUnknownReceipt"),
    ("field", "ResultUnknownReceipt::operation"),
    ("field", "ResultUnknownReceipt::reason"),
    ("field", "ResultUnknownReceipt::record"),
    ("field", "ResultUnknownReceipt::record_key"),
    ("const", "BINDING_SCHEMA"),
    ("const", "IMMUTABLE_BINDING_SCHEMA"),
    ("const", "RECORD_SCHEMA"),
    ("type", "AsyncEvidenceStore"),
    ("fn", "AsyncEvidenceStore::append"),
    ("fn", "AsyncEvidenceStore::append_idempotent"),
    ("fn", "AsyncEvidenceStore::append_idempotent_outcome"),
    ("fn", "AsyncEvidenceStore::append_idempotent_outcome_with_binding"),
    ("fn", "AsyncEvidenceStore::append_idempotent_with_binding"),
    ("fn", "AsyncEvidenceStore::append_with_binding"),
    ("fn", "AsyncEvidenceStore::durability"),
    ("type", "EvidenceReader"),
    ("fn", "EvidenceReader::find_by_record"),
    ("fn", "EvidenceReader::get"),
    ("fn", "EvidenceReader::is_empty"),
    ("fn", "EvidenceReader::len"),
    ("type", "EvidenceStore"),
    ("fn", "EvidenceStore::append"),
    ("fn", "EvidenceStore::append_idempotent"),
    ("fn", "EvidenceStore::append_idempotent_with_binding"),
    ("fn", "EvidenceStore::append_with_binding"),
    ("fn", "EvidenceStore::durability"),
    ("type", "SigningKey"),
    ("fn", "SigningKey::key_material"),
    ("fn", "artifact_manifest_digest"),
    ("fn", "parse_line"),
    ("fn", "read_entries_page"),
    ("fn", "sha256_hex"),
    ("fn", "sign_canonical"),
    ("fn", "verify_approval"),
    ("fn", "verify_canonical"),
    ("fn", "verify_composition"),
    ("fn", "verify_lineage"),
    ("type", "EvidenceResult"),
];

mod cover {
    use std::collections::BTreeSet;
    use std::sync::{Mutex, OnceLock};

    static EXECUTED: OnceLock<Mutex<BTreeSet<(&'static str, &'static str)>>> = OnceLock::new();

    fn log() -> &'static Mutex<BTreeSet<(&'static str, &'static str)>> {
        EXECUTED.get_or_init(|| Mutex::new(BTreeSet::new()))
    }

    /// 登记一次真实执行。清单外的 `(类别, id)` 立即 panic，防止调用点与清单漂移。
    pub fn hit(kind: &'static str, id: &'static str) {
        assert!(
            super::E2E_MANIFEST
                .iter()
                .any(|(declared_kind, declared_id)| *declared_kind == kind && *declared_id == id),
            "登记了清单外的公开条目：{kind} {id}"
        );
        log().lock().expect("覆盖登记表锁中毒").insert((kind, id));
    }

    /// 已登记的执行集合（收尾断言用）。
    pub fn executed() -> BTreeSet<(&'static str, &'static str)> {
        log().lock().expect("覆盖登记表锁中毒").clone()
    }
}

/// 覆盖登记的简写入口（保持调用点可读）。
fn hit(kind: &'static str, id: &'static str) {
    cover::hit(kind, id);
}

/// 清单自身良构：类别取值域合法、`(类别, id)` 不重复。
fn assert_manifest_wellformed() {
    let mut seen: BTreeSet<(&str, &str)> = BTreeSet::new();
    for (kind, id) in E2E_MANIFEST {
        assert!(
            matches!(*kind, "fn" | "type" | "field" | "const" | "variant"),
            "未知条目类别 {kind}（id={id}）"
        );
        assert!(seen.insert((*kind, *id)), "清单重复条目：{kind} {id}");
    }
}

/// 覆盖完整性：清单里每一条都必须被真实执行过。
fn assert_coverage_complete() {
    let executed = cover::executed();
    let mut missing: Vec<(&str, &str)> = Vec::new();
    for (kind, id) in E2E_MANIFEST {
        if !executed.contains(&(*kind, *id)) {
            missing.push((kind, id));
        }
    }
    assert!(missing.is_empty(), "声明了却未执行：{missing:?}");
}

/// 测试侧签名密钥：只提供密钥材料，签名算法由 crate 侧决定。
#[derive(Debug)]
struct TestKey(Vec<u8>);

impl SigningKey for TestKey {
    fn key_material(&self) -> &[u8] {
        &self.0
    }
}

/// 确定性 64 位十六进制摘要（crate 侧 `validate_digest` 要求）。
fn digest(seed: &str) -> String {
    hit("fn", "sha256_hex");
    sha256_hex(seed.as_bytes())
}

/// 确定性 40 位 commit（crate 侧 `validate_commit` 要求）。
fn commit(seed: &str) -> String {
    digest(seed)[..40].to_owned()
}

/// 一条合法记录（`EvidenceRecord::new` 的登记由各阶段负责）。
fn raw_record(event: &str) -> EvidenceRecord {
    EvidenceRecord {
        event: event.to_owned(),
        code_version: "0.2.0".to_owned(),
        input_snapshot: digest("snapshot"),
        raw_batch_ids: vec!["batch-1".to_owned()],
        result_digest: digest("result"),
        outcome: "accepted".to_owned(),
    }
}

/// 错误枚举：逐个变体构造。
fn phase_error_variants() {
    hit("type", "EvidenceError");
    let variants: [(EvidenceError, &str); 13] = [
        (
            EvidenceError::BindingMismatch,
            "EvidenceError::BindingMismatch",
        ),
        (
            EvidenceError::BindingUnsupported,
            "EvidenceError::BindingUnsupported",
        ),
        (EvidenceError::Closed, "EvidenceError::Closed"),
        (
            EvidenceError::Durability(std::io::Error::other("disk")),
            "EvidenceError::Durability",
        ),
        (
            EvidenceError::EmptyField("event"),
            "EvidenceError::EmptyField",
        ),
        (EvidenceError::EmptySignerId, "EvidenceError::EmptySignerId"),
        (
            EvidenceError::IdempotencyUnsupported,
            "EvidenceError::IdempotencyUnsupported",
        ),
        (
            EvidenceError::InvalidApprovalRole,
            "EvidenceError::InvalidApprovalRole",
        ),
        (
            EvidenceError::InvalidCharacter("event"),
            "EvidenceError::InvalidCharacter",
        ),
        (
            EvidenceError::InvalidDigest("result_digest"),
            "EvidenceError::InvalidDigest",
        ),
        (
            EvidenceError::InvalidWire("bad".to_owned()),
            "EvidenceError::InvalidWire",
        ),
        (
            EvidenceError::LineageInvalid("cycle".to_owned()),
            "EvidenceError::LineageInvalid",
        ),
        (EvidenceError::LockPoisoned, "EvidenceError::LockPoisoned"),
    ];
    for (error, id) in variants {
        hit("variant", id);
        assert!(!error.to_string().is_empty(), "{id} 必须可读");
    }

    let rest: [(EvidenceError, &str); 4] = [
        (
            EvidenceError::PathAlreadyOpen,
            "EvidenceError::PathAlreadyOpen",
        ),
        (
            EvidenceError::Remote("remote down".to_owned()),
            "EvidenceError::Remote",
        ),
        (
            EvidenceError::SignatureInvalid,
            "EvidenceError::SignatureInvalid",
        ),
        (EvidenceError::Closed, "EvidenceError::Closed"),
    ];
    for (error, id) in rest {
        hit("variant", id);
        assert!(!format!("{error:?}").is_empty(), "{id} 必须有 Debug");
    }
}

/// 记录与绑定：构造 → 规范行 → 摘要。
fn phase_record_and_binding() {
    hit("type", "EvidenceRecord");
    hit("fn", "EvidenceRecord::new");
    hit("fn", "EvidenceRecord::canonical_line");
    hit("fn", "EvidenceRecord::canonical_bytes");
    hit("field", "EvidenceRecord::event");
    hit("field", "EvidenceRecord::code_version");
    hit("field", "EvidenceRecord::input_snapshot");
    hit("field", "EvidenceRecord::raw_batch_ids");
    hit("field", "EvidenceRecord::result_digest");
    hit("field", "EvidenceRecord::outcome");
    hit("const", "RECORD_SCHEMA");

    let record = EvidenceRecord::new(
        "unit-a",
        "0.2.0",
        digest("snapshot"),
        vec!["batch-1".to_owned()],
        digest("result"),
        "accepted",
    )
    .expect("合法记录构造必须成功");
    assert_eq!(record.event, "unit-a");
    assert_eq!(record.code_version, "0.2.0");
    assert_eq!(record.input_snapshot.len(), 64);
    assert_eq!(record.raw_batch_ids.len(), 1);
    assert_eq!(record.result_digest.len(), 64);
    assert_eq!(record.outcome, "accepted");
    let line = record.canonical_line();
    assert!(line.starts_with(RECORD_SCHEMA), "规范行必须带 schema 前缀");
    assert_eq!(record.canonical_bytes(), line.clone().into_bytes());

    hit("type", "ReceiptBinding");
    hit("fn", "ReceiptBinding::new");
    hit("fn", "ReceiptBinding::canonical_line");
    hit("field", "ReceiptBinding::source_commit");
    hit("field", "ReceiptBinding::environment");
    hit("field", "ReceiptBinding::artifact_digest");
    hit("const", "BINDING_SCHEMA");

    let binding = ReceiptBinding::new(commit("commit"), "development", digest("artifact"))
        .expect("合法绑定构造必须成功");
    assert_eq!(binding.source_commit.len(), 40);
    assert_eq!(binding.environment, "development");
    assert_eq!(binding.artifact_digest.len(), 64);
    assert!(binding.canonical_line().starts_with(BINDING_SCHEMA));

    hit("fn", "artifact_manifest_digest");
    let artifact = digest("artifact");
    let manifest =
        artifact_manifest_digest(vec![("a.txt", artifact.as_str())]).expect("清单摘要必须成功");
    assert_eq!(manifest.len(), 64);
}

/// 签名：签发 → 单签校验 → 审批双签校验。
fn phase_signing() {
    hit("type", "SigningKey");
    hit("fn", "SigningKey::key_material");
    let key = TestKey(b"e2e-key-material".to_vec());
    assert_eq!(key.key_material(), b"e2e-key-material");

    hit("type", "SignatureRole");
    hit("variant", "SignatureRole::Owner");
    hit("variant", "SignatureRole::Reviewer");
    hit("fn", "sign_canonical");
    hit("fn", "verify_canonical");
    hit("fn", "verify_approval");
    hit("type", "ProtectedSignature");
    hit("fn", "ProtectedSignature::role");
    hit("fn", "ProtectedSignature::signer_id");
    hit("fn", "ProtectedSignature::signature_hex");
    hit("fn", "ProtectedSignature::signed_at_ms");

    let payload = b"e2e-payload";
    let owner =
        sign_canonical(&key, SignatureRole::Owner, "owner-1", payload).expect("Owner 签名必须成功");
    assert_eq!(owner.signer_id(), "owner-1");
    assert!(!owner.signature_hex().is_empty());
    assert!(owner.signed_at_ms() > 0);
    assert!(matches!(owner.role(), SignatureRole::Owner));
    verify_canonical(&key, &owner, payload).expect("单签校验必须成功");

    let reviewer = sign_canonical(&key, SignatureRole::Reviewer, "reviewer-1", payload)
        .expect("Reviewer 签名必须成功");
    assert!(matches!(reviewer.role(), SignatureRole::Reviewer));
    verify_approval(&key, &owner, &reviewer, payload).expect("审批双签校验必须成功");
}

/// 血缘与决策组合：构造 → 访问器 → 校验。
fn phase_lineage() {
    hit("type", "LineageBinding");
    hit("fn", "LineageBinding::new");
    hit("fn", "LineageBinding::provider_request_id");
    hit("fn", "LineageBinding::raw_sha256");
    hit("fn", "LineageBinding::lineage");
    hit("fn", "LineageBinding::pit");
    hit("fn", "verify_lineage");

    let raw = digest("raw");
    let lineage = LineageBinding::new(
        "req-1",
        raw.clone(),
        "binance/um/1m",
        "2026-10-09T00:00:00Z",
    )
    .expect("合法血缘构造必须成功");
    assert_eq!(lineage.provider_request_id(), "req-1");
    assert_eq!(lineage.raw_sha256(), raw);
    assert_eq!(lineage.lineage(), "binance/um/1m");
    assert_eq!(lineage.pit(), "2026-10-09T00:00:00Z");
    verify_lineage(&lineage).expect("血缘校验必须成功");

    hit("type", "DecisionComposition");
    hit("fn", "DecisionComposition::new");
    hit("fn", "DecisionComposition::decision_id");
    hit("fn", "DecisionComposition::composition");
    hit("fn", "DecisionComposition::record_ref");
    hit("fn", "verify_composition");

    let composition = DecisionComposition::new(
        "decision-1",
        vec![LineageBinding::new(
            "req-2",
            digest("raw-2"),
            "binance/um/1m",
            "2026-10-09T01:00:00Z",
        )
        .expect("血缘构造必须成功")],
        Some("record-ref-1".to_owned()),
    )
    .expect("合法组合构造必须成功");
    assert_eq!(composition.decision_id(), "decision-1");
    assert_eq!(composition.composition().len(), 1);
    assert_eq!(composition.record_ref(), Some("record-ref-1"));
    verify_composition(&composition).expect("组合校验必须成功");
}

/// 内存存储：同步三条契约（Store / Reader / Async）全走一遍。
async fn phase_memory_store() {
    hit("type", "MemoryEvidenceStore");
    hit("fn", "MemoryEvidenceStore::new");
    hit("fn", "MemoryEvidenceStore::entries");
    hit("fn", "MemoryEvidenceStore::close");
    hit("type", "EvidenceStore");
    hit("fn", "EvidenceStore::append");
    hit("fn", "EvidenceStore::append_with_binding");
    hit("fn", "EvidenceStore::append_idempotent");
    hit("fn", "EvidenceStore::append_idempotent_with_binding");
    hit("type", "EvidenceReader");
    hit("fn", "EvidenceReader::get");
    hit("fn", "EvidenceReader::len");
    hit("fn", "EvidenceReader::is_empty");
    hit("fn", "EvidenceReader::find_by_record");
    hit("type", "AppendReceipt");
    hit("field", "AppendReceipt::seq");
    hit("field", "AppendReceipt::record");
    hit("field", "AppendReceipt::binding");

    let store = MemoryEvidenceStore::new();
    assert!(store.is_empty().expect("is_empty 必须成功"));
    let record = EvidenceRecord::new(
        "memory-a",
        "0.2.0",
        digest("snapshot"),
        vec!["batch-1".to_owned()],
        digest("result"),
        "accepted",
    )
    .expect("记录构造必须成功");
    let binding = ReceiptBinding::new(commit("commit"), "development", digest("artifact"))
        .expect("绑定构造必须成功");

    let bound = raw_record("memory-bound");
    let first = EvidenceStore::append(&store, &record).expect("append 必须成功");
    assert!(first.seq >= 1, "追加序号必须从 1 起");
    assert!(first.binding.is_none());
    assert_eq!(first.record.event, "memory-a");

    let with_binding = EvidenceStore::append_with_binding(&store, &bound, &binding)
        .expect("append_with_binding 必须成功");
    assert!(with_binding.binding.is_some());

    let replayed =
        EvidenceStore::append_idempotent(&store, &record).expect("append_idempotent 必须成功");
    assert_eq!(replayed.seq, first.seq, "幂等重放必须命中首条");

    let replayed_bound = EvidenceStore::append_idempotent_with_binding(&store, &bound, &binding)
        .expect("append_idempotent_with_binding 必须成功");
    assert!(replayed_bound.binding.is_some());

    assert_eq!(store.len().expect("len 必须成功"), 2);
    assert!(!store.is_empty().expect("is_empty 必须成功"));
    assert!(store.get(1).expect("get 必须成功").is_some());
    assert_eq!(store.entries().expect("entries 必须成功").len(), 2);
    assert!(store
        .find_by_record(&record)
        .expect("find_by_record 必须成功")
        .is_some());

    hit("type", "EvidenceDurability");
    hit("variant", "EvidenceDurability::Volatile");
    hit("fn", "EvidenceStore::durability");
    assert_eq!(
        EvidenceStore::durability(&store),
        EvidenceDurability::Volatile,
        "内存存储必须自报易失"
    );

    hit("type", "AsyncEvidenceStore");
    hit("fn", "AsyncEvidenceStore::append");
    hit("fn", "AsyncEvidenceStore::append_with_binding");
    hit("fn", "AsyncEvidenceStore::append_idempotent");
    hit("fn", "AsyncEvidenceStore::append_idempotent_with_binding");
    hit("fn", "AsyncEvidenceStore::append_idempotent_outcome");
    hit(
        "fn",
        "AsyncEvidenceStore::append_idempotent_outcome_with_binding",
    );
    hit("fn", "AsyncEvidenceStore::durability");
    hit("type", "EvidenceAppendOutcome");
    hit("variant", "EvidenceAppendOutcome::Appended");
    hit("variant", "EvidenceAppendOutcome::IdempotentReplay");

    // 本仓内存/文件存储不产生 IdempotentReplay（该变体供远端/持久存储的消费者使用），
    // 这里用真实 receipt 构造，覆盖变体形状。
    let replay_probe = EvidenceAppendOutcome::IdempotentReplay(
        EvidenceStore::append(&store, &raw_record("memory-replay-probe"))
            .expect("探针追加必须成功"),
    );
    assert!(matches!(
        replay_probe,
        EvidenceAppendOutcome::IdempotentReplay(_)
    ));

    let async_store = MemoryEvidenceStore::new();
    let async_record = EvidenceRecord::new(
        "memory-b",
        "0.2.0",
        digest("snapshot-b"),
        vec!["batch-1".to_owned()],
        digest("result-b"),
        "rejected",
    )
    .expect("记录构造必须成功");

    let async_bound = raw_record("memory-e");
    let _ = AsyncEvidenceStore::append_with_binding(&async_store, &async_bound, &binding)
        .await
        .expect("绑定追加必须成功");
    match async_store
        .append_idempotent_outcome(&async_record)
        .await
        .expect("outcome 追加必须成功")
    {
        EvidenceAppendOutcome::Appended(receipt) => {
            assert!(receipt.seq >= 1, "追加序号必须从 1 起")
        }
        other => panic!("首次追加必须判为 Appended，实际 {other:?}"),
    }
    match async_store
        .append_idempotent_outcome(&async_record)
        .await
        .expect("outcome 重放必须成功")
    {
        EvidenceAppendOutcome::Appended(receipt)
        | EvidenceAppendOutcome::IdempotentReplay(receipt) => {
            assert!(receipt.seq >= 1, "追加必须回传真实序号")
        }
        other => panic!("未预期的追加结果 {other:?}"),
    }
    match async_store
        .append_idempotent_outcome_with_binding(&async_bound, &binding)
        .await
        .expect("outcome 绑定追加必须成功")
    {
        EvidenceAppendOutcome::Appended(receipt)
        | EvidenceAppendOutcome::IdempotentReplay(receipt) => {
            assert!(receipt.binding.is_some(), "带绑定追加必须回传绑定")
        }
        other => panic!("应判为重放，实际 {other:?}"),
    }

    let _ = AsyncEvidenceStore::append(&async_store, &raw_record("memory-c"))
        .await
        .expect("async append 必须成功");
    let _ =
        AsyncEvidenceStore::append_with_binding(&async_store, &raw_record("memory-d"), &binding)
            .await
            .expect("async append_with_binding 必须成功");
    let _ = AsyncEvidenceStore::append_idempotent(&async_store, &async_record)
        .await
        .expect("async append_idempotent 必须成功");
    let _ =
        AsyncEvidenceStore::append_idempotent_with_binding(&async_store, &async_bound, &binding)
            .await
            .expect("async append_idempotent_with_binding 必须成功");
    assert_eq!(
        AsyncEvidenceStore::durability(&async_store),
        EvidenceDurability::Volatile,
        "异步视图必须与同步视图同口径"
    );

    hit("variant", "EvidenceDurability::LocalDurable");
    hit("variant", "EvidenceDurability::RemoteDurable");
    let _ = (
        EvidenceDurability::LocalDurable,
        EvidenceDurability::RemoteDurable,
    );

    hit("fn", "MemoryEvidenceStore::close");
    store.close().expect("close 必须成功");
}

/// 文件存储：真实临时文件上的落盘 → 迭代 → 分页 → 重新解析闭环。
fn phase_file_store() {
    hit("type", "FileEvidenceStore");
    hit("fn", "FileEvidenceStore::open");
    hit("fn", "FileEvidenceStore::path");
    hit("fn", "FileEvidenceStore::entry_count");
    hit("fn", "FileEvidenceStore::entries");
    hit("fn", "FileEvidenceStore::was_truncated_on_open");
    hit("type", "FileEvidenceIter");
    hit("fn", "FileEvidenceIter::open");
    hit("fn", "FileEvidenceIter::parsed_count");
    hit("fn", "read_entries_page");
    hit("fn", "parse_line");

    let dir = tempfile::tempdir().expect("临时目录必须可创建");
    let path = dir.path().join("evidence.jsonl");
    std::fs::File::create(&path)
        .expect("证据文件必须可创建")
        .flush()
        .expect("刷新必须成功");

    let store = FileEvidenceStore::open(&path).expect("文件存储必须可打开");
    assert_eq!(
        store.path(),
        std::fs::canonicalize(&path).expect("路径必须可规范化")
    );
    assert!(!store.was_truncated_on_open(), "全新文件不应触发截断标记");

    let record = EvidenceRecord::new(
        "file-a",
        "0.2.0",
        digest("snapshot"),
        vec!["batch-1".to_owned()],
        digest("result"),
        "accepted",
    )
    .expect("记录构造必须成功");
    let binding = ReceiptBinding::new(commit("commit"), "development", digest("artifact"))
        .expect("绑定构造必须成功");
    EvidenceStore::append_with_binding(&store, &record, &binding).expect("文件追加必须成功");

    assert_eq!(store.entry_count().expect("entry_count 必须成功"), 1);
    assert_eq!(store.entries().expect("entries 必须成功").len(), 1);

    // 同一路径独占打开：迭代器与分页读取必须在 store 释放后进行。
    drop(store);

    let mut iter = FileEvidenceIter::open(&path).expect("迭代器必须可打开");
    for item in &mut iter {
        let receipt: AppendReceipt = item.expect("迭代项必须可解析");
        assert_eq!(receipt.record.event, "file-a");
    }
    assert_eq!(iter.parsed_count(), 1, "迭代必须只解析出一条");

    drop(iter);

    let page = read_entries_page(&path, 0, 10).expect("分页读取必须成功");
    assert_eq!(page.len(), 1);
    assert!(read_entries_page(&path, 5, 10)
        .expect("越界分页必须成功")
        .is_empty());

    let raw = std::fs::read_to_string(&path).expect("文件必须可读");
    let first_line = raw.lines().next().expect("至少一行");
    let parsed = parse_line(first_line).expect("落盘行必须可重新解析");
    assert_eq!(parsed.record.event, "file-a");
    assert!(parsed.binding.is_some());

    hit("type", "ImmutableBinding");
    hit("fn", "ImmutableBinding::canonical_bytes");
    hit("fn", "ImmutableBinding::source_commit");
    hit("fn", "ImmutableBinding::schema");
    hit("fn", "ImmutableBinding::environment");
    hit("fn", "ImmutableBinding::artifact_digest");
    hit("fn", "ImmutableBinding::owner_signature");
    hit("const", "IMMUTABLE_BINDING_SCHEMA");

    let immutable = ImmutableBinding::sign(
        "owner-1",
        commit("commit"),
        IMMUTABLE_BINDING_SCHEMA,
        "development",
        digest("artifact"),
    )
    .expect("不可变绑定签发必须成功");
    assert_eq!(immutable.source_commit().len(), 40);
    assert_eq!(immutable.schema(), IMMUTABLE_BINDING_SCHEMA);
    assert_eq!(immutable.environment(), "development");
    assert_eq!(immutable.artifact_digest().len(), 64);
    assert_eq!(immutable.owner_signature().signer_id(), "owner-1");
    assert!(!immutable.canonical_bytes().is_empty());

    hit("type", "ResultUnknownReceipt");
    hit("variant", "EvidenceAppendOutcome::ResultUnknown");
    hit("field", "ResultUnknownReceipt::operation");
    hit("field", "ResultUnknownReceipt::reason");
    hit("field", "ResultUnknownReceipt::record");
    hit("field", "ResultUnknownReceipt::record_key");
    let unknown = ResultUnknownReceipt {
        operation: "append".to_owned(),
        reason: "transport reset".to_owned(),
        record: raw_record("file-b"),
        record_key: "file-b".to_owned(),
    };
    assert_eq!(unknown.operation, "append");
    assert_eq!(unknown.reason, "transport reset");
    assert_eq!(unknown.record.event, "file-b");
    assert_eq!(unknown.record_key, "file-b");
    let outcome = EvidenceAppendOutcome::ResultUnknown(unknown);
    assert!(matches!(outcome, EvidenceAppendOutcome::ResultUnknown(_)));
}

/// `EvidenceResult` 别名可用（`type` 条目落地）。
fn typed_result() -> EvidenceResult<usize> {
    Ok(1)
}

/// 单一驱动用例：保证阶段顺序与覆盖断言在同一个进程内完成。
#[tokio::test]
async fn e2e_evidence_all_public_api() {
    assert_manifest_wellformed();
    phase_error_variants();
    phase_record_and_binding();
    phase_signing();
    phase_lineage();
    phase_memory_store().await;
    phase_file_store();
    hit("type", "EvidenceResult");
    assert_eq!(typed_result().expect("别名结果必须可用"), 1);
    assert_coverage_complete();
}
