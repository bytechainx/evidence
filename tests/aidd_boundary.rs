#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::unreachable
)]
//! AIDD 对抗 / 边界用例（特性 002）。
//!
//! 候选由 AI 生成，逐条人工复核后仅保留「结论=保留」项；丢弃项登记于 PR 描述。
//!
//! // AIDD: 记录字段含行协议保留字符 | 来源=AI | 复核=ZoneCNH/2026-09-22 | 依据=标准.md §2 行协议保留字符禁令 | 结论=保留
//! // AIDD: 批次标识含逗号（列表分隔符注入） | 来源=AI | 复核=ZoneCNH/2026-09-22 | 依据=标准.md §2 raw_batch_ids 额外禁逗号 | 结论=保留
//! // AIDD: 摘要用大写十六进制 | 来源=AI | 复核=ZoneCNH/2026-09-22 | 依据=标准.md §2 仅要求 64 位 ASCII 十六进制 | 结论=保留
//! // AIDD: 行序号取 u64::MAX | 来源=AI | 复核=ZoneCNH/2026-09-22 | 依据=标准.md §4 parse_line 接受任意非零序号 | 结论=保留
//! // AIDD: 文件重开时序号回退（非严格递增） | 来源=AI | 复核=ZoneCNH/2026-09-22 | 依据=标准.md §3 重开逐行校验并严格递增 | 结论=保留
//! // AIDD: 多线程并发追加同一内存 store | 来源=AI | 复核=ZoneCNH/2026-09-22 | 依据=标准.md §3 序号单调且唯一 | 结论=保留
//! // AIDD: 空 payload 签名 | 来源=AI | 复核=ZoneCNH/2026-09-22 | 依据=标准.md §4 仅空 signer_id 被拒 | 结论=保留

use std::collections::BTreeSet;
use std::sync::Arc;

use evidence::{
    parse_line, sha256_hex, sign_canonical, verify_canonical, EvidenceError, EvidenceRecord,
    EvidenceStore, FileEvidenceStore, MemoryEvidenceStore, SignatureRole, TestSigningKey,
};

fn record(snapshot: &str, batch: &str) -> EvidenceRecord {
    EvidenceRecord::new(
        "regime_decision",
        "commit-aidd-002",
        snapshot,
        vec![batch.into()],
        sha256_hex(format!("decision:{snapshot}").as_bytes()),
        "accepted",
    )
    .expect("夹具记录有效")
}

/// 边界：字段含行协议保留字符——必须被拒绝，不得进入行协议。
#[test]
fn record_rejects_reserved_wire_chars() {
    for bad in ["ev\rent", "ev\nnt", "ev\tnt", "ev|nt"] {
        assert!(
            matches!(
                EvidenceRecord::new(bad, "c", "s", vec!["b".into()], sha256_hex(b"x"), "o"),
                Err(EvidenceError::InvalidCharacter("event"))
            ),
            "含保留字符的 event 必须被拒绝：{bad:?}"
        );
    }
}

/// 边界：批次标识含逗号——逗号是列表分隔符，必须被拒绝。
#[test]
fn batch_id_comma_is_rejected() {
    assert!(matches!(
        EvidenceRecord::new("e", "c", "s", vec!["a,b".into()], sha256_hex(b"x"), "o"),
        Err(EvidenceError::InvalidCharacter("raw_batch_id"))
    ));
    // 合法批次仍可含其他可见字符。
    assert!(!record("snapshot-batch", "batch/with:colon")
        .canonical_line()
        .is_empty());
}

/// 边界：64 位大写十六进制摘要——只要求 ASCII 十六进制，应被接受。
#[test]
fn uppercase_digest_is_accepted() {
    let uppercase = "A".repeat(64);
    let record = EvidenceRecord::new("e", "c", "s", vec!["b".into()], &uppercase, "o")
        .expect("大写十六进制摘要应被接受");
    assert_eq!(record.result_digest, uppercase);
}

/// 边界：行序号取 u64::MAX——合法非零序号，可解析且原样保留。
#[test]
fn parse_line_accepts_max_seq() {
    let expected = record("snapshot-max-seq", "batch-max");
    let line = format!("{}\t{}", u64::MAX, expected.canonical_line());
    let parsed = parse_line(&line).expect("u64::MAX 序号应可解析");
    assert_eq!(parsed.seq, u64::MAX);
    assert_eq!(parsed.record, expected);
}

/// 边界：文件重开时序号回退——必须 fail-closed，不得静默接受。
#[test]
fn file_reopen_rejects_non_monotonic_seq() {
    let directory = tempfile::tempdir().expect("临时目录");
    let path = directory.path().join("non-monotonic.log");
    let first = record("snapshot-1", "batch-1");
    let second = record("snapshot-2", "batch-2");
    // 手工构造 seq 2 后接 seq 1 的非法文件。
    let content = format!(
        "2\t{}\n1\t{}\n",
        second.canonical_line(),
        first.canonical_line()
    );
    std::fs::write(&path, content).expect("写入非法行协议文件");

    assert!(matches!(
        FileEvidenceStore::open(&path),
        Err(EvidenceError::InvalidWire(_))
    ));
}

/// 边界：多线程并发追加同一内存 store——序号集合必须恰好为 1..=N。
#[test]
fn concurrent_memory_append_is_unique() {
    const THREADS: usize = 8;
    const PER_THREAD: usize = 16;
    let store = Arc::new(MemoryEvidenceStore::new());
    let mut handles = Vec::new();
    for thread_id in 0..THREADS {
        let store = Arc::clone(&store);
        handles.push(std::thread::spawn(move || {
            let mut seqs = Vec::new();
            for item in 0..PER_THREAD {
                let record = record(
                    &format!("snapshot-{thread_id}-{item}"),
                    &format!("batch-{thread_id}"),
                );
                seqs.push(store.append(&record).expect("并发追加").seq);
            }
            seqs
        }));
    }
    let mut all: Vec<u64> = Vec::new();
    for handle in handles {
        all.extend(handle.join().expect("线程"));
    }
    let unique: BTreeSet<u64> = all.iter().copied().collect();
    assert_eq!(all.len(), THREADS * PER_THREAD);
    assert_eq!(unique.len(), THREADS * PER_THREAD, "序号不得重复");
    assert_eq!(
        unique.into_iter().collect::<Vec<_>>(),
        (1..=(THREADS * PER_THREAD) as u64).collect::<Vec<_>>(),
        "序号集合应为连续的 1..=N"
    );
}

/// 边界：空 payload 签名——仅空 signer_id 被拒，空 payload 合法且可验签。
#[test]
fn signature_accepts_empty_payload() {
    let signature = sign_canonical(&TestSigningKey, SignatureRole::Owner, "owner-aidd", b"")
        .expect("空 payload 应可签名");
    verify_canonical(&TestSigningKey, &signature, b"").expect("空 payload 验签通过");
    assert!(matches!(
        verify_canonical(&TestSigningKey, &signature, b"x"),
        Err(EvidenceError::SignatureInvalid)
    ));
}
