# evidence

`evidence` 是一个**零业务依赖**的审计证据追加面 crate：把领域无关的 provenance、
输入快照、原始批次与结果摘要固化成可复验的追加记录，并提供本地 durable 文件存储。

- 统一错误模型：`EvidenceError` / `EvidenceResult`
- 追加 seam：`EvidenceStore`（同步）与 `AsyncEvidenceStore`（远程持久化 port）
- 可判定结果：`EvidenceAppendOutcome` 区分「已确认新增 / 幂等重放 / 远程结果未知」
- 显式持久性能力：`EvidenceDurability::{Volatile, LocalDurable, RemoteDurable}`
- 本地实现：行协议 `seq<TAB>canonical_record`，追加后 `flush` + `sync_data`，
  重开时校验并恢复序号；原子 sidecar writer lock 拒绝跨进程并发 opener
- 完整性原语：SHA-256 摘要、canonical 签名、lineage / composition 校验

## 安装

```bash
cargo add evidence
```

## 最小可运行示例

```rust,no_run
use evidence::{EvidenceRecord, EvidenceStore, FileEvidenceStore, ReceiptBinding, sha256_hex};

fn main() -> evidence::EvidenceResult<()> {
    // 1) 打开（或创建）本地 durable 存储
    let store = FileEvidenceStore::open("audit.log")?;

    // 2) 组装一条领域无关的证据记录并校验
    let record = EvidenceRecord::new(
        "regime_decision",                                   // event
        env!("CARGO_PKG_VERSION"),                           // code_version
        "snapshot-2026-09-21",                               // input_snapshot
        vec!["fred-batch-001".into()],                       // raw_batch_ids
        sha256_hex(b"{\"outcome\":\"accepted\"}"),            // result_digest
        "accepted",                                          // outcome
    )?;

    // 3) 附带 B1 receipt 绑定（commit / environment / artifact 摘要）
    let binding = ReceiptBinding::new(
        "0000000000000000000000000000000000000001",
        "production",
        sha256_hex(b"artifacts"),
    )?;

    let receipt = store.append_with_binding(&record, &binding)?;
    println!("追加序号 = {}", receipt.seq);
    Ok(())
}
```

## 能力矩阵

| 类型 | 作用 |
| --- | --- |
| `EvidenceRecord` | 领域无关证据记录（event / code_version / snapshot / batches / digest / outcome） |
| `ReceiptBinding` | B1 生产绑定：40 位 commit + environment + artifact 摘要 |
| `AppendReceipt` / `ResultUnknownReceipt` | 追加回执 / 结果未知回执 |
| `EvidenceAppendOutcome` | `Appended` / `IdempotentReplay` / `ResultUnknown` |
| `EvidenceDurability` | `Volatile` / `LocalDurable` / `RemoteDurable` |
| `EvidenceStore` / `AsyncEvidenceStore` | 追加 seam（同步 / 远程异步 port） |
| `MemoryEvidenceStore` | 进程内实现，`Volatile`，仅供开发与确定性测试 |
| `FileEvidenceStore` | 本地行协议 durable 实现 |
| `EvidenceReader` | 只读查询面（`len` / `is_empty` / `get` / `find_by_record`） |
| `SigningKey` / `ProtectedSignature` / `verify_approval` | canonical 签名与审批角色校验 |
| `LineageBinding` / `verify_lineage` / `verify_composition` | 溯源绑定与决策合成校验 |
| `sha256_hex` / `parse_line` / `artifact_manifest_digest` | 摘要、行解析与 artifact 清单摘要 |

## 本地 durable 边界

`FileEvidenceStore` 的写入路径为「追加 → `flush` → `sync_data`」，重新打开时会逐行校验并
从最大序号继续。跨进程互斥由原子 sidecar writer lock 提供：

- Unix 上锁键使用文件 owner 对应的 `/run/user/<uid>` 或 `/var/run/user/<uid>` inode 命名空间
  （均不可用时回退 `/tmp`）；非 Unix 使用 `<path>.evidence-writer-lock`
- 进程异常退出后**不**擅自判断锁是否过期，残留锁保持 fail-closed，必须由受控运维流程清理
- 它只保证同一受控文件系统上协作进程的互斥，**不**提供跨主机 / NFS 锁语义

## 非目标

本 crate 不是独立 verifier、签名链、备份恢复系统或合规审计产品；远程数据库实现由
消费方自持有的 adapter 提供（`AsyncEvidenceStore` 即该 seam）。它不提供生产 provider/API、
owner/reviewer 签署流程、不可变存储或跨主机一致性。

## 门禁

```bash
cargo fmt --check
cargo clippy --all-targets -- -D warnings
cargo test
EVIDENCE_LIVE_PROFILE=production cargo run --example evidence_basic
```

## 许可

MIT OR Apache-2.0
