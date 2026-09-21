# evidence 公开 API

**版本 / 角色**：`evidence 0.1.0` · L1 审计证据追加面（记录 + 追加 + 只读查询 + 完整性原语）

全部条目一经发布即视为稳定面；字段私有类型只能经其构造 / 签名函数得到合法实例。

## 常量

- `RECORD_SCHEMA = "evidence-record/v1"`：结构化记录行的 wire schema。
- `BINDING_SCHEMA = "evidence-binding/v1"`：B1 最小生产 receipt 绑定行的 wire schema。
- `IMMUTABLE_BINDING_SCHEMA = "evidence-immutable-binding/v1"`：B3 不可变 binding 的 wire schema。

## 类型别名与错误

- `EvidenceResult<T> = Result<T, EvidenceError>`。
- `EvidenceError`（`thiserror` 枚举）：`EmptyField` / `InvalidCharacter` / `InvalidDigest` /
  `LockPoisoned` / `Closed` / `IdempotencyUnsupported` / `Durability` / `PathAlreadyOpen` /
  `InvalidWire` / `Remote` / `BindingUnsupported` / `BindingMismatch` / `SignatureInvalid` /
  `EmptySignerId` / `InvalidApprovalRole` / `LineageInvalid`。

## 记录模型

- `EvidenceRecord`：六字段领域无关决策证据；`new`（构造并校验）、`canonical_line`、
  `canonical_bytes`。
- `ReceiptBinding`：B1 生产绑定（commit / environment / artifact 摘要）；`new`、`canonical_line`。
- `artifact_manifest_digest(artifacts)`：按路径排序后计算确定性 artifact 摘要。

## 追加面

- `EvidenceStore`（trait）：`durability`（默认 `Volatile`）、`append`；
  `append_idempotent`（默认 `IdempotencyUnsupported`）、`append_with_binding`、
  `append_idempotent_with_binding`（默认均 `BindingUnsupported`）。
- `AsyncEvidenceStore`（trait）：与同步面并列的远程异步 port，含
  `append_idempotent_outcome` / `append_idempotent_outcome_with_binding` 以保留
  `Appended` / `IdempotentReplay` / `ResultUnknown` 区分；同步实现自动获得异步兼容桥。
- `MemoryEvidenceStore`：`Volatile` 进程内实现；`new`、`entries`、`close`。
- `FileEvidenceStore`：`LocalDurable` 本地行协议实现；`open`（fail-closed 跨进程 writer 锁）、
  `path`、`entries`。

## 回执与结局

- `AppendReceipt`：`seq` / `record` / 可选 `binding`。
- `ResultUnknownReceipt`：`record_key` / `record` / `operation` / `reason`。
- `EvidenceAppendOutcome`：`Appended` / `IdempotentReplay` / `ResultUnknown`。
- `EvidenceDurability`：`Volatile` / `LocalDurable` / `RemoteDurable`。

## 只读查询

- `EvidenceReader`（trait）：`len`、`is_empty`、`get(seq)`、`find_by_record`；
  `MemoryEvidenceStore` 与 `FileEvidenceStore` 均已实现。

## 完整性原语

- `sha256_hex(payload)`：小写 SHA-256 摘要。
- `parse_line(line)`：解析带序号的 Evidence 行（record 的逆运算）。
- 签名：`SigningKey`（注入点）、`TestSigningKey`（**测试专用，禁止生产**）、
  `SignatureRole`（`Owner` / `Reviewer`）、`ProtectedSignature`（字段私有）、
  `sign_canonical`、`verify_canonical`、`verify_approval`。
- 不可变 binding：`ImmutableBinding`（`sign` / `verify` / 访问器）、`verify_binding`。
- 溯源：`LineageBinding`（`new` + 访问器）、`DecisionComposition`（`new` + 访问器）、
  `verify_lineage`、`verify_composition`。

## 最小示例

```rust
use evidence::{sha256_hex, EvidenceRecord, EvidenceStore, MemoryEvidenceStore};

let store = MemoryEvidenceStore::new();
let record = EvidenceRecord::new(
    "regime_decision",
    env!("CARGO_PKG_VERSION"),
    "snapshot-2026-09-22",
    vec!["fred-batch-001".into()],
    sha256_hex(b"{\"outcome\":\"accepted\"}"),
    "accepted",
)?;
let receipt = store.append(&record)?;
assert_eq!(receipt.seq, 1);
# Ok::<(), evidence::EvidenceError>(())
```

`FileEvidenceStore` 用法见 crate 文档与 `examples/evidence_basic.rs`。
