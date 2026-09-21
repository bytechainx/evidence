# Changelog — evidence

本文件记录 `evidence` 的用户可见变更，遵循 [Keep a Changelog](https://keepachangelog.com/)
与 [Semantic Versioning](https://semver.org/)。

本仓库代码自 `xhyper.rs` 的 `crates/infra/evidence` 抽取而来（抽取时点为 `0.1.14`）。
该工程内的版本线不在本文件中延续，本仓库从 `0.1.0` 重新起算。

## [Unreleased]

## [0.1.0] - 2026-09-21

### 新增

- 领域无关的证据记录 `EvidenceRecord`：固化 event / code_version / input_snapshot /
  raw_batch_ids / result_digest / outcome，并给出可校验的规范化行 `canonical_line`。
- 追加 seam：同步 `EvidenceStore` 与远程异步 port `AsyncEvidenceStore`，均返回可复验的
  `AppendReceipt`（单调追加序号 + 完整记录 + 可选 `ReceiptBinding`）。
- 可判定追加结局 `EvidenceAppendOutcome`：区分 `Appended` / `IdempotentReplay` /
  `ResultUnknown`，远程无法确认提交状态时不再伪装成失败或成功。
- 显式持久性能力 `EvidenceDurability::{Volatile, LocalDurable, RemoteDurable}`，由实现声明、
  调用方据此决定能否用于生产路径。
- 本地实现：`FileEvidenceStore` 使用行协议 `seq<TAB>canonical_record`，追加后 `flush` +
  `sync_data`，重开时逐行校验并从最大序号继续；原子 sidecar writer lock 拒绝跨进程并发 opener。
- `MemoryEvidenceStore`（`Volatile`，供开发与确定性测试）与只读查询面 `EvidenceReader`
  （`len` / `is_empty` / `get` / `find_by_record`）。
- 完整性原语：`sha256_hex`、`artifact_manifest_digest`、canonical 签名
  （`sign_canonical` / `verify_canonical` / `verify_approval`）、不可变 binding
  （`ImmutableBinding` / `verify_binding`）与溯源校验（`LineageBinding` /
  `DecisionComposition` / `verify_lineage` / `verify_composition`）。

### 变更

- 抽取为独立 crate 并下沉重构错误模型：错误统一为 crate 内 `src/lib.rs` 的 `EvidenceError`
  与 `EvidenceResult` 别名，不再依赖 `kernel` / `contracts` 等主工程内部 crate。
- 公开 API 收敛为「记录 + 追加 + 只读查询」三段面，领域 DTO 与 provenance 的所有权留在领域层，
  本 crate 不复制业务 DTO、不形成反向业务依赖。

### 说明

- **不是**独立 verifier、签名链、备份恢复系统或合规审计产品；远程数据库实现由消费方自持有的
  adapter 提供（`AsyncEvidenceStore` 即该 seam）。
- 当前只提供本地 durable 文件适配器、测试用内存适配器与异步远程 port；生产密钥 provider、
  查询授权、不可抵赖与跨主机一致性不在本 crate 范围内。
- 锁残留为 **fail-closed**：异常退出后不猜测锁是否过期，必须由受控运维流程清理。
- 本 crate **不发布到 crates.io**，仅以 GitHub 源码 / git 依赖形式复用。
