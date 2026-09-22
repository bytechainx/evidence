# Changelog — evidence

本文件记录 `evidence` 的用户可见变更，遵循 [Keep a Changelog](https://keepachangelog.com/)
与 [Semantic Versioning](https://semver.org/)。

本仓库代码自 `xhyper.rs` 的 `crates/infra/evidence` 抽取而来（抽取时点为 `0.1.14`）。
该工程内的版本线不在本文件中延续，本仓库从 `0.1.0` 重新起算。

## [Unreleased]

### 新增

- `FileEvidenceIter`：流式证据文件条目迭代器，逐行解析行协议文件而不一次性加载全量到内存。
  适合长期运行审计容器在内存受限场景下对大审计文件做分页查询。
- `read_entries_page(path, offset, limit)`：按分页读取文件条目，跳过 `offset` 条后取最多 `limit` 条。
- 回归测试 5 项：全量迭代正确性、与 `entries()` 结果一致性、分页边界、空文件、解析计数。

### 变更

- `EvidenceError` 标记 `#[non_exhaustive]`：下游穷举 match 需加通配臂，新增变体不再视为 PATCH 兼容。
- `FileProcessLock` 与 `pid_is_alive` 文档补充非 Linux 平台陈旧锁手动清理流程说明。

## [0.1.1] - 2026-09-22

### 新增

- 特性 002 三类测试：`tests/tdd_contracts.rs`（10 个公开入口的行为契约与 TDD-PROBE 红绿表）、
  `tests/sdd_spec.rs`（`docs/标准.md` 五章节 1:1 对照断言）、
  `tests/aidd_boundary.rs`（7 条对抗 / 边界用例，含并发序号守恒与文件 fail-closed）。
- `docs/标准.md`（定位 / 数据模型 / 追加语义 / 完整性 / 验收条款）与
  `docs/API.md`（公开面清单与最小示例）。

### 变更

- **内部结构改写（公开 API 与可观察契约均不变）**：按 `docs/module-rules.md` §5.5 的手法，把进程内
  实现与行协议原语从 `src/lib.rs` 下沉为独立子模块 —— 内存 store → `src/memory.rs`、行协议编解码 /
  字段校验 / 摘要原语 → `src/wire.rs`。门面 `src/lib.rs` 保留 crate 文档、`EvidenceError`、全部 DTO、
  `EvidenceStore` / `AsyncEvidenceStore` 两个 seam 与 `idempotent_lookup`。
  `MemoryEvidenceStore` / `parse_line` / `sha256_hex` 仍经 crate 根 `pub use` 导出，
  `receipt_line` 与三个 `validate_*` 以 `pub(crate)` 转出，**公开路径与 crate 内部路径均不变**。
  `src/lib.rs` 生产段由 **728 → 474** 行（`src/memory.rs` 149、`src/wire.rs` 134）。
  动机：`module-rules` 是元仓库必需检查，且它审计各仓**默认分支**，故当 `lib.rs` 生产段距
  `MR-STRUCT-007` 的 800 行 ERROR 阈值只剩 72 行时，任一仓的任意改动都可能卡住元仓库的全部 PR。
  属**纯搬移**（行多重集比对确认零代码行丢失），全部 73 项测试与 doctest 结果不变。

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
