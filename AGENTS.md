# evidence Agent 指南

> 本文件为 AI Agent 在本仓库工作时的入口指南。

## 项目定位

L1 审计证据追加面：领域无关的结构化 provenance（`EvidenceRecord`）、幂等 receipt 绑定与本地 durable 文件存储（`FileEvidenceStore` / `MemoryEvidenceStore`），返回可复验的追加序号。

## 技术栈

- Rust edition 2021, rust-version 1.71
- 关键依赖: `async-trait`（异步追加面）、`sha2`（SHA-256 摘要）、`thiserror`（类型化错误）
- dev-dependencies: `tempfile`（测试用临时文件）
- 零内部耦合：不依赖任何业务域或应用 crate

## 代码结构

```text
src/
├── lib.rs      # 核心面：EvidenceRecord / ReceiptBinding / AppendReceipt / 可判定 outcome 与持久性能力、
│               # EvidenceStore 与 AsyncEvidenceStore 两个 seam、idempotent_lookup
├── memory.rs   # 进程内实现：MemoryEvidenceStore（仅开发与确定性测试）
├── wire.rs     # 行协议编解码 / 字段校验 / 摘要原语：parse_line、receipt_line、sha256_hex、validate_*
├── file.rs     # 本地行协议持久化：FileEvidenceStore（文件 I/O、跨进程 writer 锁、active-file 去重）
├── binding.rs  # B1 receipt 绑定：ReceiptBinding 校验、ImmutableBinding、verify_binding
├── lineage.rs  # 组合溯源：LineageBinding、DecisionComposition、verify_lineage / verify_composition
├── query.rs    # 读取面：EvidenceReader
└── sign.rs     # 签名/校验相关导出
tests/
├── record_store.rs  # 记录与存储行为测试
├── query_sign.rs    # 查询与签名测试
└── fixtures/        # 测试夹具
examples/
└── evidence_basic.rs
benches/
└── hot_path.rs      # 热路径基准（harness = false，支持 --quick）
docs/
└── README.md
```

## 开发约定

- 注释与文档使用简体中文；标识符保持英文
- 错误：thiserror 枚举（`EvidenceError`）+ `EvidenceResult` 别名，保留 source 链
- 禁止裸 `unwrap()`（库代码；crate 级 `[lints.clippy]` 已 deny `unwrap_used` / `expect_used` / `panic` / `unreachable` / `todo` / `unimplemented`）
- `#![forbid(unsafe_code)]`
- `#![deny(missing_docs)]`
- `append` 的幂等键是记录的规范化行（canonical line），修改 `canonical_line` 格式属于 breaking change（wire 兼容）
- 远程追加失败不得当作成功；不确定状态使用 `ResultUnknownReceipt` 语义

## 门禁三件套（P0）

```bash
cargo fmt --all -- --check
cargo clippy --all-targets -- -D warnings
cargo test --all-targets
```

基准（可选）：

```bash
cargo bench --bench hot_path          # 完整
cargo run --release --bench hot_path -- --quick   # 快速
```

## 相关文档

- 组织 Rust 规范：`~/org-config/rulesets/rust/RULES.md`
- API 文档：`docs/README.md`
- 术语与领域语言：`CONTEXT.md`
- 贡献指南：`CONTRIBUTING.md`
- 变更记录：`CHANGELOG.md`
- 基准测试：`benches/hot_path.rs`
