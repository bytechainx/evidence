//! L1 审计证据追加面的结构化 provenance 与本地持久化接口。
//!
//! `EvidenceStore` 只负责接收领域无关的、已经完成决策的证据记录，并返回
//! 可复验的追加序号。领域 crate 保留决策 DTO 与 provenance 的所有权；本 crate
//! **不依赖任何业务域或应用 crate**，因此不会形成反向业务依赖。
//!
//! # 最小示例
//!
//! ```no_run
//! use evidence::{EvidenceRecord, EvidenceStore, FileEvidenceStore, ReceiptBinding, sha256_hex};
//!
//! fn main() -> evidence::EvidenceResult<()> {
//!     let store = FileEvidenceStore::open("audit.log")?;
//!
//!     let record = EvidenceRecord::new(
//!         "regime_decision",
//!         env!("CARGO_PKG_VERSION"),
//!         "snapshot-2026-09-21",
//!         vec!["fred-batch-001".into()],
//!         sha256_hex(b"{\"outcome\":\"accepted\"}"),
//!         "accepted",
//!     )?;
//!
//!     let binding = ReceiptBinding::new(
//!         "0000000000000000000000000000000000000001",
//!         "production",
//!         sha256_hex(b"artifacts"),
//!     )?;
//!
//!     let receipt = store.append_with_binding(&record, &binding)?;
//!     assert_eq!(receipt.seq, 1);
//!     Ok(())
//! }
//! ```

#![cfg_attr(
    test,
    allow(
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::panic,
        clippy::unreachable
    )
)]
#![forbid(unsafe_code)]
#![deny(missing_docs)]
#![deny(unreachable_pub)]

use std::io;

use thiserror::Error;

/// 当前结构化 Evidence 行记录的 wire schema。
pub const RECORD_SCHEMA: &str = "evidence-record/v1";

/// B1 最小生产 receipt 绑定行的 wire schema。
pub const BINDING_SCHEMA: &str = "evidence-binding/v1";

/// crate 专用 `Result` 别名。
pub type EvidenceResult<T> = Result<T, EvidenceError>;

/// Evidence 追加错误。
///
/// 此枚举标记为 [`non_exhaustive`]：下游穷举 match 必须包含通配臂。
/// 新增变体不再视为 PATCH 级兼容变更。
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum EvidenceError {
    /// 必填字段为空。
    #[error("证据记录字段为空：{0}")]
    EmptyField(&'static str),
    /// 字段包含行协议保留字符。
    #[error("证据记录字段包含非法字符：{0}")]
    InvalidCharacter(&'static str),
    /// 结果摘要不是规范的 SHA-256 文本。
    #[error("证据记录摘要必须是 64 位十六进制：{0}")]
    InvalidDigest(&'static str),
    /// 存储锁不可用。
    #[error("证据存储锁不可用")]
    LockPoisoned,
    /// 存储已经关闭。
    #[error("证据存储已关闭")]
    Closed,
    /// 存储适配器没有提供幂等追加能力。
    #[error("证据存储不支持幂等追加")]
    IdempotencyUnsupported,
    /// 本地文件持久化失败。
    #[error("证据持久化失败：{0}")]
    Durability(#[source] io::Error),
    /// 同一底层文件已经由当前进程中的另一个 store 占用。
    #[error("证据文件已由另一个 store 打开")]
    PathAlreadyOpen,
    /// 行协议内容无效。
    #[error("证据 wire 无效：{0}")]
    InvalidWire(String),
    /// 远程 Evidence 持久化失败。
    #[error("远程证据持久化失败：{0}")]
    Remote(String),
    /// 存储适配器未实现 B1 receipt 绑定追加。
    #[error("证据存储不支持 receipt 绑定追加")]
    BindingUnsupported,
    /// 同一幂等键已存在但 receipt 绑定不一致。
    #[error("证据 receipt 绑定与已有记录冲突")]
    BindingMismatch,
    /// 签名校验失败。
    #[error("证据签名校验失败")]
    SignatureInvalid,
    /// 签名者标识为空。
    #[error("签名者标识为空")]
    EmptySignerId,
    /// 审批签名角色错误（Owner 与 Reviewer 角色不符）。
    #[error("证据审批签名角色错误")]
    InvalidApprovalRole,
    /// B4 溯源绑定字段无效（PIT/lineage 等格式或一致性不符）。
    #[error("证据溯源绑定无效：{0}")]
    LineageInvalid(String),
}

mod binding;
mod file;
mod lineage;
mod memory;
mod query;
mod sign;
mod wire;

#[cfg(any(test, feature = "test-signing-key"))]
pub use binding::verify_binding;
pub use binding::{ImmutableBinding, IMMUTABLE_BINDING_SCHEMA};
pub use file::{read_entries_page, FileEvidenceIter, FileEvidenceStore};
pub use lineage::{verify_composition, verify_lineage, DecisionComposition, LineageBinding};
pub use memory::MemoryEvidenceStore;
pub use query::EvidenceReader;
#[cfg(any(test, feature = "test-signing-key"))]
pub use sign::TestSigningKey;
pub use sign::{
    sign_canonical, verify_approval, verify_canonical, ProtectedSignature, SignatureRole,
    SigningKey,
};
pub use wire::{parse_line, sha256_hex};
// 行协议的序列化与字段校验原语：`src/file.rs` 与其它模块按 `crate::<name>` 复用，
// 故在此以 `pub(crate)` 转出，保持这些 crate 内部路径与拆分前一致。
pub(crate) use wire::{receipt_line, validate_commit, validate_component, validate_digest};

/// 一条与领域无关的决策证据。
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EvidenceRecord {
    /// 事件类型，例如 `regime_decision`。
    pub event: String,
    /// 产生该结果的代码版本或 commit 标识。
    pub code_version: String,
    /// 输入快照指纹；由输入域负责计算，本 crate 只负责固化。
    pub input_snapshot: String,
    /// 参与计算的原始批次标识，顺序具有确定性语义。
    pub raw_batch_ids: Vec<String>,
    /// 决策结果或 payload 的 SHA-256 摘要。
    pub result_digest: String,
    /// 结果状态，例如 `accepted` 或 `rejected`。
    pub outcome: String,
}

impl EvidenceRecord {
    /// 创建并校验一条 Evidence 记录。
    pub fn new(
        event: impl Into<String>,
        code_version: impl Into<String>,
        input_snapshot: impl Into<String>,
        raw_batch_ids: Vec<String>,
        result_digest: impl Into<String>,
        outcome: impl Into<String>,
    ) -> Result<Self, EvidenceError> {
        let record = Self {
            event: event.into(),
            code_version: code_version.into(),
            input_snapshot: input_snapshot.into(),
            raw_batch_ids,
            result_digest: result_digest.into(),
            outcome: outcome.into(),
        };
        record.validate()?;
        Ok(record)
    }

    /// 返回规范化的单行 payload，不包含追加序号和行结束符。
    #[must_use]
    pub fn canonical_line(&self) -> String {
        format!(
            "{RECORD_SCHEMA}|{}|{}|{}|{}|{}|{}",
            self.event,
            self.code_version,
            self.input_snapshot,
            self.raw_batch_ids.join(","),
            self.result_digest,
            self.outcome
        )
    }

    /// 返回用于摘要或签名的规范字节。
    #[must_use]
    pub fn canonical_bytes(&self) -> Vec<u8> {
        self.canonical_line().into_bytes()
    }

    fn validate(&self) -> Result<(), EvidenceError> {
        validate_component("event", &self.event, false)?;
        validate_component("code_version", &self.code_version, false)?;
        validate_component("input_snapshot", &self.input_snapshot, false)?;
        validate_component("outcome", &self.outcome, false)?;
        if self.raw_batch_ids.is_empty() {
            return Err(EvidenceError::EmptyField("raw_batch_ids"));
        }
        for batch_id in &self.raw_batch_ids {
            validate_component("raw_batch_id", batch_id, true)?;
        }
        validate_digest("result_digest", &self.result_digest)
    }
}

/// B1 最小生产 receipt 绑定：完整 commit、运行环境与 artifact 摘要。
///
/// 与 [`EvidenceRecord`] 解耦；由组合根在追加时注入，写入 durable receipt。
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ReceiptBinding {
    /// 产生该 receipt 的 40 位 Git commit（小写十六进制）。
    pub source_commit: String,
    /// 运行环境标识，例如 `development` / `staging` / `production`。
    pub environment: String,
    /// 参与决策的 artifact 清单摘要（64 位 SHA-256 十六进制）。
    pub artifact_digest: String,
}

impl ReceiptBinding {
    /// 创建并校验 B1 receipt 绑定。
    pub fn new(
        source_commit: impl Into<String>,
        environment: impl Into<String>,
        artifact_digest: impl Into<String>,
    ) -> Result<Self, EvidenceError> {
        let binding = Self {
            source_commit: source_commit.into(),
            environment: environment.into(),
            artifact_digest: artifact_digest.into(),
        };
        binding.validate()?;
        Ok(binding)
    }

    /// 返回规范化的绑定行 payload，不含序号与行结束符。
    #[must_use]
    pub fn canonical_line(&self) -> String {
        format!(
            "{BINDING_SCHEMA}|{}|{}|{}",
            self.source_commit, self.environment, self.artifact_digest
        )
    }

    fn validate(&self) -> Result<(), EvidenceError> {
        validate_commit("source_commit", &self.source_commit)?;
        validate_component("environment", &self.environment, false)?;
        validate_digest("artifact_digest", &self.artifact_digest)
    }
}

/// 根据 `(相对路径, SHA-256)` 列表计算确定性 artifact 摘要。
pub fn artifact_manifest_digest(mut artifacts: Vec<(&str, &str)>) -> Result<String, EvidenceError> {
    artifacts.sort_by_key(|(path, _)| *path);
    let mut payload = String::new();
    for (path, digest) in artifacts {
        validate_component("artifact_path", path, false)?;
        validate_digest("artifact_sha256", digest)?;
        payload.push_str(path);
        payload.push('\t');
        payload.push_str(digest);
        payload.push('\n');
    }
    Ok(sha256_hex(payload.as_bytes()))
}

/// 追加成功回执。
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AppendReceipt {
    /// 单调递增的本地追加序号，从 1 开始。
    pub seq: u64,
    /// 已经被追加的完整 Evidence 记录。
    pub record: EvidenceRecord,
    /// B1 生产 receipt 绑定；历史 v1 行协议无第三段时为 `None`。
    pub binding: Option<ReceiptBinding>,
}

/// 远程追加无法确认提交状态时返回的收据。
///
/// 收据本身不代表写入成功；调用方必须在远程服务恢复后使用其中的记录再次执行
/// 幂等追加或查询。它与已经确认的普通追加、幂等重放回执严格区分。
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ResultUnknownReceipt {
    /// 规范化 Evidence 记录的幂等键。
    pub record_key: String,
    /// 产生未知结果的完整记录，便于恢复流程原样重试。
    pub record: EvidenceRecord,
    /// 发生未知结果的操作名称。
    pub operation: String,
    /// 仅用于诊断的稳定错误摘要，不包含凭据。
    pub reason: String,
}

/// Evidence 追加的可判定结果。
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum EvidenceAppendOutcome {
    /// 本次请求已确认插入一条新记录。
    Appended(AppendReceipt),
    /// 本次请求确认复用了已有幂等记录。
    IdempotentReplay(AppendReceipt),
    /// 远程系统未能确认本次追加是否提交。
    ResultUnknown(ResultUnknownReceipt),
}

/// Evidence store 提供的持久性能力。
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EvidenceDurability {
    /// 仅进程内保存，进程退出后不可恢复。
    Volatile,
    /// 本地介质已执行追加 flush 与 sync；不代表远程高可用或合规审计。
    LocalDurable,
    /// 由远程持久化服务确认；具体数据库映射由 consumer-owned adapter 持有。
    RemoteDurable,
}

/// Evidence 追加面；领域与应用通过该 seam 注入实现。
pub trait EvidenceStore: Send + Sync {
    /// 返回该 store 能够提供的持久性能力。
    fn durability(&self) -> EvidenceDurability {
        EvidenceDurability::Volatile
    }

    /// 追加一条已经校验的 Evidence 记录。
    fn append(&self, record: &EvidenceRecord) -> Result<AppendReceipt, EvidenceError>;

    /// 以规范化记录作为幂等键追加 Evidence。
    ///
    /// 未实现该能力的适配器默认拒绝调用，避免调用方把普通追加误认为可重试。
    fn append_idempotent(&self, _record: &EvidenceRecord) -> Result<AppendReceipt, EvidenceError> {
        Err(EvidenceError::IdempotencyUnsupported)
    }

    /// 追加 Evidence 并写入 B1 receipt 绑定（commit / environment / artifact 摘要）。
    fn append_with_binding(
        &self,
        _record: &EvidenceRecord,
        _binding: &ReceiptBinding,
    ) -> Result<AppendReceipt, EvidenceError> {
        Err(EvidenceError::BindingUnsupported)
    }

    /// 幂等追加并写入 B1 receipt 绑定。
    fn append_idempotent_with_binding(
        &self,
        _record: &EvidenceRecord,
        _binding: &ReceiptBinding,
    ) -> Result<AppendReceipt, EvidenceError> {
        Err(EvidenceError::BindingUnsupported)
    }
}

/// 异步 Evidence 追加面，供远程持久化适配器使用。
///
/// 该 port 与同步 [`EvidenceStore`] 并列，避免让本地文件实现承担异步
/// runtime 依赖；实现方仍必须返回完整 [`AppendReceipt`]，调用方不得把
/// `append` 的网络错误当作成功。
#[async_trait::async_trait]
pub trait AsyncEvidenceStore: Send + Sync {
    /// 返回该 store 能够提供的持久性能力。
    fn durability(&self) -> EvidenceDurability {
        EvidenceDurability::Volatile
    }

    /// 异步追加一条已经校验的 Evidence 记录。
    async fn append(&self, record: &EvidenceRecord) -> Result<AppendReceipt, EvidenceError>;

    /// 以规范化记录作为幂等键追加 Evidence。
    async fn append_idempotent(
        &self,
        _record: &EvidenceRecord,
    ) -> Result<AppendReceipt, EvidenceError> {
        Err(EvidenceError::IdempotencyUnsupported)
    }

    /// 异步追加并写入 B1 receipt 绑定。
    async fn append_with_binding(
        &self,
        _record: &EvidenceRecord,
        _binding: &ReceiptBinding,
    ) -> Result<AppendReceipt, EvidenceError> {
        Err(EvidenceError::BindingUnsupported)
    }

    /// 异步幂等追加并写入 B1 receipt 绑定。
    async fn append_idempotent_with_binding(
        &self,
        _record: &EvidenceRecord,
        _binding: &ReceiptBinding,
    ) -> Result<AppendReceipt, EvidenceError> {
        Err(EvidenceError::BindingUnsupported)
    }

    /// 追加并保留“已追加 / 幂等重放 / 结果未知”的区别。
    ///
    /// 默认实现兼容已有异步 store；只有能够判断远程提交不确定性的适配器才应
    /// 覆盖该方法返回 [`EvidenceAppendOutcome::ResultUnknown`]。
    async fn append_idempotent_outcome(
        &self,
        record: &EvidenceRecord,
    ) -> Result<EvidenceAppendOutcome, EvidenceError> {
        self.append_idempotent(record)
            .await
            .map(EvidenceAppendOutcome::Appended)
    }

    /// 幂等追加并保留 outcome 区分，同时写入 B1 receipt 绑定。
    async fn append_idempotent_outcome_with_binding(
        &self,
        record: &EvidenceRecord,
        binding: &ReceiptBinding,
    ) -> Result<EvidenceAppendOutcome, EvidenceError> {
        self.append_idempotent_with_binding(record, binding)
            .await
            .map(EvidenceAppendOutcome::Appended)
    }
}

/// 同步 store 的异步兼容桥；不会伪造远程持久性能力。
#[async_trait::async_trait]
impl<T> AsyncEvidenceStore for T
where
    T: EvidenceStore + ?Sized,
{
    fn durability(&self) -> EvidenceDurability {
        EvidenceStore::durability(self)
    }

    async fn append(&self, record: &EvidenceRecord) -> Result<AppendReceipt, EvidenceError> {
        EvidenceStore::append(self, record)
    }

    async fn append_idempotent(
        &self,
        record: &EvidenceRecord,
    ) -> Result<AppendReceipt, EvidenceError> {
        EvidenceStore::append_idempotent(self, record)
    }

    async fn append_with_binding(
        &self,
        record: &EvidenceRecord,
        binding: &ReceiptBinding,
    ) -> Result<AppendReceipt, EvidenceError> {
        EvidenceStore::append_with_binding(self, record, binding)
    }

    async fn append_idempotent_with_binding(
        &self,
        record: &EvidenceRecord,
        binding: &ReceiptBinding,
    ) -> Result<AppendReceipt, EvidenceError> {
        EvidenceStore::append_idempotent_with_binding(self, record, binding)
    }
}

pub(crate) fn idempotent_lookup<'a>(
    entries: &'a [AppendReceipt],
    record: &EvidenceRecord,
    binding: Option<&ReceiptBinding>,
) -> Result<Option<&'a AppendReceipt>, EvidenceError> {
    let Some(existing) = entries.iter().find(|entry| entry.record == *record) else {
        return Ok(None);
    };
    if let Some(binding) = binding {
        if existing.binding.as_ref() != Some(binding) {
            return Err(EvidenceError::BindingMismatch);
        }
    }
    Ok(Some(existing))
}
