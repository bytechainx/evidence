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

use std::sync::Mutex;

use sha2::{Digest, Sha256};

/// 当前结构化 Evidence 行记录的 wire schema。
pub const RECORD_SCHEMA: &str = "evidence-record/v1";

/// B1 最小生产 receipt 绑定行的 wire schema。
pub const BINDING_SCHEMA: &str = "evidence-binding/v1";

mod binding;
mod error;
mod file;
mod lineage;
mod query;
mod sign;

pub use binding::{verify_binding, ImmutableBinding, IMMUTABLE_BINDING_SCHEMA};
pub use error::{EvidenceError, EvidenceResult};
pub use file::FileEvidenceStore;
pub use lineage::{verify_composition, verify_lineage, DecisionComposition, LineageBinding};
pub use query::EvidenceReader;
pub use sign::{
    sign_canonical, verify_approval, verify_canonical, ProtectedSignature, SignatureRole,
    SigningKey, TestSigningKey,
};

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

/// 进程内 Evidence 实现，仅用于开发和确定性测试。
#[derive(Debug, Default)]
pub struct MemoryEvidenceStore {
    state: Mutex<MemoryState>,
}

#[derive(Debug, Default)]
struct MemoryState {
    next_seq: u64,
    entries: Vec<AppendReceipt>,
    closed: bool,
}

impl MemoryEvidenceStore {
    /// 创建空的内存 Evidence store。
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// 返回当前追加快照。
    pub fn entries(&self) -> Result<Vec<AppendReceipt>, EvidenceError> {
        self.state
            .lock()
            .map(|state| state.entries.clone())
            .map_err(|_| EvidenceError::LockPoisoned)
    }

    /// 关闭 store；用于验证 fail-closed 行为。
    pub fn close(&self) -> Result<(), EvidenceError> {
        self.state
            .lock()
            .map(|mut state| {
                state.closed = true;
            })
            .map_err(|_| EvidenceError::LockPoisoned)
    }
}

impl EvidenceStore for MemoryEvidenceStore {
    fn append(&self, record: &EvidenceRecord) -> Result<AppendReceipt, EvidenceError> {
        record.validate()?;
        let mut state = self.state.lock().map_err(|_| EvidenceError::LockPoisoned)?;
        if state.closed {
            return Err(EvidenceError::Closed);
        }
        let seq = state
            .next_seq
            .checked_add(1)
            .ok_or_else(|| EvidenceError::InvalidWire("追加序号溢出".into()))?;
        let receipt = AppendReceipt {
            seq,
            record: record.clone(),
            binding: None,
        };
        state.next_seq = seq;
        state.entries.push(receipt.clone());
        Ok(receipt)
    }

    fn append_idempotent(&self, record: &EvidenceRecord) -> Result<AppendReceipt, EvidenceError> {
        record.validate()?;
        let mut state = self.state.lock().map_err(|_| EvidenceError::LockPoisoned)?;
        if state.closed {
            return Err(EvidenceError::Closed);
        }
        if let Some(existing) = idempotent_lookup(&state.entries, record, None)? {
            return Ok(existing.clone());
        }
        let seq = state
            .next_seq
            .checked_add(1)
            .ok_or_else(|| EvidenceError::InvalidWire("追加序号溢出".into()))?;
        let receipt = AppendReceipt {
            seq,
            record: record.clone(),
            binding: None,
        };
        state.next_seq = seq;
        state.entries.push(receipt.clone());
        Ok(receipt)
    }

    fn append_with_binding(
        &self,
        record: &EvidenceRecord,
        binding: &ReceiptBinding,
    ) -> Result<AppendReceipt, EvidenceError> {
        record.validate()?;
        binding.validate()?;
        let mut state = self.state.lock().map_err(|_| EvidenceError::LockPoisoned)?;
        if state.closed {
            return Err(EvidenceError::Closed);
        }
        let seq = state
            .next_seq
            .checked_add(1)
            .ok_or_else(|| EvidenceError::InvalidWire("追加序号溢出".into()))?;
        let receipt = AppendReceipt {
            seq,
            record: record.clone(),
            binding: Some(binding.clone()),
        };
        state.next_seq = seq;
        state.entries.push(receipt.clone());
        Ok(receipt)
    }

    fn append_idempotent_with_binding(
        &self,
        record: &EvidenceRecord,
        binding: &ReceiptBinding,
    ) -> Result<AppendReceipt, EvidenceError> {
        record.validate()?;
        binding.validate()?;
        let mut state = self.state.lock().map_err(|_| EvidenceError::LockPoisoned)?;
        if state.closed {
            return Err(EvidenceError::Closed);
        }
        if let Some(existing) = idempotent_lookup(&state.entries, record, Some(binding))? {
            return Ok(existing.clone());
        }
        let seq = state
            .next_seq
            .checked_add(1)
            .ok_or_else(|| EvidenceError::InvalidWire("追加序号溢出".into()))?;
        let receipt = AppendReceipt {
            seq,
            record: record.clone(),
            binding: Some(binding.clone()),
        };
        state.next_seq = seq;
        state.entries.push(receipt.clone());
        Ok(receipt)
    }
}

/// 解析一条带追加序号的 Evidence 行。
pub fn parse_line(line: &str) -> Result<AppendReceipt, EvidenceError> {
    let mut parts = line.splitn(3, '\t');
    let seq = parts
        .next()
        .ok_or_else(|| EvidenceError::InvalidWire("缺少序号".into()))?
        .parse::<u64>()
        .map_err(|error| EvidenceError::InvalidWire(format!("序号不是数字：{error}")))?;
    if seq == 0 {
        return Err(EvidenceError::InvalidWire("序号必须从 1 开始".into()));
    }
    let record_payload = parts
        .next()
        .ok_or_else(|| EvidenceError::InvalidWire("缺少 record payload".into()))?;
    let binding = parts.next().map(parse_binding).transpose()?;
    let record = parse_record_payload(record_payload)?;
    Ok(AppendReceipt {
        seq,
        record,
        binding,
    })
}

fn parse_record_payload(payload: &str) -> Result<EvidenceRecord, EvidenceError> {
    let fields: Vec<&str> = payload.split('|').collect();
    if fields.len() != 7 || fields[0] != RECORD_SCHEMA {
        return Err(EvidenceError::InvalidWire(
            "record schema 或字段数不匹配".into(),
        ));
    }
    let batch_ids = fields[4].split(',').map(str::to_owned).collect();
    EvidenceRecord::new(
        fields[1], fields[2], fields[3], batch_ids, fields[5], fields[6],
    )
}

fn parse_binding(payload: &str) -> Result<ReceiptBinding, EvidenceError> {
    let fields: Vec<&str> = payload.split('|').collect();
    if fields.len() != 4 || fields[0] != BINDING_SCHEMA {
        return Err(EvidenceError::InvalidWire(
            "binding schema 或字段数不匹配".into(),
        ));
    }
    ReceiptBinding::new(fields[1], fields[2], fields[3])
}

pub(crate) fn receipt_line(
    seq: u64,
    record: &EvidenceRecord,
    binding: Option<&ReceiptBinding>,
) -> String {
    let record_line = record.canonical_line();
    match binding {
        Some(binding) => format!("{seq}\t{record_line}\t{}\n", binding.canonical_line()),
        None => format!("{seq}\t{record_line}\n"),
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

/// 对任意 payload 计算小写 SHA-256 文本摘要。
#[must_use]
pub fn sha256_hex(payload: impl AsRef<[u8]>) -> String {
    let mut hasher = Sha256::new();
    hasher.update(payload.as_ref());
    encode_hex(&hasher.finalize())
}

fn validate_component(
    field: &'static str,
    value: &str,
    comma_reserved: bool,
) -> Result<(), EvidenceError> {
    if value.is_empty() {
        return Err(EvidenceError::EmptyField(field));
    }
    if value
        .chars()
        .any(|character| matches!(character, '|' | '\t' | '\r' | '\n'))
        || (comma_reserved && value.contains(','))
    {
        return Err(EvidenceError::InvalidCharacter(field));
    }
    Ok(())
}

fn validate_digest(field: &'static str, value: &str) -> Result<(), EvidenceError> {
    if value.len() != 64 || !value.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err(EvidenceError::InvalidDigest(field));
    }
    Ok(())
}

fn validate_commit(field: &'static str, value: &str) -> Result<(), EvidenceError> {
    if value.len() != 40 || !value.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err(EvidenceError::InvalidDigest(field));
    }
    Ok(())
}

fn encode_hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(bytes.len() * 2);
    for &byte in bytes {
        output.push(HEX[(byte >> 4) as usize] as char);
        output.push(HEX[(byte & 0x0f) as usize] as char);
    }
    output
}
