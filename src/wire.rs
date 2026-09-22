//! 行协议的编解码、字段校验与摘要原语。
//!
//! 从 crate 根下沉而来：`{seq}\t{canonical_record}[\t{binding}]\\n` 这一行格式的
//! 解析 / 序列化、其字段级校验，以及十六进制与 SHA-256 摘要原语。公开条目
//! （[`parse_line`] / [`sha256_hex`]）经 crate 根 `pub use` 导出，路径与拆分前一致；
//! `receipt_line` 与三个 `validate_*` 以 `pub(crate)` 复用。

use sha2::{Digest, Sha256};

use crate::{
    AppendReceipt, EvidenceError, EvidenceRecord, ReceiptBinding, BINDING_SCHEMA, RECORD_SCHEMA,
};

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

/// 对任意 payload 计算小写 SHA-256 文本摘要。
///
/// # Examples
///
/// ```
/// use evidence::sha256_hex;
///
/// // FIPS 180-4 标准向量：SHA-256("abc")
/// let digest = sha256_hex(b"abc");
/// assert_eq!(
///     digest,
///     "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
/// );
/// assert_eq!(digest.len(), 64, "十六进制小写，定长 64 字符");
/// ```
#[must_use]
pub fn sha256_hex(payload: impl AsRef<[u8]>) -> String {
    let mut hasher = Sha256::new();
    hasher.update(payload.as_ref());
    encode_hex(&hasher.finalize())
}

pub(crate) fn validate_component(
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

pub(crate) fn validate_digest(field: &'static str, value: &str) -> Result<(), EvidenceError> {
    if value.len() != 64 || !value.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err(EvidenceError::InvalidDigest(field));
    }
    Ok(())
}

pub(crate) fn validate_commit(field: &'static str, value: &str) -> Result<(), EvidenceError> {
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
