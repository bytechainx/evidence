//! B4：macro provider 溯源绑定（lineage binding）。
//!
//! 记录 provider 请求标识 → raw SHA → lineage → PIT 的溯源绑定链，并纳入
//! [`DecisionComposition`]，使决策与输入数据来源可追溯。
//!
//! ## CONTRACT_GAP（跨域，未决）
//!
//! macro_data 域的 provider PIT/lineage **数据采集本身**不在本 crate 范围
//! （本 crate 不依赖 `contracts` / 分析域，见 `lib.rs` 模块文档）。本模块只
//! **消费其契约**：`provider_request_id` / `raw_sha256` / `lineage` / `pit`
//! 四字段。因此 [`verify_lineage`] 校验的是**结构性一致性**（字段存在且格式
//! 合法，使 raw SHA→lineage→PIT 链完整可追溯）；provider 侧真实数据的
//! **内容级对账**须待 macro_data 域提供数据契约后由该域实现。

use crate::{validate_component, validate_digest, EvidenceError};

/// 单条 macro provider 溯源绑定。
///
/// 字段私有，仅 [`LineageBinding::new`] 可构造通过校验的实例；
/// [`verify_lineage`] 独立复验全部不变量，不信任构造结果。
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LineageBinding {
    /// macro provider 请求标识（非空，无行协议保留字符）。
    provider_request_id: String,
    /// provider 返回原始数据的 SHA-256 摘要（64 位十六进制）。
    raw_sha256: String,
    /// 溯源标识（lineage），例如数据批次血缘标识（非空）。
    lineage: String,
    /// PIT（Point-in-Time）时间点：RFC3339 时间戳或 Unix 毫秒数字串。
    pit: String,
}

impl LineageBinding {
    /// 创建并校验一条溯源绑定。
    pub fn new(
        provider_request_id: impl Into<String>,
        raw_sha256: impl Into<String>,
        lineage: impl Into<String>,
        pit: impl Into<String>,
    ) -> Result<Self, EvidenceError> {
        let binding = Self {
            provider_request_id: provider_request_id.into(),
            raw_sha256: raw_sha256.into(),
            lineage: lineage.into(),
            pit: pit.into(),
        };
        verify_lineage(&binding)?;
        Ok(binding)
    }

    /// macro provider 请求标识。
    #[must_use]
    pub fn provider_request_id(&self) -> &str {
        &self.provider_request_id
    }

    /// provider 原始数据的 SHA-256 摘要（64 位十六进制）。
    #[must_use]
    pub fn raw_sha256(&self) -> &str {
        &self.raw_sha256
    }

    /// 溯源标识（lineage）。
    #[must_use]
    pub fn lineage(&self) -> &str {
        &self.lineage
    }

    /// PIT 时间点。
    #[must_use]
    pub fn pit(&self) -> &str {
        &self.pit
    }
}

/// 决策与输入数据溯源的组合视图（B4 FR-002）。
///
/// 字段私有，仅 [`DecisionComposition::new`] 可构造通过校验的实例；
/// [`verify_composition`] 独立复验全部不变量。
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DecisionComposition {
    /// 决策标识（非空，无行协议保留字符）。
    decision_id: String,
    /// 该决策输入的全部溯源绑定（至少一条）。
    composition: Vec<LineageBinding>,
    /// 可选的外部记录引用（如证据记录标识）。
    record_ref: Option<String>,
}

impl DecisionComposition {
    /// 创建并校验一个决策组合。
    pub fn new(
        decision_id: impl Into<String>,
        composition: Vec<LineageBinding>,
        record_ref: Option<String>,
    ) -> Result<Self, EvidenceError> {
        let document = Self {
            decision_id: decision_id.into(),
            composition,
            record_ref,
        };
        verify_composition(&document)?;
        Ok(document)
    }

    /// 决策标识。
    #[must_use]
    pub fn decision_id(&self) -> &str {
        &self.decision_id
    }

    /// 输入溯源绑定集合。
    #[must_use]
    pub fn composition(&self) -> &[LineageBinding] {
        &self.composition
    }

    /// 外部记录引用（可选）。
    #[must_use]
    pub fn record_ref(&self) -> Option<&str> {
        self.record_ref.as_deref()
    }
}

/// 溯源一致性校验（B4 FR-003）：校验单个 [`LineageBinding`] 的结构性不变量。
///
/// 校验内容：`provider_request_id` / `lineage` 非空且无保留字符、
/// `raw_sha256` 为 64 位十六进制、`pit` 为 RFC3339 时间戳或 Unix 毫秒数字串。
/// 内容级与 provider 数据对账见模块文档 CONTRACT_GAP。
pub fn verify_lineage(binding: &LineageBinding) -> Result<(), EvidenceError> {
    validate_component("provider_request_id", &binding.provider_request_id, false)?;
    validate_digest("raw_sha256", &binding.raw_sha256)?;
    validate_component("lineage", &binding.lineage, false)?;
    validate_pit(&binding.pit)
}

/// 溯源组合一致性校验（B4 FR-003）：校验 [`DecisionComposition`] 及其中每个绑定。
pub fn verify_composition(composition: &DecisionComposition) -> Result<(), EvidenceError> {
    validate_component("decision_id", &composition.decision_id, false)?;
    if let Some(record_ref) = &composition.record_ref {
        validate_component("record_ref", record_ref, false)?;
    }
    if composition.composition.is_empty() {
        return Err(EvidenceError::EmptyField("composition"));
    }
    for binding in &composition.composition {
        verify_lineage(binding)?;
    }
    Ok(())
}

/// 校验 PIT 时间点：RFC3339 时间戳或 Unix 毫秒数字串。
fn validate_pit(value: &str) -> Result<(), EvidenceError> {
    validate_component("pit", value, true)?;
    let valid = if value.bytes().all(|byte| byte.is_ascii_digit()) {
        value.len() >= 13
    } else {
        is_rfc3339(value)
    };
    if valid {
        Ok(())
    } else {
        Err(EvidenceError::LineageInvalid(format!(
            "pit 必须是 RFC3339 时间戳或 Unix 毫秒数字串，实际：{value}"
        )))
    }
}

/// RFC3339 时间戳形状校验（只校验语法形状，不校验公历日期合法性）。
fn is_rfc3339(value: &str) -> bool {
    let bytes = value.as_bytes();
    if bytes.len() < 20 || bytes[10] != b'T' {
        return false;
    }
    let date_ok = bytes[0..4].iter().all(u8::is_ascii_digit)
        && bytes[4] == b'-'
        && bytes[5..7].iter().all(u8::is_ascii_digit)
        && bytes[7] == b'-'
        && bytes[8..10].iter().all(u8::is_ascii_digit);
    let time_ok = bytes[11..13].iter().all(u8::is_ascii_digit)
        && bytes[13] == b':'
        && bytes[14..16].iter().all(u8::is_ascii_digit)
        && bytes[16] == b':'
        && bytes[17..19].iter().all(u8::is_ascii_digit);
    if !date_ok || !time_ok {
        return false;
    }
    let mut index = 19;
    if bytes.get(index) == Some(&b'.') {
        index += 1;
        let fraction_start = index;
        while bytes.get(index).is_some_and(u8::is_ascii_digit) {
            index += 1;
        }
        if index == fraction_start {
            return false;
        }
    }
    let rest = &value[index..];
    rest == "Z" || is_utc_offset(rest)
}

/// `±HH:MM` 时区偏移校验。
fn is_utc_offset(value: &str) -> bool {
    let bytes = value.as_bytes();
    bytes.len() == 6
        && (bytes[0] == b'+' || bytes[0] == b'-')
        && bytes[1..3].iter().all(u8::is_ascii_digit)
        && bytes[3] == b':'
        && bytes[4..6].iter().all(u8::is_ascii_digit)
}

#[cfg(test)]
mod tests {
    use super::{verify_composition, verify_lineage, DecisionComposition, LineageBinding};
    use crate::{sha256_hex, EvidenceError};

    const REQUEST_ID: &str = "provider-request-001";
    const LINEAGE: &str = "fred/series/2026-08-27";
    const PIT_RFC3339: &str = "2026-08-27T12:34:56Z";
    const PIT_MILLIS: &str = "1785249296000";

    fn raw_sha() -> String {
        sha256_hex(b"raw-provider-payload")
    }

    fn sample_binding() -> LineageBinding {
        LineageBinding::new(REQUEST_ID, raw_sha(), LINEAGE, PIT_RFC3339).expect("绑定有效")
    }

    fn sample_composition() -> DecisionComposition {
        DecisionComposition::new(
            "decision-001",
            vec![sample_binding()],
            Some("evidence-record-001".into()),
        )
        .expect("组合有效")
    }

    #[test]
    fn lineage_roundtrip() {
        let binding = sample_binding();
        assert_eq!(binding.provider_request_id(), REQUEST_ID);
        assert_eq!(binding.raw_sha256(), raw_sha());
        assert_eq!(binding.lineage(), LINEAGE);
        assert_eq!(binding.pit(), PIT_RFC3339);
        assert!(verify_lineage(&binding).is_ok());
    }

    #[test]
    fn composition_roundtrip() {
        let document = sample_composition();
        assert_eq!(document.decision_id(), "decision-001");
        assert_eq!(document.composition().len(), 1);
        assert_eq!(document.record_ref(), Some("evidence-record-001"));
        assert!(verify_composition(&document).is_ok());
    }

    #[test]
    fn composition_accepts_missing_record_ref() {
        let document = DecisionComposition::new("decision-002", vec![sample_binding()], None)
            .expect("组合有效");
        assert_eq!(document.record_ref(), None);
    }

    #[test]
    fn accepts_rfc3339_with_fraction_and_offset() {
        let binding = LineageBinding::new(
            REQUEST_ID,
            raw_sha(),
            LINEAGE,
            "2026-08-27T12:34:56.123+08:00",
        )
        .expect("带小数秒与偏移的 RFC3339 有效");
        assert!(verify_lineage(&binding).is_ok());
    }

    #[test]
    fn accepts_unix_millis() {
        let binding =
            LineageBinding::new(REQUEST_ID, raw_sha(), LINEAGE, PIT_MILLIS).expect("Unix 毫秒有效");
        assert!(verify_lineage(&binding).is_ok());
    }

    #[test]
    fn rejects_empty_provider_request_id() {
        let result = LineageBinding::new("", raw_sha(), LINEAGE, PIT_RFC3339);
        assert!(matches!(
            result,
            Err(EvidenceError::EmptyField("provider_request_id"))
        ));
    }

    #[test]
    fn rejects_empty_lineage() {
        let result = LineageBinding::new(REQUEST_ID, raw_sha(), "", PIT_RFC3339);
        assert!(matches!(result, Err(EvidenceError::EmptyField("lineage"))));
    }

    #[test]
    fn rejects_empty_pit() {
        let result = LineageBinding::new(REQUEST_ID, raw_sha(), LINEAGE, "");
        assert!(matches!(result, Err(EvidenceError::EmptyField("pit"))));
    }

    #[test]
    fn rejects_malformed_raw_sha256() {
        let result = LineageBinding::new(REQUEST_ID, "not-a-sha", LINEAGE, PIT_RFC3339);
        assert!(matches!(
            result,
            Err(EvidenceError::InvalidDigest("raw_sha256"))
        ));
    }

    #[test]
    fn rejects_short_raw_sha256() {
        // 长度不足 64 的十六进制摘要 → 拒绝。
        let result = LineageBinding::new(REQUEST_ID, "abcd", LINEAGE, PIT_RFC3339);
        assert!(matches!(
            result,
            Err(EvidenceError::InvalidDigest("raw_sha256"))
        ));
    }

    #[test]
    fn rejects_non_rfc3339_pit() {
        // 不是时间戳形状、也不是数字串 → 拒绝。
        let result = LineageBinding::new(REQUEST_ID, raw_sha(), LINEAGE, "2026-08-27");
        assert!(matches!(result, Err(EvidenceError::LineageInvalid(_))));
    }

    #[test]
    fn rejects_short_millis_pit() {
        // 纯数字但不足 Unix 毫秒长度 → 拒绝。
        let result = LineageBinding::new(REQUEST_ID, raw_sha(), LINEAGE, "123456");
        assert!(matches!(result, Err(EvidenceError::LineageInvalid(_))));
    }

    #[test]
    fn verify_rejects_tampered_raw_sha256() {
        // 构造后篡改 raw_sha256 → 独立 verify 拒绝（不信任构造结果）。
        let mut binding = sample_binding();
        binding.raw_sha256 = "tampered-sha-value".into();
        assert!(matches!(
            verify_lineage(&binding),
            Err(EvidenceError::InvalidDigest(_))
        ));
    }

    #[test]
    fn verify_rejects_tampered_pit() {
        // 构造后篡改 pit → 独立 verify 拒绝。
        let mut binding = sample_binding();
        binding.pit = "not-a-pit".into();
        assert!(matches!(
            verify_lineage(&binding),
            Err(EvidenceError::LineageInvalid(_))
        ));
    }

    #[test]
    fn verify_rejects_tampered_provider_request_id() {
        // 构造后篡改 provider_request_id 为非法值（空串）→ 独立 verify 拒绝。
        let mut binding = sample_binding();
        binding.provider_request_id.clear();
        assert!(matches!(
            verify_lineage(&binding),
            Err(EvidenceError::EmptyField("provider_request_id"))
        ));

        // 篡改为含行协议保留字符的非法值 → 拒绝。
        let mut binding = sample_binding();
        binding.provider_request_id = "provider|tampered".into();
        assert!(matches!(
            verify_lineage(&binding),
            Err(EvidenceError::InvalidCharacter("provider_request_id"))
        ));
    }

    #[test]
    fn verify_rejects_tampered_lineage() {
        // 构造后篡改 lineage 为非法值（空串）→ 独立 verify 拒绝。
        let mut binding = sample_binding();
        binding.lineage.clear();
        assert!(matches!(
            verify_lineage(&binding),
            Err(EvidenceError::EmptyField("lineage"))
        ));

        // 篡改为含行协议保留字符的非法值 → 拒绝。
        let mut binding = sample_binding();
        binding.lineage = "lineage|tampered".into();
        assert!(matches!(
            verify_lineage(&binding),
            Err(EvidenceError::InvalidCharacter("lineage"))
        ));
    }

    #[test]
    fn composition_rejects_empty_bindings() {
        let result = DecisionComposition::new("decision-003", vec![], None);
        assert!(matches!(
            result,
            Err(EvidenceError::EmptyField("composition"))
        ));
    }

    #[test]
    fn composition_rejects_tampered_binding() {
        // composition 内某个绑定被篡改 → verify_composition 拒绝。
        let mut binding = sample_binding();
        binding.raw_sha256 = "tampered-sha".into();
        let result = DecisionComposition::new("decision-004", vec![binding], None);
        assert!(matches!(result, Err(EvidenceError::InvalidDigest(_))));
    }

    #[test]
    fn composition_rejects_empty_decision_id() {
        let result = DecisionComposition::new("", vec![sample_binding()], None);
        assert!(matches!(
            result,
            Err(EvidenceError::EmptyField("decision_id"))
        ));
    }
}
