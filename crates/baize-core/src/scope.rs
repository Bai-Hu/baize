use std::collections::HashSet;

use crate::error::{Error, Result};

/// 安全等级
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct Level(pub u8);

impl Level {
    pub const ISOLATED: Level = Level(0);  // 隔离区
    pub const RESTRICTED: Level = Level(1); // 受限操作
    pub const STANDARD: Level = Level(2);   // 标准操作
    pub const CORE: Level = Level(3);       // 核心操作
    pub const USER: Level = Level(4);       // 用户级（最高）

    pub fn is_valid(&self) -> bool {
        self.0 <= 4
    }
}

/// Scope = Level + Zones
#[derive(Debug, Clone)]
pub struct Scope {
    pub level: Level,
    pub zones: HashSet<String>,
}

impl Scope {
    pub fn new(level: Level, zones: impl IntoIterator<Item = impl AsRef<str>>) -> Result<Self> {
        let zones: HashSet<String> = zones.into_iter().map(|s| s.as_ref().to_string()).collect();

        if !level.is_valid() {
            return Err(Error::Validation(format!("invalid level: {}", level.0)));
        }

        Ok(Scope { level, zones })
    }

    /// 判断 self 是否是 other 的子集（递减合法）
    /// 规则：
    /// - self.level <= parent.level
    /// - self.zones ⊆ parent.zones（parent 含 "*" 时视为所有 zone）
    pub fn is_subset_of(&self, parent: &Scope) -> bool {
        if self.level > parent.level {
            return false;
        }
        // "*" 通配：parent 包含 "*" 则视为拥有所有 zone
        if !parent.zones.contains("*") && !self.zones.is_subset(&parent.zones) {
            return false;
        }
        true
    }

    /// 验证 child scope 是否可以从 parent 派生（递减合法）
    pub fn validate_decrease(parent: &Scope, child: &Scope) -> Result<()> {
        if child.level > parent.level {
            return Err(Error::Validation(format!(
                "child level {} exceeds parent level {}",
                child.level.0, parent.level.0
            )));
        }

        let overflow: Vec<&str> = child
            .zones
            .iter()
            .filter(|z| z.as_str() != "*" && !parent.zones.contains(z.as_str()) && !parent.zones.contains("*"))
            .map(|s| s.as_str())
            .collect();
        if !overflow.is_empty() {
            let parent_zones: Vec<String> = parent.zones.iter().cloned().collect();
            return Err(Error::Validation(format!(
                "zones not allowed: [{}] not in parent zones [{}]. \
                 Child agent zones must be a subset of parent zones",
                overflow.join(", "),
                parent_zones.join(", "),
            )));
        }

        Ok(())
    }
}

/// 借权访问模式
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ElevationMode {
    ReadOnly,
    WriteOnly,
    ReadWrite,
}

impl ElevationMode {
    /// 从小写字符串解析: "readonly" / "write" / "readwrite"
    pub fn from_str_lower(s: &str) -> Option<Self> {
        match s {
            "readonly" => Some(Self::ReadOnly),
            "write" => Some(Self::WriteOnly),
            "readwrite" => Some(Self::ReadWrite),
            _ => None,
        }
    }
}

/// 借权请求状态
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ElevationStatus {
    Pending,
    Approved,
    Expired,
    Revoked,
    Returned,
}

/// 借权请求
#[derive(Debug, Clone)]
pub struct ElevationRequest {
    pub id: String,
    pub agent_id: String,
    pub requested_zones: HashSet<String>,
    pub mode: ElevationMode,
    pub reason: String,
    pub status: ElevationStatus,
    pub created_at: String,
    pub expires_at: Option<String>,
}

/// 解析时长字符串（"30m", "1h", "2h"）为 chrono::Duration
pub fn parse_duration(s: &str) -> Option<chrono::Duration> {
    if s.is_empty() {
        return None;
    }
    let (num_str, multiplier) = if s.ends_with('m') {
        (&s[..s.len() - 1], 60i64)
    } else if s.ends_with('h') {
        (&s[..s.len() - 1], 3600i64)
    } else {
        return None;
    };
    let num: i64 = num_str.parse().ok()?;
    if num <= 0 {
        return None;
    }
    Some(chrono::Duration::seconds(num * multiplier))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn scope_subset_level2_in_level3() {
        let parent = Scope::new(Level(3), vec!["A", "B", "C"]).unwrap();
        let child = Scope::new(Level(2), vec!["A"]).unwrap();
        assert!(child.is_subset_of(&parent));
    }

    #[test]
    fn scope_decrease_valid() {
        let parent = Scope::new(Level(3), vec!["A", "B", "C"]).unwrap();
        let child = Scope::new(Level(2), vec!["A", "B"]).unwrap();
        assert!(Scope::validate_decrease(&parent, &child).is_ok());
    }

    #[test]
    fn scope_level_exceed() {
        let parent = Scope::new(Level(2), vec!["A", "B"]).unwrap();
        let child = Scope::new(Level(3), vec!["A"]).unwrap(); // L3 > L2
        assert!(Scope::validate_decrease(&parent, &child).is_err());
    }

    #[test]
    fn scope_zone_count_unrestricted() {
        // zone 数量不受 level 限制，只要在 parent 范围内即可
        let scope = Scope::new(Level(2), vec!["A", "B", "C", "D", "E"]);
        assert!(scope.is_ok());
    }

    #[test]
    fn scope_zone_overflow_parent() {
        let parent = Scope::new(Level(3), vec!["A", "B"]).unwrap();
        // C is not in parent's zones
        let child_with_c = Scope::new(Level(3), vec!["A", "B", "C"]).unwrap();
        assert!(Scope::validate_decrease(&parent, &child_with_c).is_err());
    }

    #[test]
    fn scope_equal_parent() {
        let parent = Scope::new(Level(3), vec!["A", "B"]).unwrap();
        let child = Scope::new(Level(3), vec!["A", "B"]).unwrap();
        assert!(Scope::validate_decrease(&parent, &child).is_ok());
    }

    #[test]
    fn scope_empty_zones() {
        let parent = Scope::new(Level(3), vec!["A", "B"]).unwrap();
        let child = Scope::new(Level(2), Vec::<&str>::new()).unwrap();
        assert!(Scope::validate_decrease(&parent, &child).is_ok());
    }

    #[test]
    fn scope_cross_zones() {
        let parent = Scope::new(Level(3), vec!["A", "B"]).unwrap();
        let child = Scope::new(Level(3), vec!["B", "C"]).unwrap();
        assert!(Scope::validate_decrease(&parent, &child).is_err());
    }

    #[test]
    fn parse_duration_minutes() {
        let d = parse_duration("30m").unwrap();
        assert_eq!(d.num_minutes(), 30);
    }

    #[test]
    fn parse_duration_hours() {
        let d = parse_duration("2h").unwrap();
        assert_eq!(d.num_hours(), 2);
    }

    #[test]
    fn parse_duration_one_hour() {
        let d = parse_duration("1h").unwrap();
        assert_eq!(d.num_minutes(), 60);
    }

    #[test]
    fn parse_duration_empty() {
        assert!(parse_duration("").is_none());
    }

    #[test]
    fn parse_duration_invalid() {
        assert!(parse_duration("abc").is_none());
    }

    #[test]
    fn parse_duration_zero() {
        assert!(parse_duration("0m").is_none());
    }

    #[test]
    fn parse_duration_no_unit() {
        assert!(parse_duration("30").is_none());
    }

    #[test]
    fn elevation_mode_from_str_lower() {
        assert_eq!(ElevationMode::from_str_lower("readonly"), Some(ElevationMode::ReadOnly));
        assert_eq!(ElevationMode::from_str_lower("write"), Some(ElevationMode::WriteOnly));
        assert_eq!(ElevationMode::from_str_lower("readwrite"), Some(ElevationMode::ReadWrite));
        assert_eq!(ElevationMode::from_str_lower("Readonly"), None);
        assert_eq!(ElevationMode::from_str_lower("invalid"), None);
        assert_eq!(ElevationMode::from_str_lower(""), None);
    }
}
