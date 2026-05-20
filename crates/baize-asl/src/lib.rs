//! baize-asl — ASL 合规层 + 适配
//!
//! 白泽 v1 的 ASL（Agent Safety Layer）合规实现，负责：
//! - ASL 载荷结构定义（payload.rs）
//! - ASL payload ↔ blob+label 双向转换（adapter.rs）
//! - CNV 全链路校验 + AZN-VER 五项校验（verify.rs）

pub mod adapter;
pub mod payload;
pub mod verify;

pub use adapter::{AslAdapter, AslContext};
pub use payload::*;
pub use verify::{cnv_verify, verify_authorization, CnvResult, AuthzVerifyResult};
