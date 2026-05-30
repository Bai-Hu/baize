//! 可插拔身份提供者 — 默认实现与模块入口
//!
//! V3 Phase 3：CertIdentityProvider 包装现有 X.509 证书系统，
//! 二次开发者实现 `IdentityProvider` trait 即可替换为 OAuth/SPIFFE/自定义方案。

mod cert_provider;

pub use cert_provider::CertIdentityProvider;
