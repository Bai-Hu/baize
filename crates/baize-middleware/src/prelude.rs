//! Baize Middleware Prelude
//!
//! 导出中间件开发所需的核心类型和 trait。

pub use crate::client::BaizeClient;
pub use crate::error::{ClientError, ClientResult};
pub use crate::types::*;

#[cfg(feature = "http")]
pub use crate::http::BaizeHttpClient;
