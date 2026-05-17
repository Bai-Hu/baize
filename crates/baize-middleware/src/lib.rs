//! Baize Middleware — agent 架构的白泽集成接口
//!
//! 提供标准化的 trait 和客户端实现，让不同 agent 框架
//! 能够通过白泽网关进行鉴权、文件操作和数据同步。
//!
//! # 使用方式
//!
//! ```no_run
//! use baize_middleware::prelude::*;
//!
//! // 创建 HTTP 客户端
//! let client = BaizeHttpClient::new(
//!     "http://127.0.0.1:3000/api/v0",
//!     "my-agent",
//! );
//!
//! // 写入文件
//! let record = client.file_write("A/config.yaml", FileWriteRequest {
//!     content: "key: value".to_string(),
//!     labels: None,
//! }).unwrap();
//! ```

pub mod client;
pub mod error;
pub mod prelude;
pub mod types;

#[cfg(feature = "http")]
pub mod http;
