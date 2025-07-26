//! Gateway integration test module
//! 
//! This module provides the integration test interface for the gateway.

// Re-export all gateway components for integration tests
pub use gateway_core::*;
pub use gateway_waf;
pub use gateway_cache;
pub use gateway_database;
pub use gateway_auth;
pub use gateway_monitoring;
pub use gateway_plugins;