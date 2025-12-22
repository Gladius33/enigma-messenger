#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NodeClientConfig {
    pub timeout_ms: u64,
    pub connect_timeout_ms: u64,
    pub user_agent: String,
    pub max_response_bytes: usize,
}

impl Default for NodeClientConfig {
    fn default() -> Self {
        NodeClientConfig {
            timeout_ms: 3000,
            connect_timeout_ms: 1500,
            user_agent: "enigma-node-client/0.0.1".to_string(),
            max_response_bytes: 8 * 1024 * 1024,
        }
    }
}
