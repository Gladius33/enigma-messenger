use super::*;
use crate::config::{EndpointMode, TlsConfig};
use std::env;
use std::path::PathBuf;

fn restore_env(key: &str, value: Option<String>) {
    if let Some(value) = value {
        env::set_var(key, value);
    } else {
        env::remove_var(key);
    }
}

#[test]
fn api_bind_non_loopback_requires_auth() {
    let mut cfg = test_config(false, false, false);
    cfg.api.bind_addr = "0.0.0.0:9171".to_string();

    let original = env::var("ENIGMA_UI_TOKEN").ok();
    env::remove_var("ENIGMA_UI_TOKEN");

    let result = cfg.validate();
    assert!(result.is_err());

    if cfg!(feature = "ui-auth") {
        env::set_var("ENIGMA_UI_TOKEN", "token");
        let ok_result = cfg.validate();
        restore_env("ENIGMA_UI_TOKEN", original);
        assert!(ok_result.is_ok());
        return;
    }

    restore_env("ENIGMA_UI_TOKEN", original);
}

#[test]
fn registry_tls_requires_config() {
    let mut cfg = test_config(false, false, false);
    cfg.registry.enabled = true;
    cfg.registry.mode = EndpointMode::Tls;
    cfg.registry.base_url = "https://registry.example.com".to_string();
    cfg.registry.tls = None;

    let result = cfg.validate();
    assert!(result.is_err());
}

#[test]
fn relay_tls_requires_client_key_pair() {
    let mut cfg = test_config(false, false, false);
    cfg.relay.enabled = true;
    cfg.relay.mode = EndpointMode::Tls;
    cfg.relay.base_url = Some("https://relay.example.com".to_string());
    cfg.relay.tls = Some(TlsConfig {
        ca_cert: Some(PathBuf::from("/tmp/ca.pem")),
        client_cert: Some(PathBuf::from("/tmp/client.pem")),
        client_key: None,
    });

    let result = cfg.validate();
    assert!(result.is_err());
}
