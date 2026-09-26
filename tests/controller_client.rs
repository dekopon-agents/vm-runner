#[tokio::test]
async fn kubernetes_tls_client_selects_a_provider_without_prior_initialization() {
    let mut config = kube::Config::new("https://127.0.0.1:443".parse().expect("literal URI"));
    config.root_cert = Some(Vec::new());
    assert!(kube::Client::try_from(config).is_ok());
}
