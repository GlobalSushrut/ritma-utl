#[cfg(all(target_os = "linux", feature = "tls"))]
use std::io::{Read, Write};
#[cfg(all(target_os = "linux", feature = "tls"))]
use std::net::{SocketAddr, TcpListener, TcpStream};
#[cfg(all(target_os = "linux", feature = "tls"))]
use std::sync::{Arc, Mutex};
#[cfg(all(target_os = "linux", feature = "tls"))]
use std::thread;

#[cfg(all(target_os = "linux", feature = "tls"))]
use biz_api::BusinessPlugin;
#[cfg(all(target_os = "linux", feature = "tls"))]
use policy_engine::PolicyEngine;
#[cfg(all(target_os = "linux", feature = "tls"))]
use security_os::{Did, MtlsConfig};
#[cfg(all(target_os = "linux", feature = "tls"))]
use utld::UtlNode;

/// Start a TCP+TLS listener for utld on the given address.
/// Extracts DIDs from client certs and injects into p_container.
#[cfg(all(target_os = "linux", feature = "tls"))]
pub fn start_tls_listener(
    addr: SocketAddr,
    cfg: MtlsConfig,
    node: Arc<Mutex<UtlNode>>,
    engine: Option<Arc<Mutex<PolicyEngine>>>,
    plugin: Option<Arc<dyn BusinessPlugin + Send + Sync>>,
) -> std::io::Result<()> {
    let server_config = security_os::build_rustls_server_config_from_mtls(&cfg)
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e))?;

    tracing::info!("utld TLS listening on {}", addr);

    let listener = TcpListener::bind(addr)?;
    for stream in listener.incoming() {
        match stream {
            Ok(stream) => {
                let server_config = server_config.clone();
                let node = Arc::clone(&node);
                let engine = engine.as_ref().map(Arc::clone);
                let plugin = plugin.as_ref().map(Arc::clone);

                thread::spawn(move || {
                    if let Err(e) = handle_tls_client(stream, server_config, node, engine, plugin) {
                        tracing::error!("TLS client error: {}", e);
                    }
                });
            }
            Err(e) => tracing::error!("TLS accept error: {}", e),
        }
    }

    Ok(())
}

#[cfg(all(target_os = "linux", feature = "tls"))]
fn handle_tls_client(
    stream: TcpStream,
    server_config: Arc<rustls::ServerConfig>,
    node: Arc<Mutex<UtlNode>>,
    engine: Option<Arc<Mutex<PolicyEngine>>>,
    plugin: Option<Arc<dyn BusinessPlugin + Send + Sync>>,
) -> std::io::Result<()> {
    use rustls::ServerConnection;

    let mut conn = ServerConnection::new(server_config)
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e))?;

    let mut tls_stream = rustls::StreamOwned::new(conn, stream);

    // Extract DID from peer cert after handshake.
    let peer_did = tls_stream
        .conn
        .peer_certificates()
        .and_then(|certs| {
            let rustls_certs: Vec<rustls::Certificate> = certs
                .iter()
                .map(|c| rustls::Certificate(c.as_ref().to_vec()))
                .collect();
            security_os::mtls_identity_from_rustls_certs(&rustls_certs)
        })
        .and_then(|id| security_os::did_from_mtls_identity(&id));

    // Now handle as a normal client, but inject DID into p_container.
    crate::handle_client_with_did(tls_stream, node, engine, plugin, peer_did)
}

#[cfg(not(all(target_os = "linux", feature = "tls")))]
pub fn start_tls_listener(
    _addr: std::net::SocketAddr,
    _cfg: security_os::MtlsConfig,
    _node: std::sync::Arc<std::sync::Mutex<utld::UtlNode>>,
    _engine: Option<std::sync::Arc<std::sync::Mutex<policy_engine::PolicyEngine>>>,
    _plugin: Option<std::sync::Arc<dyn biz_api::BusinessPlugin + Send + Sync>>,
) -> std::io::Result<()> {
    Err(std::io::Error::new(
        std::io::ErrorKind::Unsupported,
        "TLS listener requires Linux and 'tls' feature",
    ))
}
