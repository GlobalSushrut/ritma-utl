use std::net::SocketAddr;

use axum::Router;
use tokio::net::{TcpListener, TcpStream};
use tokio_rustls::TlsAcceptor;
use hyper::body::Incoming;
use hyper::Request;
use hyper_util::rt::TokioIo;
use tower::Service;

use security_os::{MtlsConfig, Did};

/// Extension type to carry the DID derived from a client cert.
#[derive(Clone, Debug)]
pub struct PeerDid(pub Option<Did>);

/// Start an HTTPS listener using tokio-rustls + hyper, serving the given Axum Router.
/// This replaces axum-server for advanced TLS/mTLS control.
pub async fn serve_https_tokio_rustls(
    addr: SocketAddr,
    cfg: MtlsConfig,
    app: Router,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let server_config = security_os::build_rustls_server_config_from_mtls(&cfg)
        .map_err(|e| format!("failed to build rustls config: {}", e))?;
    let acceptor = TlsAcceptor::from(server_config);

    let listener = TcpListener::bind(addr).await?;
    tracing::info!("utl_http tokio-rustls HTTPS listening on {}", addr);

    loop {
        let (stream, _peer_addr) = match listener.accept().await {
            Ok(s) => s,
            Err(e) => {
                tracing::error!("failed to accept TCP connection: {}", e);
                continue;
            }
        };

        let acceptor = acceptor.clone();
        let app = app.clone();

        tokio::spawn(async move {
            if let Err(e) = handle_tls_connection(stream, acceptor, app).await {
                tracing::error!("TLS connection error: {}", e);
            }
        });
    }
}

async fn handle_tls_connection(
    stream: TcpStream,
    acceptor: TlsAcceptor,
    app: Router,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let tls_stream = acceptor.accept(stream).await?;

    // Extract peer certs and derive DID (steps 5-6).
    let peer_did = tls_stream
        .get_ref()
        .1
        .peer_certificates()
        .and_then(|certs| {
            let rustls_certs: Vec<rustls::Certificate> = certs
                .iter()
                .map(|c| rustls::Certificate(c.as_ref().to_vec()))
                .collect();
            security_os::mtls_identity_from_rustls_certs(&rustls_certs)
        })
        .and_then(|id| security_os::did_from_mtls_identity(&id));

    let io = TokioIo::new(tls_stream);

    let hyper_service = hyper::service::service_fn(move |mut req: Request<Incoming>| {
        // Attach PeerDid into request extensions so handlers can access it.
        req.extensions_mut().insert(PeerDid(peer_did.clone()));
        let mut app = app.clone();
        async move { app.call(req).await }
    });

    hyper_util::server::conn::auto::Builder::new(hyper_util::rt::TokioExecutor::new())
        .serve_connection(io, hyper_service)
        .await?;

    Ok(())
}
