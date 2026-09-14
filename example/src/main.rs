//! A static file server whose requests can be answered from the kernel.

use axum::http::StatusCode;
use beeper_axum::{OpenObject, fast_path::FastPath, listener::BeeperListener, server};
use clap::Parser;
use std::{collections::HashMap, net::SocketAddr, path::PathBuf};
use tokio::net::TcpListener;
use tower_http::{
    services::{ServeDir, ServeFile},
    set_status::SetStatus,
    trace::TraceLayer,
};
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

/// A static file server that can answer its smaller assets from eBPF.
#[derive(Parser)]
#[command(about, long_about = None)]
struct Args {
    /// Disable the eBPF fast path.
    #[arg(long)]
    no_fastpath: bool,

    /// The address to listen on.
    #[arg(short, long, default_value = "127.0.0.1:8080")]
    addr: SocketAddr,
}

/// All assets that are served with the fast path.
fn fastpath_routes(assets_dir: &str) -> HashMap<String, PathBuf> {
    ["/1KB.txt", "/8KB.txt", "/32KB.txt", "/128KB.txt"]
        .into_iter()
        .map(|path| {
            let file = PathBuf::from(format!("{assets_dir}{path}"));
            (path.to_string(), file)
        })
        .collect()
}

#[tokio::main]
async fn main() {
    let args = Args::parse();

    tracing_subscriber::registry()
        .with(
            tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| {
                format!(
                    "{}=debug,bpf=trace,tower_http=debug",
                    env!("CARGO_CRATE_NAME")
                )
                .into()
            }),
        )
        .with(tracing_subscriber::fmt::layer())
        .init();

    let assets_dir = concat!(env!("CARGO_MANIFEST_DIR"), "/assets");
    let index_html = SetStatus::new(
        ServeFile::new(format!("{assets_dir}/index.html")),
        StatusCode::NOT_FOUND,
    );
    let serve_dir = ServeDir::new(assets_dir).not_found_service(index_html);

    let app = axum::Router::new()
        .fallback_service(serve_dir)
        .layer(TraceLayer::new_for_http());

    // the fast path has to outlive the server, and nothing of it is loaded
    // unless it was asked for
    let mut open_obj = OpenObject::new();
    let _fastpath = if args.no_fastpath {
        tracing::info!("Running without the eBPF fast path");
        None
    } else {
        let routes = fastpath_routes(assets_dir);
        Some(FastPath::attach(args.addr, &mut open_obj, routes).expect("attach"))
    };

    let listener = TcpListener::bind(args.addr).await.unwrap();
    let listener = BeeperListener::new(listener);
    tracing::debug!("listening on {}", listener.local_addr().unwrap());

    server::serve(listener, app).await;
}
