#![allow(unused_imports)]
use anyhow::{Context, Result, bail};
use beeper::{h1, h2};
use httlib_huffman as huffman;
use std::{
    collections::HashMap,
    io::{Error, ErrorKind},
    mem::MaybeUninit,
    net::{SocketAddr, ToSocketAddrs},
    os::{
        fd::{AsFd, AsRawFd, IntoRawFd},
        unix::fs::OpenOptionsExt,
    },
    path::{Path, PathBuf},
};
use tracing::{Level, debug, info};
use xbpf::libbpf::{
    self as libbpf_rs, Link, MapCore, MapFlags,
    skel::{OpenSkel, Skel, SkelBuilder},
};

xbpf::include_bpf!("fast_path");

fn huffman_encode(val: &str) -> Vec<u8> {
    let mut res = Vec::new();
    huffman::encode(val.as_bytes(), &mut res).unwrap();
    res
}

// Must stay in sync with the corresponding `#define`s in fastpath.bpf.c.
const MAX_ROUTES: usize = 16;
const MAX_ROUTE_PATH: usize = 64;
const MAX_ROUTE_BODY: usize = 32768;

/// The eBPF fast path of a server.
///
/// It parses the requests arriving on the server's sockets with an HTTP/1.1
/// parser and answers the ones whose path it has a pre-rendered response for
/// straight from the kernel. Everything else is passed on to the user space
/// server. The fast path stays attached until this value is dropped.
pub struct FastPath<'obj> {
    #[allow(dead_code)]
    skel: FastPathSkel<'obj>,
    #[allow(dead_code)]
    sockops: Link,
    #[allow(dead_code)]
    h1: h1::AttachedParser,
    #[allow(dead_code)]
    h2: h2::AttachedParser,
}

unsafe impl<'obj> Send for FastPath<'obj> {}

unsafe impl<'obj> Sync for FastPath<'obj> {}

/// Returns the value of the `Content-Type` header to serve `file` with, based
/// on its extension.
fn content_type(file: &Path) -> &'static str {
    match file.extension().and_then(|ext| ext.to_str()) {
        Some("html") => "text/html; charset=utf-8",
        Some("js") => "application/javascript",
        Some("css") => "text/css",
        Some("json") => "application/json",
        _ => "application/octet-stream",
    }
}

/// Renders the full HTTP/1.1 response (status line, headers and body) that
/// the fast path will serve verbatim whenever `path` is requested.
fn render_response(file: &Path) -> Result<Vec<u8>> {
    let body = std::fs::read(file)
        .with_context(|| format!("failed to read fastpath asset {}", file.display()))?;

    let mut resp = format!(
        "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nContent-Type: {}\r\nConnection: keep-alive\r\n\r\n",
        body.len(),
        content_type(file),
    )
    .into_bytes();
    resp.extend_from_slice(&body);

    Ok(resp)
}

/// Encodes a header as an HPACK literal without indexing, taking the name from
/// the static table. Not indexing keeps the client's dynamic table untouched,
/// which it has to be: the server never sees this response, so its own encoder
/// would not know about the entry.
fn hpack_literal(name_idx: u8, value: &str) -> Vec<u8> {
    let mut out = vec![0x0F, name_idx - 15];
    out.push(value.len() as u8);
    out.extend_from_slice(value.as_bytes());
    out
}

fn h2_frame(kind: u8, flags: u8, payload: &[u8]) -> Vec<u8> {
    let mut frame = Vec::with_capacity(9 + payload.len());
    frame.extend_from_slice(&(payload.len() as u32).to_be_bytes()[1..]);
    frame.push(kind);
    frame.push(flags);
    // the stream id is only known once a request comes in, the fast path
    // patches it into the frame header before serving
    frame.extend_from_slice(&0u32.to_be_bytes());
    frame.extend_from_slice(payload);
    frame
}

/// Renders the same response as [`render_response`] as an HTTP/2 HEADERS frame
/// followed by a DATA frame. Both carry a zeroed stream id; the returned
/// offsets point at the two spots the fast path has to patch it into.
fn render_h2_response(file: &Path) -> Result<(Vec<u8>, [u32; 2])> {
    let body = std::fs::read(file)
        .with_context(|| format!("failed to read fastpath asset {}", file.display()))?;

    // :status: 200 is a static table entry of its own, so it can be referenced
    // as an indexed field
    let mut hdrs = vec![0x88];
    hdrs.extend_from_slice(&hpack_literal(28, &body.len().to_string()));
    hdrs.extend_from_slice(&hpack_literal(31, content_type(file)));

    let mut resp = h2_frame(0x01, 0x04, &hdrs); // HEADERS, END_HEADERS
    let data_off = resp.len();
    resp.extend_from_slice(&h2_frame(0x00, 0x01, &body)); // DATA, END_STREAM

    // the stream id sits at offset 5 of a frame header
    Ok((resp, [5, data_off as u32 + 5]))
}

impl<'obj> FastPath<'obj> {
    /// Attaches the server's fast path.
    ///
    /// `routes` maps request paths (e.g. `/index.html`) to files on disk. The
    /// contents of those files are pre-rendered into full HTTP responses and
    /// loaded into the eBPF program's `.bss` section, so that requests for a
    /// matching path can be served directly from the fast path without ever
    /// reaching userspace.
    pub fn attach<A: ToSocketAddrs>(
        address: A,
        open_obj: &'obj mut MaybeUninit<libbpf_rs::OpenObject>,
        routes: HashMap<String, PathBuf>,
    ) -> Result<Self> {
        if routes.len() > MAX_ROUTES {
            bail!(
                "too many fastpath routes: {} configured, at most {MAX_ROUTES} supported",
                routes.len()
            );
        }

        // a route is reachable under its plain text path as well as under the
        // huffman encoded one h2 puts on the wire
        let mut prepared = Vec::with_capacity(routes.len());
        for (path, file) in routes.iter() {
            let keys = [path.as_bytes().to_vec(), huffman_encode(path)];
            if keys.iter().any(|key| key.len() > MAX_ROUTE_PATH) {
                bail!("fastpath route path `{path}` is longer than {MAX_ROUTE_PATH} bytes");
            }

            let body = render_response(file)?;
            let (h2_body, h2_sid_offs) = render_h2_response(file)?;

            // a response too large to pre-render is left to the server rather
            // than refused: a path the fast path does not know is one it passes
            // on, which is exactly what should happen to it
            let len = body.len().max(h2_body.len());
            if len > MAX_ROUTE_BODY {
                info!("Not serving `{path}` from the fast path, {len}B exceeds {MAX_ROUTE_BODY}B");
                continue;
            }

            debug!("Serving `{path}` from the fast path");
            prepared.push((keys, body, h2_body, h2_sid_offs));
        }

        let address = address
            .to_socket_addrs()?
            .next()
            .expect("Failed to parse address");

        let skel_builder = FastPathSkelBuilder::default();
        let mut open_skel = skel_builder.open(open_obj)?;
        if tracing::event_enabled!(Level::TRACE) {
            open_skel.progs.msg_verdict.set_log_level(1);
        }

        let ip4 = match address {
            SocketAddr::V4(addr) => Ok(u32::from_ne_bytes(addr.ip().octets())),
            _ => Err(Error::new(
                ErrorKind::InvalidInput,
                "Unsupported address family",
            )),
        }?;

        open_skel.maps.rodata_data.as_mut().unwrap().ip4 = ip4;
        open_skel.maps.rodata_data.as_mut().unwrap().port = address.port() as u32;

        let bss = open_skel.maps.bss_data.as_mut().unwrap();
        for (i, (_, body, h2_body, h2_sid_offs)) in prepared.iter().enumerate() {
            let route = &mut bss.routes[i];
            route.body[..body.len()].copy_from_slice(body);
            route.body_len = body.len() as u32;
            route.h2_body[..h2_body.len()].copy_from_slice(h2_body);
            route.h2_body_len = h2_body.len() as u32;
            route.h2_sid_offs = *h2_sid_offs;
        }

        let skel = open_skel.load()?;
        xbpf::tracing::try_init(skel.object())?;

        // the route index is a hash map, so it can only be populated once the
        // program is loaded and the map created
        for (i, (keys, ..)) in prepared.iter().enumerate() {
            for key in keys {
                let mut padded = [0; MAX_ROUTE_PATH];
                padded[..key.len()].copy_from_slice(key);

                skel.maps
                    .route_idx
                    .update(&padded, &[i as u8], MapFlags::ANY)
                    .with_context(|| format!("failed to index fastpath route {i}"))?;
            }
        }
        let sock_map_fd = skel.maps.sock_map.as_fd().as_raw_fd();
        let prog_fd = skel.progs.msg_verdict.as_fd().as_raw_fd();

        let h1 = h1::Parser::new()
            .match_h2_preface()
            .capture_hdr(&beeper::header::PATH)
            .capture_hdr(&http::header::CONTENT_LENGTH)
            .replace_parse_msg("parse_h1")
            .replace_extract("extract_h1_match")
            .replace_matched("matched_h1")
            .attach(prog_fd)?;

        let h2 = h2::Parser::new()
            .capture_hdr(&beeper::header::PATH)?
            .capture_hdr(&http::header::CONTENT_LENGTH)?
            .replace_parse_msg("parse_h2")
            .replace_extract("extract_h2_match")
            .replace_get_dynamic_table_entry("get_dt_entry")
            .attach(prog_fd)?;

        let cgroup_fd = std::fs::OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_DIRECTORY)
            .open("/sys/fs/cgroup")?
            .into_raw_fd();

        let sockops = skel.progs.monitor_sockets.attach_cgroup(cgroup_fd)?;
        skel.progs.msg_verdict.attach_sockmap(sock_map_fd)?;

        debug!("Server fast path attached");

        Ok(Self {
            sockops,
            skel,
            h1,
            h2,
        })
    }
}
