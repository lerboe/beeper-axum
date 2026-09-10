use beeper::build::clang_args;
use xbpf::build::Builder;

fn main() {
    Builder::new()
        .clang_arg(clang_args().iter())
        .tracing_ring_buf_size(32768)
        .export_headers()
        .build();
}
