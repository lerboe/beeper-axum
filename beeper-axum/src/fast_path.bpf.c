#include "beeper.h"
#include "xbpf.h"
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_endian.h>

// The fast path of the example server. It parses the requests arriving on the
// server's sockets and answers the ones it has a pre-rendered response for
// right here, without ever waking up user space.

// Tracks how far an upgraded connection's HTTP/2 handshake has progressed, so
// that a connection present in the map is known to speak HTTP/2.
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 16384);
    __type(key, struct ip4_conn);
    __type(value, int);
} upgraded_conns SEC(".maps");
u32 num_upgraded_conns = 0;

// The client sockets of the server, i.e. the ones `msg_verdict` runs on.
struct {
    __uint(type, BPF_MAP_TYPE_SOCKHASH);
    __uint(max_entries, 16384);
    __type(key, struct ip4_conn);
    __type(value, int);
} sock_map SEC(".maps");

// The address of the server, set by user space before the program is loaded.
volatile const u32 ip4;
volatile const u32 port;

// Fast path routing table: a fixed-size, userspace-populated table (backed by
// the program's .bss section) holding pre-rendered HTTP responses. Populated by
// userspace before the program is attached.
#define MAX_ROUTES 16
#define MAX_ROUTE_PATH 64
#define MAX_ROUTE_BODY 32768

// The matches the parsers are configured with, in the order in which user
// space captures them.
#define H1_PREFACE_MID 0
#define H1_PATH_MID 1
#define H1_CONTENT_LENGTH_MID 2
#define H2_PATH_MID 0
#define H2_CONTENT_LENGTH_MID 1

#define H2_SETTINGS_FRAME 0x04
#define H2_ACK_FLAG 0x01

// how far along an upgraded connection is. only once the handshake completed
// can the fast path answer on it without preempting the server's SETTINGS.
#define H2_UPGRADED 1
#define H2_HANDSHAKED 2

// The number of entries of the HPACK static table. A dynamic table entry is
// addressed by the index that follows them, see `BEEPER_H2_GET_DT_ENTRY`.
#define STATIC_TABLE_SIZE 61

// The frame type the fast path prepends its dynamic table changes to a
// forwarded message under.
//
// 0xFB is not assigned by RFC 7540, so an HTTP/2 implementation that does not
// know about it is required to discard it rather than choke on it. The user
// space wrapper (see `listener.rs`) picks it out of the stream before the
// server's own codec ever sees it.
#define DT_SYNC_FRAME_TYPE 0xFB

// The most entries a single sync frame carries. A table larger than this
// cannot be replayed, so the fast path stops answering on that connection
// instead of letting the two tables drift apart silently.
#define MAX_SYNC_ENTRIES 8

// The most bytes a sync frame's body can take up. An entry needs at most two
// length bytes plus a name and a value, both of which the parser truncates to
// `BEEPER_H2_FIELD_MAXLEN`.
#define MAX_SYNC_BODY (MAX_SYNC_ENTRIES * (2 + 2 * BEEPER_H2_FIELD_MAXLEN))

// The size of the buffer the body is built up in, with room to spare so that
// an offset clamped to `MAX_SYNC_BODY` is always well inside it.
#define MAX_SYNC_BUF 4096

// The longest name or value a sync frame spells out. HPACK would encode a
// longer string with a multi byte length, which the encoder below does not
// bother to emit.
#define MAX_SYNC_FIELD 126

// Whether the fast path has answered a request on a connection since user
// space last saw one, i.e. whether the two dynamic tables may have drifted
// apart. Set when a request is served, cleared once the difference has been
// handed over.
//
// Only a flag is kept, not a count of what changed: a request the fast path
// answers can evict entries as well as add them, and once user space is
// holding entries the client has already dropped there is no set of additions
// that puts the two back in step. The sync frame therefore replays the whole
// table rather than a delta.
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 16384);
    __type(key, struct ip4_conn);
    __type(value, u8);
} dt_dirty SEC(".maps");

// Scratch space for the sync frame that is being built, along with the entry
// that is being read out of the dynamic table into it. Both are far too large
// to live on the stack the verifier allows.
struct dt_sync_buf {
    u8 data[MAX_SYNC_BUF];
    u32 len;
    struct header_field hf;
};

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, u32);
    __type(value, struct dt_sync_buf);
} dt_sync_scratch SEC(".maps");

struct route {
    // the response rendered as HTTP/1.1
    u8 body[MAX_ROUTE_BODY];
    u32 body_len;

    // the same response rendered as an h2 HEADERS and DATA frame, along with
    // the offsets of the stream ids in the two frame headers
    u8 h2_body[MAX_ROUTE_BODY];
    u32 h2_body_len;
    u32 h2_sid_offs[2];
};

struct route routes[MAX_ROUTES];

// The request path, zero padded to a fixed size so that it can be hashed.
struct route_key {
    u8 path[MAX_ROUTE_PATH];
};

// Maps a request path to its index in `routes`. Populated by userspace once the
// program is loaded, as a hash map only exists from then on. A route is
// reachable under several paths, the plain text one and the huffman encoded one
// h2 puts on the wire, hence the two entries per route.
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 2 * MAX_ROUTES);
    __type(key, struct route_key);
    __type(value, u8);
} route_idx SEC(".maps");

// The functions beeper replaces with an HTTP/1.1 parser.
BEEPER_MATCHED(matched_h1)
BEEPER_EXTRACT_MATCH(extract_h1_match)
BEEPER_H1_PARSE_MSG(parse_h1)

// The functions beeper replaces with an HTTP/2 parser.
BEEPER_EXTRACT_MATCH(extract_h2_match)
BEEPER_H2_PARSE_MSG(parse_h2)
BEEPER_H2_GET_DT_ENTRY(get_dt_entry)

// Appends `len` bytes of `src` to `buf`. Returns 0 on success, -1 if the
// buffer is full.
static __always_inline int sync_put(struct dt_sync_buf *buf, const u8 *src, u32 len) {
    u32 off = buf->len;
    if (len > MAX_SYNC_FIELD || off + len > MAX_SYNC_BODY) return -1;

    u32 i;
    bpf_for(i, 0, len) {
        u32 j = i;
        bpf_clamp_uminmax(j, 0, MAX_SYNC_FIELD - 1);

        // clamping rather than masking, as clang folds a mask away again once
        // it thinks the bound check above already established the range
        u32 o = off + j;
        bpf_clamp_uminmax(o, 0, MAX_SYNC_BODY - 1);

        buf->data[o] = src[j];
    }

    buf->len = off + len;

    return 0;
}

// Appends the single byte `c` to `buf`. Returns 0 on success, -1 if the buffer
// is full.
static __always_inline int sync_put_byte(struct dt_sync_buf *buf, u8 c) {
    u32 off = buf->len;
    if (off + 1 > MAX_SYNC_BODY) return -1;
    bpf_clamp_uminmax(off, 0, MAX_SYNC_BODY - 1);

    buf->data[off] = c;
    buf->len = off + 1;

    return 0;
}

// Renders the whole of `conn`'s dynamic table into `buf` as an HPACK block,
// `n` entries, oldest first, so that a decoder replaying the block ends up
// holding exactly what the fast path last saw the client holding.
//
// This is a resync rather than a delta: a request the fast path answered may
// have evicted entries as well as added them, and only a decoder that starts
// from an empty table ends up agreeing with the client again. Emptying it is
// the reader's job, see `Decoder::prime` in the patched `vendor/h2` -- the size
// the table has to be restored to afterwards is the one the reader announced,
// which is not something the fast path knows.
//
// Every entry is written as a literal header field with incremental indexing
// and a new name (RFC 7541 section 6.2.1), which is the representation that
// makes a decoder add it to its dynamic table. Names and values are copied
// straight out of the mirrored table, in whichever form the client sent them.
//
// Returns 0 if the whole table was written, -1 if an entry could not be read or
// does not fit, in which case `buf` is left incomplete and must be discarded.
static __always_inline int render_dt_sync(struct dt_sync_buf *buf, const struct ip4_conn *conn, u32 n) {
    u32 i;
    bpf_for(i, 0, n) {
        // the entries to replay are the `n` most recent ones, i.e. HPACK
        // indices 1 through `n`, and the oldest of those has to go first
        u32 idx = STATIC_TABLE_SIZE + (n - i);
        if (get_dt_entry(conn, idx, &buf->hf) < 0) {
            bpf_warn("dt sync: entry %u is gone", idx);
            return -1;
        }

        u32 key_len = buf->hf.key_len;
        u32 val_len = buf->hf.val_len;
        if (key_len == 0 || key_len > MAX_SYNC_FIELD || val_len > MAX_SYNC_FIELD) {
            bpf_warn("dt sync: entry %u does not fit", idx);
            return -1;
        }

        // the entry is copied over in whatever form it arrived in, so the H bit
        // has to say which one that was rather than assume Huffman
        u8 key_huff = buf->hf.key_huff ? 0x80 : 0;
        u8 val_huff = buf->hf.val_huff ? 0x80 : 0;

        if (sync_put_byte(buf, 0x40) < 0) return -1;
        if (sync_put_byte(buf, key_huff | key_len) < 0) return -1;
        if (sync_put(buf, buf->hf.key, key_len) < 0) return -1;
        if (sync_put_byte(buf, val_huff | val_len) < 0) return -1;
        if (sync_put(buf, buf->hf.val, val_len) < 0) return -1;
    }

    return 0;
}

// Prepends the dynamic table of `msg`'s connection to `msg`, as a frame of
// type `DT_SYNC_FRAME_TYPE`, so that user space can bring its own table back in
// line with it.
//
// The frame goes in front of the message rather than replacing it: the message
// still has to reach the server, it just has to be preceded by the table
// updates that make its HPACK indices resolve to the right fields.
//
// Returns the number of bytes prepended, or -1 if the frame could not be
// built, in which case `msg` is left untouched.
static __always_inline int prepend_dt_sync(struct sk_msg_md *msg, const struct ip4_conn *conn, u32 n) {
    u32 zero = 0;
    struct dt_sync_buf *buf = bpf_map_lookup_elem(&dt_sync_scratch, &zero);
    if (!buf) return -1;

    // the frame header is written once the body's length is known, so the body
    // is built up behind it
    buf->len = 0;
    if (render_dt_sync(buf, conn, n) < 0) return -1;

    u32 body_len = buf->len;
    if (body_len == 0 || body_len > MAX_SYNC_BODY) return -1;
    bpf_clamp_uminmax(body_len, 1, MAX_SYNC_BODY);

    u32 frame_len = 9 + body_len;
    u32 orig_size = msg->size;

    if (bpf_msg_push_data(msg, 0, frame_len, 0) < 0) return -1;
    if (bpf_msg_pull_data(msg, 0, frame_len, 0) < 0) return -1;

    u8 *data = (u8 *)(long)msg->data;
    u8 *data_end = (u8 *)(long)msg->data_end;

    // the bound has to be established on the very pointer that is written
    // through, and with a constant offset, or the verifier does not carry it
    // over to `data` itself
    if (data + 9 > data_end) return -1;

    data[0] = (body_len >> 16) & 0xFF;
    data[1] = (body_len >> 8) & 0xFF;
    data[2] = body_len & 0xFF;
    data[3] = DT_SYNC_FRAME_TYPE;
    data[4] = 0;
    // the sync frame describes the connection, not a stream
    data[5] = 0;
    data[6] = 0;
    data[7] = 0;
    data[8] = 0;

    u32 i;
    bpf_for(i, 0, body_len) {
        u32 j = i;
        bpf_clamp_uminmax(j, 0, MAX_SYNC_BODY - 1);

        // same again: the check has to sit on `p`, not on a pointer `p` is
        // later derived from
        u8 *p = data + 9 + j;
        if (p + 1 > data_end) return -1;

        *p = buf->data[j];
    }

    bpf_debug("dt sync: prepended %u entries (%uB) to a %uB msg", n, frame_len, orig_size);

    return frame_len;
}

// Writes `sid` into the frame header at `off`, where h2 keeps the stream id.
static __always_inline int write_sid(u8 *data, u8 *data_end, u32 off, u32 sid) {
    if (off + 4 > MAX_ROUTE_BODY) return -1;
    bpf_clamp_uminmax(off, 0, MAX_ROUTE_BODY - 4);

    // the bound has to be established on the very pointer that is written
    // through, deriving another one from `data` loses it again
    u8 *p = data + off;
    if (p + 4 > data_end) return -1;

    p[0] = (sid >> 24) & 0xFF;
    p[1] = (sid >> 16) & 0xFF;
    p[2] = (sid >> 8) & 0xFF;
    p[3] = sid & 0xFF;

    return 0;
}

// Overwrites `msg` in place with `r`'s pre-rendered response and redirects it
// straight back to the sender's socket (BPF_F_INGRESS), bypassing userspace
// entirely. `sid` is the h2 stream to answer on, or 0 to serve the HTTP/1.1
// rendering. Returns 0 on success, < 0 if the response could not be served.
static __always_inline int serve_route(struct sk_msg_md *msg, struct ip4_conn *ikey, struct route *r, u32 sid) {
    bool is_h2 = (sid != 0);
    u32 body_len = is_h2 ? r->h2_body_len : r->body_len;
    if (body_len == 0 || body_len > MAX_ROUTE_BODY) return -1;

    u32 orig_size = msg->size;

    if (body_len > orig_size) {
        if (bpf_msg_push_data(msg, orig_size, body_len - orig_size, 0) < 0) return -1;
    } else if (body_len < orig_size) {
        if (bpf_msg_pop_data(msg, body_len, orig_size - body_len, 0) < 0) return -1;
    }

    if (bpf_msg_pull_data(msg, 0, body_len, 0) < 0) return -1;

    u8 *data = (u8 *)(long)msg->data;
    u8 *data_end = (u8 *)(long)msg->data_end;

    // after the push/pop above, the message is exactly `body_len` bytes, so
    // the packet bound check below is sufficient on its own to stop the copy
    // at the right place.
    u32 k;
    bpf_for(k, 0, MAX_ROUTE_BODY) {
        if (data + k + 1 > data_end) break;

        u32 idx = k;
        bpf_clamp_uminmax(idx, 0, MAX_ROUTE_BODY - 1);
        data[k] = is_h2 ? r->h2_body[idx] : r->body[idx];
    }

    // the rendered frames carry a zeroed stream id, the one of the request
    // this responds to is only known here
    if (is_h2) {
        if (write_sid(data, data_end, r->h2_sid_offs[0], sid) < 0) return -1;
        if (write_sid(data, data_end, r->h2_sid_offs[1], sid) < 0) return -1;
    }

    if (bpf_msg_redirect_hash(msg, &sock_map, ikey, BPF_F_INGRESS) < 0) return -1;

    bpf_msg_apply_bytes(msg, body_len);

    return 0;
}

// Looks up the captured request path in `route_idx` and, on a match, serves
// the pre-rendered response directly from the fast path. Returns 0 if a route
// was served (the caller should return SK_PASS immediately without further
// processing `msg`), < 0 otherwise.
static __always_inline int try_serve_route(struct sk_msg_md *msg, struct ip4_conn *ikey, struct hdr_str *path, u32 sid) {
    if (path->len == 0 || path->len > MAX_ROUTE_PATH) return -1;

    u32 len = path->len;
    bpf_clamp_uminmax(len, 1, MAX_ROUTE_PATH);

    struct route_key key = { 0 };
    if (bpf_probe_read_kernel(key.path, len, path->ptr) < 0) return -1;

    u8 *idx = bpf_map_lookup_elem(&route_idx, &key);
    if (!idx) {
        bpf_warn("No route found for request path");
        return -1;
    };

    u32 i = *idx;
    bpf_clamp_uminmax(i, 0, MAX_ROUTES - 1);

    return serve_route(msg, ikey, &routes[i], sid);
}

// Returns the value of the captured `Content-Length` header, or -1 if it is
// empty or not a number. It is what tells the fast path how far the body of a
// request reaches, as the parser itself stops at the end of the header block.
static __always_inline int parse_content_length(const struct hdr_str *content_length) {
    char digits[16] = { 0 };
    u32 n = content_length->len;
    if (n > 0) {
        bpf_clamp_uminmax(n, 1, sizeof(digits) - 1);

        if (bpf_probe_read_kernel(digits, n, content_length->ptr) == 0) {
            unsigned long len = 0;
            if (bpf_strtoul(digits, n, 0, &len) >= 0 && len > 0) {
                return len;
            }
        }
    }

    return -1;
}

// Parses the request the message carries and serves it from the fast path if it
// asks for one of the pre-rendered routes. Anything else is passed on to the
// user space server.
SEC("sk_msg")
int msg_verdict(struct sk_msg_md *msg) {
    // socket identifier of the ingress connection
    struct ip4_conn ikey = {
        .local = {
            .ip4 = msg->local_ip4,
            .port = msg->local_port
        },
        .remote = {
            .ip4 = msg->remote_ip4,
            .port = bpf_ntohl(msg->remote_port)
        }
    };

    bool is_downstream = (ikey.remote.ip4 == ip4 && ikey.remote.port == port);
    bpf_debug("Processing %dB msg from [%pI4:%u->%pI4:%u] (downstream: %d)", msg->size, &ikey.local.ip4, ikey.local.port, &ikey.remote.ip4, ikey.remote.port, is_downstream);

    int *conn_state = bpf_map_lookup_elem(&upgraded_conns, &ikey);
    bool is_h2 = (conn_state != NULL);
    // the map entry may be reallocated by the update below, so keep a copy
    int h2_state = is_h2 ? *conn_state : 0;
    int msg_len = -1;
    struct parse_res pres = { 0 };
    struct hdr_str path = { 0 };
    int path_res = -1;
    u32 sid = 0;

    // whether the two dynamic tables may have drifted apart, and what it takes
    // to replay the mirrored one if they have
    bool dt_stale = false;
    u32 dt_count = 0;

    if (is_h2) {
        struct h2_frame frame = { 0 };
        msg_len = parse_h2(msg, &pres, &frame);
        if (msg_len >= 0) {
            sid = frame.sid;

            u8 *dirty = bpf_map_lookup_elem(&dt_dirty, &ikey);
            dt_stale = (dirty != NULL && *dirty != 0);

            // the table as it stands before this message, which is the state
            // user space has to reach before decoding it. the entries this
            // message itself adds are none of the sync frame's business, user
            // space adds those when it decodes it.
            dt_count = frame.dt_count_before;

            // a client only acks SETTINGS once it has received the server's, so
            // this is the point from which a response cannot preempt the
            // handshake anymore
            if (frame.type == H2_SETTINGS_FRAME && (frame.flags & H2_ACK_FLAG) && h2_state < H2_HANDSHAKED) {
                bpf_trace("HTTP/2 handshake complete");

                h2_state = H2_HANDSHAKED;
                bpf_map_update_elem(&upgraded_conns, &ikey, &h2_state, BPF_ANY);
            }

            struct hdr_str content_length = { 0 };
            if (extract_h2_match(msg, &pres, H2_CONTENT_LENGTH_MID, &content_length) == 0) {
                bpf_trace("content length: %s", content_length.ptr);

                int res = parse_content_length(&content_length);
                if (res > 0) msg_len += res;
            }

            path_res = extract_h2_match(msg, &pres, H2_PATH_MID, &path);
        }
    }
    else {
        msg_len = parse_h1(msg, &pres);
        if (msg_len > 0) {
            if (matched_h1(msg, &pres, H1_PREFACE_MID)) {
                bpf_trace("Upgrading connection to HTTP/2");

                int val = H2_UPGRADED;
                bpf_map_update_elem(&upgraded_conns, &ikey, &val, BPF_ANY);
                num_upgraded_conns++;

                // the H2 preface is 24 bytes long
                bpf_msg_apply_bytes(msg, 24);

                return SK_PASS;
            }

            struct hdr_str content_length = { 0 };
            if (extract_h1_match(msg, &pres, H1_CONTENT_LENGTH_MID, &content_length) == 0) {
                bpf_trace("content length: %s", content_length.ptr);

                int res = parse_content_length(&content_length);
                if (res > 0) msg_len += res;
            }

            path_res = extract_h1_match(msg, &pres, H1_PATH_MID, &path);
        }
    }

    // answering before the h2 handshake completed would preempt the server's
    // SETTINGS, so such requests are left to userspace
    bool can_serve = (path_res == 0) && (!is_h2 || h2_state >= H2_HANDSHAKED);
    if (path_res == 0 && !can_serve) {
        bpf_debug("Not serving request, HTTP/2 handshake is still in flight");
    }

    // a table too large to replay cannot be handed over, so answering here
    // would strand user space for good. the request goes to it instead, which
    // is always safe: decoding it is what keeps the two tables in step.
    if (can_serve && dt_count > MAX_SYNC_ENTRIES) {
        bpf_warn("Not serving request, the dynamic table holds %u entries", dt_count);
        can_serve = false;
    }

    if (can_serve) {
        if (try_serve_route(msg, &ikey, &path, sid) == 0) {
            bpf_debug("Served request");

            // user space knows nothing of this request, and the header block
            // just decoded may well have changed the dynamic table, so the
            // next message it does get has to carry the table with it
            if (is_h2) {
                u8 dirty = 1;
                bpf_map_update_elem(&dt_dirty, &ikey, &dirty, BPF_ANY);
            }

            return SK_PASS;
        }
    }

    // the message is going to user space, so this is the moment to hand the
    // dynamic table over. once it is in front of the message, user space
    // rebuilds the table from it and then decodes the message against it,
    // ending up exactly where the fast path's mirror is.
    if (is_h2 && msg_len >= 0 && dt_stale) {
        int synced = prepend_dt_sync(msg, &ikey, dt_count);
        if (synced < 0) {
            bpf_error("Failed to sync dynamic table, dropping connection");

            // letting the message through now would have user space decode it
            // against a table that no longer matches the client's, which
            // desyncs HPACK for good. cutting the connection is the lesser evil.
            return SK_DROP;
        }

        msg_len += synced;

        u8 dirty = 0;
        bpf_map_update_elem(&dt_dirty, &ikey, &dirty, BPF_ANY);
    }

    bpf_msg_apply_bytes(msg, msg_len);

    return SK_PASS;
}

SEC("sockops")
int monitor_sockets(struct bpf_sock_ops *ops) {
    if (ops->op == BPF_SOCK_OPS_PASSIVE_ESTABLISHED_CB || ops->op == BPF_SOCK_OPS_ACTIVE_ESTABLISHED_CB) {
        // we don't want to get called anymore for this connection
        bpf_sock_ops_cb_flags_set(ops, 0);

        struct ip4_conn skey = {
            .local = {
                .ip4 = ops->local_ip4,
                .port = ops->local_port
            },
            .remote = {
                .ip4 = ops->remote_ip4,
                .port = bpf_ntohl(ops->remote_port)
            }
        };

        bpf_debug("Established socket [%pI4:%u->%pI4:%u]", &skey.local.ip4, skey.local.port, &skey.remote.ip4, skey.remote.port);

        if (skey.remote.ip4 == ip4 && skey.remote.port == port) {
            if (bpf_sock_hash_update(ops, &sock_map, &skey, BPF_ANY) < 0) {
                bpf_error("Failed to add socket [%pI4:%u->%pI4:%u]", &skey.local.ip4, skey.local.port, &skey.remote.ip4, skey.remote.port);
                return SK_PASS;
            }

            bpf_debug("Add socket [%pI4:%u->%pI4:%u]", &skey.local.ip4, skey.local.port, &skey.remote.ip4, skey.remote.port);
        }
    }

    return SK_PASS;
}
