//! The limits of the twin (docs/design.md §19 step 13): what one simulated loop and its network
//! hold. Every table is static and every walk is bounded by one of these.
const std = @import("std");
const core = @import("core");

/// The most operations one loop holds in flight: its slot table.
pub const operations_max: usize = 4096;

/// The most events waiting to be delivered by a tick. An operation ends in one final event and a
/// multishot delivers many, so this is above the slot count.
pub const events_pending_max: usize = 8192;

/// The most sockets one network holds, datagram and stream together.
pub const sockets_max: usize = 64;

/// The most scripted servers one network answers for: the servers a configuration may name.
pub const servers_max = core.constants.servers_max;

/// The most datagrams waiting to be delivered, and the room each holds: a reply is at most the
/// UDP payload cocuyo advertises.
pub const datagrams_pending_max: usize = 256;
pub const datagram_bytes_max = core.constants.udp_payload_bytes_default;

/// The most stream connections open at once, and the octets each direction of one buffers.
pub const connections_max: usize = 16;
pub const stream_bytes_max: usize = 16384;

/// Buffer groups and the buffers each holds, as rotor bounds them.
pub const buffer_groups_max: usize = 4;
pub const buffers_per_group_max: usize = 256;

/// What a socket's kernel buffers may be sized to here, which is the shape rotor measured on
/// macOS: what is asked for up to the cap, the cap above it, and a refusal above the second
/// bound, because that kernel refuses rather than caps once a socket is already large.
pub const socket_buffer_bytes_cap: usize = 1 << 20;
pub const socket_buffer_bytes_refuse_above: usize = 1 << 28;

/// The alignment rotor asks of a buffer ring and of the loop's memory, and the octets one ring
/// entry takes, so a caller's arrays are sized and aligned the same for the twin and for rotor.
///
/// The ring's alignment was 64 here until 2026-09-22, when rotor asks 64 KiB on both of its
/// backends. A twin that asks for less cannot catch a caller whose memory is not aligned enough,
/// and it did not: `IORING_REGISTER_PBUF_RING` refuses a ring that is not page-aligned, and the
/// engine met that refusal on Linux with every test on the twin green.
pub const buffer_ring_alignment: usize = 64 * 1024;
pub const buffer_ring_entry_bytes: usize = 16;
pub const memory_alignment: usize = 64;

/// The prefix rotor puts before a datagram's payload in a group buffer: a head, then room for
/// the addresses and the control data. 16 + 32 + 144.
pub const prefix_head_bytes: usize = 16;
pub const name_reserve_default: usize = 32;
pub const control_reserve_default: usize = 144;

/// The longest one `tick` may wait: rotor's `wait_ns_max`, ten seconds, kept so a tick valid here
/// is valid there. A caller that waits longer ticks again, as a caller of rotor must.
pub const wait_ns_max: u64 = 10 * ns_per_s;

/// The most events one `tick` may be handed room for: rotor's `batch_max`.
pub const batch_max: usize = 4096;

/// How many ticks `drain` runs before it gives up on an operation that will not end.
pub const drain_rounds_max: usize = 64;

/// The generation a handle starts at; zero is `Handle.none`.
pub const generation_first: u32 = 1;

/// The most octets one transfer moves, rotor's bound.
pub const transfer_bytes_max: usize = 1 << 30;

/// The address the scripted servers sit at: the documentation range of RFC 5737, one octet per
/// server, on port 53.
pub const server_prefix = [_]u8{ 192, 0, 2 };
pub const server_octet_first: u8 = 53;
pub const server_port = core.constants.port_dns_default;

/// The port a scripted server also accepts streams on, so a `Server.tcp_port` of its own is a
/// thing a test can set (docs/design.md §19 step 11).
pub const server_tcp_port: u16 = 5353;

/// The address a client socket bound to no address gets, and the range of ports handed out.
pub const client_address = [_]u8{ 192, 0, 2, 1 };
pub const client_port_first: u16 = 40000;

/// The prefix of a scripted AAAA answer: the documentation prefix of RFC 3849, `2001:db8::`.
pub const answer_v6_prefix = [_]u8{ 0x20, 0x01, 0x0d, 0xb8 };

/// The default TTL of a scripted answer.
pub const answer_ttl_seconds: u32 = 300;

/// The server cookie every scripted server hands out, sixteen octets as RFC 9018 §4 has it.
pub const server_cookie_bytes: usize = 16;

/// The most octets one scripted stream reply is split into per delivery, at the least: a chunk
/// is drawn between this and what the buffer holds, so framing is exercised.
pub const stream_chunk_bytes_min: usize = 1;

/// One second, spelled out because nothing under `src/` names `std.time` (CLAUDE.md
/// non-negotiable 4).
pub const ns_per_s: u64 = 1_000_000_000;

/// The octets of one draw the scripted server reads its decisions from: one chance per octet,
/// and the delay from the high half.
pub const dice_drop_shift: u6 = 0;
pub const dice_servfail_shift: u6 = 8;
pub const dice_nxdomain_shift: u6 = 16;
pub const dice_truncate_shift: u6 = 24;
pub const dice_delay_shift: u6 = 32;

/// The port a scripted server speaks the twin's TLS on, and nothing else: RFC 7858 §3.1 keeps it
/// for DNS over TLS alone.
pub const server_tls_port = core.constants.port_dns_tls_default;

/// The port a scripted server hears the twin's QUIC on over TCP, as a channel's TCP link writes it:
/// TCP's 443, which is where a DoH template that names no port goes (RFC 9110 §4.2.2).
pub const server_https_port: u16 = 443;

/// The twin's TLS records keep the shape of a real one (RFC 9846 §5.1): a content type, two
/// octets of legacy version, and a two-octet length, then that many octets unsealed.
pub const tls_record_header_bytes: usize = 5;
pub const tls_content_alert: u8 = 21;
pub const tls_content_handshake: u8 = 22;
pub const tls_content_application: u8 = 23;
pub const tls_legacy_version: u16 = 0x0303;
/// Where the version and the length sit in the header.
pub const tls_record_version_at: usize = 1;
pub const tls_record_length_at: usize = 3;

/// A `close_notify` alert: level warning, description `close_notify` (RFC 9846 §6).
pub const tls_close_notify = [_]u8{ 1, 0 };
/// An alert's level octet when it is fatal (RFC 9846 §6).
pub const tls_alert_fatal: u8 = 2;
/// The fatal alert the twin's session sends for a handshake it refuses: level fatal, description
/// `handshake_failure` (RFC 9846 §6, §6.2).
pub const tls_alert_handshake_failure = [_]u8{ tls_alert_fatal, 40 };

/// The most the twin's TLS carries in one record: a framed query at its longest, or a framed
/// answer the size of the twin's largest datagram.
pub const tls_payload_bytes_max: usize = core.constants.tcp_prefix_bytes + datagram_bytes_max;

/// What one call to the twin's session may make before the engine takes it out: one record at
/// its longest.
pub const tls_out_bytes_max: usize = tls_record_header_bytes + tls_payload_bytes_max;

/// The port a scripted server speaks the twin's QUIC on: UDP's 853, which RFC 9250 §4.1.1 names
/// for DoQ. It is TCP's 853 for DoT as well, and the socket's kind tells them apart.
pub const server_quic_port = core.constants.port_dns_tls_default;

/// The longest datagram the twin's QUIC makes, which is what a pending datagram holds.
pub const quic_datagram_bytes_max = datagram_bytes_max;

/// A QUIC item of the twin's: one octet naming what happened, four naming the stream it happened
/// on, and two giving the length of the octets after them (sim_quic.zig).
pub const quic_item_header_bytes: usize = 7;
pub const quic_item_stream_at: usize = 1;
pub const quic_item_length_at: usize = 5;

/// The most items one datagram holds, which bounds every walk over one: a datagram of items with
/// nothing after their headers.
pub const quic_items_per_datagram_max: usize = quic_datagram_bytes_max / quic_item_header_bytes;

/// What a client connection keeps to send, and how much of it a request may not take: room for
/// every short item it still owes, a cancel for each of the engine's streams among them.
pub const quic_pending_bytes_max: usize = 16384;
pub const quic_pending_reserve_bytes: usize = 2048;

/// The distance between two of a client's bidirectional streams: 0, 4, 8, and on (RFC 9000 §2.1).
pub const quic_stream_step: u64 = 4;

/// The longest ALPN token a scripted server keeps from a client's hello, and the one it names
/// when its script says to negotiate another protocol than the one offered: HTTP/1.1's, which no
/// connection of the engine's offers (RFC 7301 §6).
pub const quic_alpn_bytes_max: usize = 16;
pub const quic_alpn_other = "http/1.1";

/// The exchanges the twin's channel holds at once, as colibri's channel holds 16
/// (sim_channel.zig): past them a request waits in the engine's queue (docs/design.md §24,
/// request rule 21).
pub const channel_exchanges_max: usize = 16;

/// The steps a test or the replay may queue on the twin's channel before it says them, one at
/// each of the engine's reads: the longest a test queues, chosen, not measured.
pub const channel_steps_max: usize = 16;

/// The octets the twin's channel writes on a link at once: one item of the twin's QUIC with
/// nothing after its header, framed over TCP as `sim_quic_stream.zig` frames one.
pub const channel_output_bytes_max: usize = core.constants.tcp_prefix_bytes + quic_item_header_bytes;

// A constant with no type is a `comptime_int`, which takes the type of a narrow runtime value it
// meets in a sum. The lint rule reads the shape of each value, and this reads the type, so an
// alias or a call that gives a `comptime_int` is caught here (docs/design.md §16 decision 40).
test "each integer constant here has a type" {
    inline for (@typeInfo(@This()).@"struct".decls) |declaration| {
        const untyped = @TypeOf(@field(@This(), declaration.name)) == comptime_int;
        try std.testing.expectEqualStrings("", if (untyped) declaration.name else "");
    }
}
