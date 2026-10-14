//! The limits of the I/O engine (docs/design.md §19 step 13): what one engine holds beside the
//! lookups its options size and the cache its caller hands it the memory of.
const std = @import("std");
const core = @import("cocuyo").core;

/// The lookups an engine holds in flight, when the caller says nothing.
pub const lookups_default: usize = 256;

/// The slots of the cache a caller with no number of its own hands an engine: a thousand, which
/// §18 measures at 2.9 MiB, and at 49% to 60% of a real log's questions answered with no packet.
/// The README and the examples declare this many. It is no default the engine takes: an engine
/// holds no cache memory, and has the cache it is handed the memory of, or none (docs/design.md
/// §19 step 13, the cache's memory; §16 decision 37).
pub const cache_slots_default: usize = 1024;

/// The high sixteen bits of every `user_data` the engine submits, so a caller sharing the loop
/// tells the engine's events from its own. One by default; a caller with several engines on
/// one loop gives each its own.
pub const tag_default: u16 = 1;

/// Where the tag and the kind sit in a `user_data`, above the index in the low bits.
pub const tag_shift: u6 = 48;
pub const kind_shift: u6 = 40;
pub const index_mask: u64 = (1 << kind_shift) - 1;

/// The buffers the datagram group holds, and the octets of each: rotor's prefix plus the payload
/// cocuyo advertises, rounded up to a power of two the ring wants.
pub const group_buffers_default: usize = 64;
pub const buffer_bytes: usize = 2048;
pub const group_id: u16 = 0;

/// The most operations and entries the loop is asked to hold for one engine: a receive per
/// server, a send per lookup, one timer, and slack for the closes.
pub const loop_operations_slack: usize = 16;

/// The TCP connections one engine keeps, when the caller says nothing. One: every lookup that
/// needs a stream to the same server pipelines onto it (RFC 7766 §6.2.1.1), and a caller that
/// asks several servers over TCP at once raises it. Each costs a message buffer.
pub const tcp_connections_default: usize = 1;

/// The longest message a length prefix can describe (RFC 7766 §8), which is what one connection
/// assembles its chunks into. A stream exists for the answers a datagram cannot carry, so the
/// buffer is the whole of what one can say.
pub const tcp_message_bytes_max = core.constants.message_bytes_max;

/// The stream chunks arrive in a group of their own: a datagram group carries rotor's prefix
/// before every payload, and a stream has no peer to name.
pub const tcp_group_id: u16 = 1;

/// The most alignment a buffer group's storage may claim for itself. The loader keeps page
/// alignment and nothing larger, and the smallest page of any target cocuyo builds for is 4 KiB,
/// so a type that claims more makes a promise some platform breaks — and in ReleaseSafe the
/// optimizer believes the promise (docs/design.md §19 step 13). The ring's own 64 KiB is found at
/// run time inside the storage instead.
pub const storage_alignment_max: usize = 4096;
pub const tcp_chunk_bytes: usize = 2048;
pub const tcp_group_buffers_default: usize = 8;

/// How long a connection nobody is using is kept. Ten seconds, chosen and not measured, which is
/// short by the standard RFC 7766 §6.2.3 sets a client.
pub const tcp_idle_ns_default: u64 = 10_000_000_000;

/// Where a receive's generation sits in its `user_data`, above the server's index: a socket
/// that has been replaced has a generation of its own, so the end of the receive it left behind
/// is told from the one now armed. The generation is thirty-two bits, which the index's forty
/// hold above the server's eight.
pub const receive_generation_shift: u6 = 8;
pub const receive_index_mask: usize = (1 << receive_generation_shift) - 1;

/// Where a connection's incarnation sits in the `user_data` of its connect and its receive, above
/// the connection's slot, so the event of an opening of the slot that is gone is told from the
/// current one's (docs/design.md §19 step 13, the stream's rule 2). A slot fits in the octet
/// below it.
pub const tcp_incarnation_shift: u6 = 8;
pub const tcp_slot_mask: usize = (1 << tcp_incarnation_shift) - 1;

/// The polls one drive makes for one lookup at most, which bounds the drive's loop: each server
/// and pass the lookup can fail over to within one drive costs two, one to ask for the
/// connection and one to send on it, and its end one more. A drive that stopped short of this
/// left a lookup on the ready list with its query unsent and nothing to wake it (the stream's
/// rule 8).
pub const drive_polls_per_lookup_max: usize = 2 * core.constants.servers_max * core.constants.attempts_max + 1;

/// What one connection asks of the loop: the connect, and then the receive that replaces it, and
/// over TLS a send of the session's own records (docs/design.md §21).
pub const loop_operations_per_connection: usize = 3;

/// What a connection's frame holds past its partial message in the clear: one chunk. A connection
/// takes a chunk whole before it hands over the messages the chunk ends. The chunk that ends one
/// message can start the next (docs/design.md §19 step 13, the stream's rule 11).
pub const tcp_frame_room_bytes: usize = tcp_chunk_bytes;

/// What a connection's frame holds past its partial message over TLS: the body of one record at
/// its longest. The session opens a whole record into the frame after the partial message.
/// colibri asks for room as long as the record's body (RFC 9846 §5.2; §21, TLS rule 7).
pub const tls_frame_room_bytes: usize = tls_record_body_bytes_max;

/// The most whole messages a connection's frame holds at once, which bounds the loop over it.
/// Each message is at least its two-octet prefix (RFC 1035 §4.2.2), and a frame over TLS is the
/// longest. So the loop hands over every whole message, and none waits for a chunk that may not
/// come (the stream's rule 11).
pub const tcp_messages_per_frame_max: usize = (core.constants.tcp_prefix_bytes + tcp_message_bytes_max +
    @max(tcp_frame_room_bytes, tls_frame_room_bytes)) / core.constants.tcp_prefix_bytes;

/// A TLS record's header: its content type, two octets of legacy version and two of length
/// (RFC 9846 §5.1), and where the length sits.
pub const tls_record_header_bytes: usize = 5;
pub const tls_record_length_at: usize = 3;

/// The longest record body a TLS 1.3 peer may send: 2^14 octets of plaintext, one of content type
/// and 255 of expansion (RFC 9846 §5.2).
pub const tls_record_body_bytes_max: usize = (1 << 14) + 256;

/// What a TLS connection keeps of the records it reads: one at its longest, header and all, and
/// one chunk. The chunk that ends a record can start the next one. The connection takes the whole
/// chunk before it hands the first record to the session (docs/design.md §21, TLS rule 7).
pub const tls_record_in_bytes: usize = tls_record_header_bytes + tls_record_body_bytes_max + tcp_chunk_bytes;

/// What sealing adds to a record: its header, the inner content type and the AEAD's 16-octet tag
/// (RFC 9846 §5.2).
pub const tls_record_overhead_bytes: usize = tls_record_header_bytes + 1 + 16;

/// The sealed records a TLS connection holds before they go: what the session stages at once, a
/// ClientHello at its longest among it, beside a query sealed at its longest. `io_chapulin.zig`
/// holds it to that sum at compile time. What is left, more than a thousand octets today, holds
/// the few of a KeyUpdate's answer and a `close_notify`. Past it the connection fails rather than
/// hold more (§21, TLS rule 3).
pub const tls_records_out_bytes: usize = 4096;

/// The entries of the session's own records one queue holds at once beside its queries: the one
/// in flight, and the one behind it, which every record made meanwhile joins (§21, TLS rule 2).
pub const tls_records_entries_max: usize = 2;

/// The most whole records a TLS connection's buffer holds at once, which bounds the loop over it.
/// Each record is at least its five-octet header (RFC 9846 §5.1). So the loop hands every whole
/// record to the session, and none waits for a chunk that may not come (TLS rule 7).
pub const tls_records_per_buffer_max: usize = tls_record_in_bytes / tls_record_header_bytes;

/// A client MUST NOT use a ticket more than seven days after it was issued (RFC 9846 §4.7.1).
pub const tls_ticket_age_ns_max: u64 = 7 * 24 * 60 * 60 * 1_000_000_000;

/// What one QUIC connection asks of the loop: its receive, and the send of its datagram
/// (docs/design.md §24, request rules 1 and 8).
pub const loop_operations_per_quic_connection: usize = 2;

/// A channel's operations in the loop at once: its QUIC link's receive and send, and its TCP link's
/// connect, receive and send (docs/design.md §24, rule 19).
pub const loop_operations_per_channel: usize = 5;

/// What one read of a channel takes at most beside an end for each request: its links' opens and
/// closes, its tickets and its close, which bounds the loop over it. What a flood leaves unread is
/// read at the next read. Chosen, not measured, as `quic_connection_events_max` is.
pub const channel_events_max: usize = 16;

/// Where a QUIC connection's incarnation sits in the `user_data` of its operations, above its
/// server's index, as a TCP connection's does above its slot. A server fits in the octet below.
pub const quic_incarnation_shift: u6 = 8;
pub const quic_server_mask: usize = (1 << quic_incarnation_shift) - 1;

/// How long a QUIC connection with no request on it is kept: TCP's ten seconds. RFC 9250 §5.5.2
/// names no value; this one is chosen, not measured (docs/design.md §24, request rule 9).
pub const quic_idle_ns_default = tcp_idle_ns_default;

/// How near the idle timeout it negotiated a connection with no request stops taking one, and
/// closes instead (RFC 9250 §4.4, request rule 9): a query and its answer take less than a
/// second. Chosen, not measured.
pub const quic_idle_margin_ns: u64 = 1_000_000_000;

/// The `next` calls one datagram or one expiry is read with, beside one answer or reset for each
/// lookup: the handshake's end, a close and tickets. Chosen, not measured. What a flood leaves
/// unread is read with the next datagram (docs/design.md §24, New limits).
pub const quic_connection_events_max: usize = 16;

/// The ALPN token of DoQ (RFC 9250 §4.1).
pub const quic_alpn_doq = "doq";

/// The port a DoH server's connection goes to when its template names none: "If the port
/// subcomponent is empty or not given, TCP port 443 ... is the default" (RFC 9110 §4.2.2), and
/// HTTP/3 goes to "the indicated port" over UDP (RFC 9114 §3.1).
pub const port_https_default: u16 = 443;

/// A second and a millisecond, in nanoseconds: chapulin's clock is Unix seconds, and a resumed
/// hello states a ticket's age in milliseconds (RFC 9846 §4.3.11.1).
pub const ns_per_second: u64 = 1_000_000_000;
pub const ns_per_millisecond: u64 = 1_000_000;

comptime {
    // The shifts are `u6`. Each check adds in `comptime_int` and subtracts nothing, so a wrong
    // shift reaches its message and does not overflow first.
    if (kind_shift < @as(comptime_int, receive_generation_shift) + 32) {
        @compileError("a receive's user_data has no room for a thirty-two-bit generation");
    }
    if (@as(comptime_int, quic_incarnation_shift) + 32 > kind_shift) {
        @compileError("a QUIC connection's user_data has no room for a thirty-two-bit incarnation");
    }
    if (buffer_bytes < core.constants.udp_payload_bytes_default + 192) {
        @compileError("a group buffer cannot hold the payload cocuyo advertises after rotor's prefix");
    }
    if (!@import("cocuyo").cache.slot_count_valid(cache_slots_default)) {
        @compileError("the cache size the README and the examples declare is one no cache takes");
    }
    // The chunk that ends one item can start the next, and the connection takes the whole chunk
    // first. So each buffer holds a chunk past its partial item (§19 step 13, the stream's rule
    // 11; §21, TLS rule 7).
    if (tls_record_in_bytes < tls_record_header_bytes + tls_record_body_bytes_max + tcp_chunk_bytes) {
        @compileError("a TLS connection's record buffer has no room for a chunk past a record");
    }
    if (tcp_frame_room_bytes < tcp_chunk_bytes or tls_frame_room_bytes < tls_record_body_bytes_max) {
        @compileError("a frame has no room for what one take adds past its partial message");
    }
}

// A constant with no type is a `comptime_int`, which takes the type of a narrow runtime value it
// meets in a sum. The lint rule reads the shape of each value, and this reads the type, so an
// alias or a call that gives a `comptime_int` is caught here (docs/design.md §16 decision 40).
test "each integer constant here has a type" {
    inline for (@typeInfo(@This()).@"struct".decls) |declaration| {
        const untyped = @TypeOf(@field(@This(), declaration.name)) == comptime_int;
        try std.testing.expectEqualStrings("", if (untyped) declaration.name else "");
    }
}
