//! The stream octets that `cocuyo_doh` keeps until colibri takes them (`io_doh_channel_read.zig`;
//! docs/design.md §16 decision 41, §24 the interface; c4milo/cocuyo#44). colibri's server writes
//! whole records back to back. Some lengths put many whole records in one chunk. Others leave a
//! long partial record before a chunk, or put a short record after two full ones. The test plays
//! the engine, as `io_doh_channel_test.zig` does. Each chunk goes to the type, then the type is
//! read as the engine's `hear` reads it. After each read no whole record stays in the buffer. So
//! the next chunk finds a partial record at most, and fits beside it.
const std = @import("std");
const testing = std.testing;
const cocuyo = @import("cocuyo");
const io = @import("io");
const rig = @import("io_doh_channel_test.zig");
const constants = rig.constants;

/// The requests a test has in flight: one for each of the pair's answer buffers.
const requests = 2;
/// The most that one read takes, as the engine's `hear` takes it. That is an end for each request,
/// and `channel_events_max` of the channel's own (`io/constants.zig`).
const events_per_read_max = requests + io.constants.channel_events_max;

/// The room for a record of 2^14 octets of plaintext and nothing after it (RFC 9846 §5.2).
const full_record_bytes = constants.record_plaintext_bytes_max + io.constants.tls_record_overhead_bytes;
/// The plaintext of a short record after two full ones, in each of two lists, and the room for it.
const short_plaintext_bytes = 1_000;
const longer_short_plaintext_bytes = 1_500;
const short_after_full_bytes = [_]usize{
    short_plaintext_bytes + io.constants.tls_record_overhead_bytes,
    longer_short_plaintext_bytes + io.constants.tls_record_overhead_bytes,
};
/// The room for a record of 78 octets of plaintext. About twenty such records fill one chunk.
const short_record_bytes = 100;

/// The room that the server writes into, call after call, in each run. Each record is at most as
/// long as its room. A run takes one list, and starts it again at its end:
///
/// - One room alone: a record at its longest, one past the engine's chunk, one short of it, or
///   one of 100 octets.
/// - Two full records, then a short one. Over HTTP/2, the first full record holds the HEADERS
///   frame of the first answer, and most of its first DATA frame. The second full record ends
///   that frame and holds most of the next. The short record comes whole in the chunk that ends
///   the second. It does not fit beside the second in colibri's room, so it opens in a second
///   pass of the read.
const patterns = [_][]const usize{
    &.{constants.output_bytes_max},
    &.{constants.engine_chunk_bytes + 1},
    &.{constants.engine_chunk_bytes - 1},
    &.{short_record_bytes},
    &.{ full_record_bytes, full_record_bytes, short_after_full_bytes[0] },
    &.{ full_record_bytes, full_record_bytes, short_after_full_bytes[1] },
};

/// Each answer's length: one that one record holds, one that crosses records, and one past two
/// DATA frames at their longest (RFC 9113 §4.2). In the last, a frame with no END_STREAM can end
/// in a full record, and the next frame cannot end there (RFC 9113 §6.1).
const short_answer_bytes = 2_000;
const long_answer_bytes = 20_000;
const longest_answer_bytes = 40_000;
const answer_lengths = [_]usize{ short_answer_bytes, long_answer_bytes, longest_answer_bytes };
/// What the server selects: HTTP/2, then HTTP/1.1 (RFC 7301 §3.2).
const protocols = [_][]const []const u8{ &.{"h2"}, &.{"http/1.1"} };
/// The octet the answer is filled with after the query. Test-only.
const filler = 0x41;

/// The most that the server writes in one round: a DNS message at its longest for each request.
/// That is more than the answers and their heads.
const burst_bytes = requests * cocuyo.constants.message_bytes_max;

/// What the test saw over its runs:
///
/// - the chunks that came;
/// - the chunks that put two whole records or more in the buffer before the read;
/// - the most that the buffer held with a chunk.
const Tally = struct {
    chunks: usize = 0,
    back_to_back: usize = 0,
    most: usize = 0,
};

/// Answers a query with the query, the QR bit set, and filler to the length `context` names.
fn long_answer(context: *anyopaque, asked: []const u8, out: []u8) ?usize {
    const length: *const usize = @ptrCast(@alignCast(context));
    @memcpy(out[0..asked.len], asked);
    out[rig.flags_at] |= rig.qr_bit;
    @memset(out[asked.len..length.*], filler);
    return length.*;
}

/// The whole records at the start of `octets`. Each is its header, then the octets that the
/// header's length gives (RFC 9846 §5.1).
fn whole_records(octets: []const u8) usize {
    const header = io.constants.tls_record_header_bytes;
    var at: usize = 0;
    var count: usize = 0;
    // Bounded: each pass passes a header at least, or stops.
    for (0..octets.len / header + 1) |_| {
        if (octets.len - at < header) break;
        const length = std.mem.readInt(u16, octets[at + io.constants.tls_record_length_at ..][0..@sizeOf(u16)], .big);
        if (octets.len - at - header < length) break;
        at += header + length;
        count += 1;
    }
    return count;
}

/// Reads the type as the engine's `hear` reads it. A sound stream says less than the bound, so the
/// read ends with nothing more to say and leaves nothing for the next read.
fn read(pair: *rig.Pair) !void {
    for (0..events_per_read_max) |_| {
        const event = pair.doh.next(pair.now_ns) orelse return;
        try pair.note(event);
    }
    return error.ReadBoundReached;
}

/// One chunk to the type, then a read. Every whole record leaves with that read.
fn deliver(pair: *rig.Pair, chunk: []const u8, tally: *Tally) !void {
    tally.most = @max(tally.most, pair.doh.stream_len + chunk.len);
    pair.doh.receive(.{ .stream = chunk }, pair.now_ns);
    try testing.expect(!pair.doh.stream_overrun);
    tally.chunks += 1;
    if (whole_records(pair.doh.stream[0..pair.doh.stream_len]) > 1) tally.back_to_back += 1;
    try read(pair);
    try testing.expectEqual(@as(usize, 0), whole_records(pair.doh.stream[0..pair.doh.stream_len]));
}

/// What the TCP link owes goes to the server. What the server owes comes back in records whose
/// rooms follow `pattern`, in the engine's chunks, with a read after each.
fn carry(pair: *rig.Pair, answer_length: *usize, pattern: []const usize, burst: []u8, tally: *Tally) !void {
    _ = pair.doh.datagram(&pair.wire, pair.now_ns);
    const up = pair.doh.output(&pair.wire, pair.now_ns);
    if (up > 0) pair.server.receive(pair.wire[0..up], .{ .context = answer_length, .answer = long_answer }, pair.now_ns);
    var down: usize = 0;
    // Bounded: each pass writes an octet at least, or stops.
    for (0..burst.len) |call| {
        const room = @min(pattern[call % pattern.len], burst.len - down);
        const sent = if (room == 0) 0 else pair.server.send(burst[down..][0..room], pair.now_ns);
        if (sent == 0) break;
        down += sent;
    }
    pair.carried = pair.carried or up > 0 or down > 0;
    var at: usize = 0;
    while (at < down) : (at += constants.engine_chunk_bytes) {
        try deliver(pair, burst[at..@min(down, at + constants.engine_chunk_bytes)], tally);
    }
}

/// Rounds until both requests have ended, as `Pair.run` moves the clock.
fn exchange(pair: *rig.Pair, answer_length: *usize, pattern: []const usize, burst: []u8, tally: *Tally) !void {
    for (0..rig.rounds_max) |_| {
        try read(pair);
        if (pair.count(.finished) == requests) return;
        const moved = pair.carried;
        pair.carried = false;
        try carry(pair, answer_length, pattern, burst, tally);
        pair.now_ns += rig.round_ns;
        const due = pair.doh.deadline() orelse continue;
        if (!moved and !pair.carried) pair.now_ns = @max(pair.now_ns, due);
        if (due <= pair.now_ns) pair.doh.expire(pair.now_ns);
    }
    return error.NotFinished;
}

/// Each request ended with its answer whole: the query, the QR bit set, then the filler.
fn expect_answers(pair: *const rig.Pair, answer_length: usize) !void {
    var expected: [rig.query.len]u8 = rig.query;
    expected[rig.flags_at] |= rig.qr_bit;
    for (pair.said[0..pair.said_len]) |event| {
        if (event != .finished) continue;
        const message = (event.finished.answer orelse return error.NoAnswer).message;
        try testing.expectEqual(answer_length, message.len);
        try testing.expectEqualSlices(u8, &expected, message[0..expected.len]);
        try testing.expect(std.mem.allEqual(u8, message[expected.len..], filler));
    }
}

/// One run: two requests, both answered in records whose rooms follow `pattern`.
fn run(alpn: []const []const u8, pattern: []const usize, answer_length: usize, burst: []u8, tally: *Tally) !void {
    const pair = try rig.Pair.create(.{ .alpn = alpn });
    defer pair.free();
    var length = answer_length;
    for (0..requests) |index| try testing.expect(pair.doh.request(@intCast(index), &rig.query, pair.now_ns));
    try exchange(pair, &length, pattern, burst, tally);
    try expect_answers(pair, answer_length);
}

test "whole records back to back leave the buffer with the read after each chunk, so the next chunk fits beside a partial record" {
    // Decision 41's rule at the DoH channel (c4milo/cocuyo#44). Over HTTP/2 colibri holds a
    // partial frame and room for a record. Over HTTP/1.1 it holds a partial head of a usual length
    // and room for a record. A read goes on until the channel says nothing more. So no whole record
    // waits for the next chunk.
    const burst = try testing.allocator.alloc(u8, burst_bytes);
    defer testing.allocator.free(burst);
    var tally: Tally = .{};
    for (protocols) |alpn| {
        for (patterns) |pattern| {
            for (answer_lengths) |answer_length| try run(alpn, pattern, answer_length, burst, &tally);
        }
    }
    // The runs put whole records back to back in a chunk, and a long partial record before a chunk.
    // With the chunk, that partial record passed a record at its longest. So the chunk used the
    // room that decision 41 gives it.
    try testing.expect(tally.back_to_back > 0);
    try testing.expect(tally.most > constants.record_bytes_max);
    try testing.expect(tally.most <= constants.stream_bytes);
}
