//! The engine over TLS on the twin, with a session that fails where a test says, or that asks for
//! more room than the twin's: a session that cannot start, seal or open, or whose peer closes,
//! fails over to the next server; the records buffer holds a session that asks for all of it, and
//! refuses one that asks for more (docs/design.md §21, TLS rule 3); a queue holds two entries of
//! the records a session makes of its own accord beside each lookup's query (TLS rule 2); a reset
//! empties the state.
//! Split from `io_tls_test.zig` by the file-length rule.
const std = @import("std");
const testing = std.testing;
const cocuyo = @import("cocuyo");
const rotor = @import("rotor");
const io = @import("io.zig");

const fixtures = @import("fixtures.zig");
const sim_test = @import("io_sim_test.zig");
const tls_test = @import("io_tls_test.zig");
const question = sim_test.question;

/// Where the failing session fails. A TLS stack can fail to start or to seal, refuse a record, as
/// it refuses a forged one, or hear its peer close; the twin's session does none of these.
const Failure = enum { start, seal, open, closed };
const Plan = struct { at: Failure = .start, left: u8 = 0 };
threadlocal var failing: Plan = .{};
/// How many empty records the failing session makes of its own accord, one at each collection,
/// as a session that answers a KeyUpdate makes records the engine did not ask for.
threadlocal var unasked: usize = 0;

fn fails_now(at: Failure) bool {
    if (failing.at != at or failing.left == 0) return false;
    failing.left -= 1;
    return true;
}

/// The twin's session, failing where `failing` says and as often, which asks for `room` octets
/// of the records buffer before it stages anything.
fn FailingOf(comptime room: usize) type {
    return struct {
        const Self = @This();
        const Twin = rotor.tls.Session;
        pub const enabled = true;
        pub const out_bytes_max = room;
        pub const Error = Twin.Error;
        pub const Context = Twin.Context;
        pub const Ticket = Twin.Ticket;
        pub const Handshake = Twin.Handshake;
        pub const Opened = Twin.Opened;

        twin: Twin = .{},

        pub fn start(self: *Self, context: anytype) Error!void {
            if (fails_now(.start)) return error.Failed;
            return self.twin.start(context);
        }
        pub fn lifetime_ns(ticket: *const Ticket) u64 {
            return Twin.lifetime_ns(ticket);
        }
        pub fn take_out(self: *Self, out: []u8) usize {
            const made = self.twin.take_out(out);
            if (unasked == 0) return made;
            unasked -= 1;
            return made + rotor.tls.write_record(rotor.constants.tls_content_application, &.{}, out[made..]);
        }
        pub fn handshake(self: *Self, record: []const u8) Error!Handshake {
            return self.twin.handshake(record);
        }
        pub fn seal(self: *Self, plaintext: []const u8) Error!void {
            if (fails_now(.seal)) return error.Failed;
            return self.twin.seal(plaintext);
        }
        pub fn open(self: *Self, record: []const u8, plaintext: []u8) Error!Opened {
            if (fails_now(.open)) return error.Failed;
            if (fails_now(.closed)) return .closed;
            return self.twin.open(record, plaintext);
        }
        pub fn take_ticket(self: *Self) ?Ticket {
            return self.twin.take_ticket();
        }
        pub fn close(self: *Self) void {
            self.twin.close();
        }
        pub fn wipe(self: *Self) void {
            self.twin.wipe();
        }
    };
}

/// The failing session with the twin's own room.
const Failing = FailingOf(rotor.tls.Session.out_bytes_max);

/// An engine over a session of type `Session`.
fn RigOver(comptime Session: type) type {
    return sim_test.RigOf(io.Resolver(.{
        .lookups = fixtures.small_lookups,
        .group_buffers = fixtures.group_buffers,
        .tcp_connections = fixtures.servers,
        .tls = Session,
    }));
}

const FailingRig = RigOver(Failing);

/// The first server's session fails once, at `at`: its connection fails, the server is charged
/// with it, and the next server answers over TLS.
fn expect_fails_over(seed: u64, at: Failure) !void {
    failing = .{ .at = at, .left = 1 };
    defer failing = .{};
    var rig: FailingRig = .{};
    try tls_test.encrypt(&rig);
    try rig.init(seed, .{ .{}, .{} }, .{ .servers = &.{}, .timeout_ns = fixtures.stream_timeout_ns, .timeout_ns_max = fixtures.stream_timeout_ns, .failover_retry_chance = 0 });
    rig.use_test_contexts();
    _ = try rig.engine.start(question("example.com."), rig.loop.now());
    const result = try rig.until_result();
    try testing.expectEqual(@as(usize, 1), result.outcome.answer.addresses.len);
    try testing.expectEqual(@as(u8, 0), failing.left);
    try testing.expectEqual(@as(u8, 1), rig.engine.resolver.servers.failures(0));
    // At once, and not once the first server's wait ran out.
    try testing.expect(rig.loop.now() < rig.config.timeout_ns);
    _ = rig.engine.take(rig.loop.now());
    try rig.deinit();
}

test "a session that cannot start, seal or open, or whose peer closes, fails over to the next server" {
    try expect_fails_over(48, .start);
    try expect_fails_over(49, .seal);
    try expect_fails_over(50, .open);
    try expect_fails_over(51, .closed);
}

test "a session that fails at each server ends in AllServersFailed, its cause where it failed" {
    // A session that cannot start fails its connection before the lookup hears that it is up, so
    // the cause is the connect's. One that cannot seal, or opens a record it refuses or a
    // `close_notify`, fails it once up, and the cause is the stream's (docs/design.md §5, The
    // cause of a failure).
    const cases = [_]struct { at: Failure, cause: cocuyo.Cause }{
        .{ .at = .start, .cause = .connect },
        .{ .at = .seal, .cause = .stream },
        .{ .at = .open, .cause = .stream },
        .{ .at = .closed, .cause = .stream },
    };
    for (cases) |case| {
        failing = .{ .at = case.at, .left = std.math.maxInt(u8) };
        defer failing = .{};
        var rig: FailingRig = .{};
        try tls_test.encrypt(&rig);
        try rig.init(117, .{ .{}, .{} }, .{ .servers = &.{}, .timeout_ns = fixtures.stream_timeout_ns, .timeout_ns_max = fixtures.stream_timeout_ns, .failover_retry_chance = 0 });
        rig.use_test_contexts();
        _ = try rig.engine.start(question("example.com."), rig.loop.now());
        const result = try rig.until_result();
        try testing.expectEqual(cocuyo.Error.AllServersFailed, result.outcome.failure.err);
        try testing.expectEqual(@as(?cocuyo.Cause, case.cause), result.outcome.failure.cause);
        _ = rig.engine.take(rig.loop.now());
        try rig.deinit();
    }
}

/// What one lookup came to: its error, null for an answer, the first server's failures, and
/// whether it ended before its wait ran out.
const Seen = struct { failure: ?cocuyo.Error, failures: u8, at_once: bool };

/// One lookup on an engine over a session that asks for `room` octets of the records buffer.
/// Both servers answer.
fn lookup_with_room(comptime room: usize, seed: u64) !Seen {
    var rig: RigOver(FailingOf(room)) = .{};
    try tls_test.start(&rig, seed, .{ .{}, .{} });
    _ = try rig.engine.start(question("example.com."), rig.loop.now());
    const result = try rig.until_result();
    const failure: ?cocuyo.Error = if (result.outcome == .failure) result.outcome.failure.err else null;
    const seen: Seen = .{ .failure = failure, .failures = rig.engine.resolver.servers.failures(0), .at_once = rig.loop.now() < rig.config.timeout_ns };
    _ = rig.engine.take(rig.loop.now());
    try rig.deinit();
    return seen;
}

test "the records buffer takes a session that asks for all of it, and a session that asks for more fails" {
    // A session stages its records in the room after the sealed records. The engine gives it that
    // room only when the room holds the most the session asks for (§21, TLS rule 3). Each opening
    // asks for room for its hello first. So a session that asks for more than the buffer fails
    // each connection before it sends an octet.
    const whole = try lookup_with_room(io.constants.tls_records_out_bytes, 59);
    try testing.expectEqual(@as(?cocuyo.Error, null), whole.failure);
    try testing.expectEqual(@as(u8, 0), whole.failures);
    const over = try lookup_with_room(io.constants.tls_records_out_bytes + 1, 60);
    // Each pass over the servers fails both at once, and the first server is charged each time.
    try testing.expectEqual(@as(?cocuyo.Error, cocuyo.Error.AllServersFailed), over.failure);
    try testing.expectEqual(@as(u8, cocuyo.constants.attempts_default), over.failures);
    try testing.expect(over.at_once);
}

/// Names a lookup each, none of which the cache holds.
const queued_names = [_][]const u8{ "a.example.", "b.example.", "c.example.", "d.example.", "e.example.", "f.example." };

test "a queue holds a query for each lookup and two entries of the records the session made itself" {
    // Records the session makes go after what is sealed, and records made behind an entry that has
    // not started join it (TLS rule 2). So beside one entry in flight there is one more at most.
    // Here every lookup's query waits behind the entry in flight, and the session makes records
    // twice more.
    var rig: FailingRig = .{};
    try tls_test.start(&rig, 61, .{ .{}, .{} });
    _ = try rig.engine.start(question("example.com."), rig.loop.now());
    _ = try rig.until_result();
    _ = rig.engine.take(rig.loop.now());
    _ = rig.engine.take(rig.loop.now());
    const connection = &rig.engine.connections[0];
    defer unasked = 0;
    unasked = 1;
    try testing.expect(io.tls.make_records(&rig.engine, 0, rig.loop.now()));
    try testing.expect(connection.sending);
    comptime std.debug.assert(queued_names.len == fixtures.small_lookups);
    for (queued_names) |name| _ = try rig.engine.start(question(name), rig.loop.now());
    for (0..io.constants.tls_records_entries_max) |_| {
        unasked = 1;
        try testing.expect(io.tls.make_records(&rig.engine, 0, rig.loop.now()));
    }
    try testing.expectEqual(fixtures.small_lookups + io.constants.tls_records_entries_max, connection.queue.count);
    for (queued_names) |_| try testing.expect((try rig.until_result()).outcome == .answer);
    _ = rig.engine.take(rig.loop.now());
    try rig.deinit();
}

/// The octet a test's buffer holds before a reset, which no reset writes.
const untouched: u8 = 0x5a;

test "a TLS reset empties the state and leaves the records' bytes, which the loop may hold" {
    var holder: struct { tls: io.tls.State(Failing) = .{} } = .{};
    holder.tls.ticket_since_ns = 9;
    holder.tls.record_in_used = 3;
    holder.tls.out_head = 1;
    holder.tls.out_tail = 2;
    @memset(&holder.tls.record_in, untouched);
    @memset(&holder.tls.out, untouched);
    io.tls.reset(&holder);
    try testing.expectEqual(@as(u64, 0), holder.tls.ticket_since_ns);
    try testing.expectEqual(@as(usize, 0), holder.tls.record_in_used);
    try testing.expectEqual(@as(u16, 0), holder.tls.out_head);
    try testing.expectEqual(@as(u16, 0), holder.tls.out_tail);
    for (holder.tls.record_in) |octet| try testing.expectEqual(untouched, octet);
    for (holder.tls.out) |octet| try testing.expectEqual(untouched, octet);
}
