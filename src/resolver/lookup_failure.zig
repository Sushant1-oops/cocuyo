//! How a lookup ends in failure: the `Failure` it reports, and the cause of the last server failure
//! that it keeps (docs/design.md §5, The cause of a failure; §16 decision 45). Split from
//! `lookup.zig` by the file-length rule.
const std = @import("std");
const assert = std.debug.assert;
const core = @import("core");
const wire = @import("wire");
const lookup_module = @import("lookup.zig");
const Lookup = lookup_module.Lookup;

pub const Failure = struct {
    err: core.Error,
    server_index: u8,
    /// The passes over the server list the lookup completed before it ended: `Config.attempts`
    /// when it ran out of them, as `Timeout` and `AllServersFailed` do, and zero when it ended in
    /// its first pass, as a name that does not exist usually does.
    attempts_made: u8,
    /// For `NameNotFound` and `NoData`, the TTL a cache may keep the negative answer for. Each
    /// negative response carries the SOA minimum it held (RFC 2308 §5), or zero when it held no
    /// SOA. A lookup that `Resolver.start` runs walks its search list itself, and reports the
    /// smallest of its candidates' negative TTLs, not the last one's alone: the end is kept under
    /// the name as asked, and it rests on every candidate's negative (docs/design.md §5).
    /// `AddressLookup` walks the search list with one absolute lookup per candidate, and its
    /// failure carries its last lookup's negative TTL alone, which the candidates before that one
    /// do not bound (docs/design.md §19 step 14). `NameLookup`'s failure carries its lookup's.
    /// Zero for every other failure, and zero is never cached (docs/design.md §18).
    negative_ttl_seconds: u32,
    /// The cause of the last server failure the lookup met, or null when no server failed it.
    /// `AllServersFailed` always has one, and `Timeout` never does. Any other error has the last
    /// one, or null: a `NameNotFound` can carry the SERVFAIL of a server before the one that
    /// answered NXDOMAIN. A negative that the memory of docs/design.md §20 recalls has none.
    /// `AddressLookup` and `NameLookup` hand on the cause of the lookup whose end they report
    /// (docs/design.md §5, The cause of a failure).
    cause: ?Cause,
};

/// What made a server fail a lookup. Each server failure replaces the cause the lookup holds,
/// and nothing clears it before the lookup ends (docs/design.md §5, The cause of a failure).
pub const Cause = union(enum) {
    /// The rcode of a response that failed the server, never NOERROR or NXDOMAIN. It is one of:
    ///
    /// - SERVFAIL, REFUSED, NOTIMP or BADVERS, while `Config.check_response` is on;
    /// - FORMERR to a query without EDNS0;
    /// - BADCOOKIE that advances the server: over a stream after its retry, or over DoH or DoQ.
    rcode: wire.Rcode,
    /// `on_tcp_failed` before `on_tcp_connected`: the connection did not come up. Its connect
    /// failed, or the caller had no socket, no free slot or no TCP at all to give. Over TLS a
    /// handshake that failed is `connect` too, since a lookup hears that a TLS connection is up
    /// only after the handshake (docs/design.md §21, TLS rule 1).
    connect,
    /// `on_tcp_failed` after `on_tcp_connected`: the connection failed before the answer came.
    /// The server closed or reset it, a send or a receive on it failed, or a TLS record did.
    stream,
    /// `on_request_failed`: a request over DoH or DoQ ended without an answer. An HTTP status that
    /// is not 2xx, a stream the server reset, or a connection or a handshake that failed under
    /// the request (docs/design.md §22, §23).
    request,
};

/// The cause `on_tcp_failed` keeps in `state`: the connect's while the lookup waits for its
/// connection, and the stream's once it was told the connection is up. Over TLS the lookup is
/// told so only after the handshake, so a handshake that fails is the connect's
/// (docs/design.md §5, The cause of a failure; §21, TLS rule 1).
pub fn stream_cause(state: lookup_module.State) Cause {
    assert(state == .connecting_tcp or state == .tcp_ready or state == .awaiting_tcp);
    const cause: Cause = if (state == .connecting_tcp) .connect else .stream;
    assert(cause != .rcode);
    return cause;
}

/// `Lookup.failure_of`: what `.failed` carries.
pub fn failure_of(self: *const Lookup) Failure {
    assert(self.state == .failed);
    // `AllServersFailed` rests on a server that failed the lookup, and `Timeout` on none.
    assert(self.failure != core.Error.AllServersFailed or self.cause != null);
    assert(self.failure != core.Error.Timeout or self.cause == null);
    const negative = self.failure == core.Error.NameNotFound or self.failure == core.Error.NoData;
    return .{
        .err = self.failure,
        // A lookup with no server to have been on reports the first.
        .server_index = if (self.config.server_count() == 0) 0 else self.server_slot(),
        .attempts_made = self.round,
        .negative_ttl_seconds = if (negative) self.negative_ttl_seconds else 0,
        .cause = self.cause,
    };
}

// Tests. The fake server of fixtures.zig answers whatever the lookup asked (docs/design.md §5,
// The cause of a failure).

const testing = std.testing;
const Config = core.Config;
const Verdict = lookup_module.Verdict;
const Action = lookup_module.Action;
const fixtures = @import("fixtures.zig");
const recall = @import("lookup_recall.zig");
const Harness = fixtures.Harness;

const seed = fixtures.seed;
/// One server and one pass: each server failure ends the lookup.
const one_try: Config = .{ .servers = &fixtures.servers_one, .attempts = 1 };

/// Polls the lookup, which must have failed with `err`, and requires `cause` of its failure.
fn expect_failure(harness: *Harness, err: core.Error, cause: ?Cause) !void {
    const failure = harness.poll().failed;
    try testing.expectEqual(err, failure.err);
    try testing.expectEqual(cause, failure.cause);
}

/// Lets the wait of the try in flight run out, and returns what the poll at its deadline asks.
fn run_out(harness: *Harness) Action {
    harness.now_ns = harness.lookup.deadline_ns - 1;
    return harness.poll();
}

/// Sends the query over UDP and hands the current server's `reply` to the lookup.
fn ask(harness: *Harness, reply: fixtures.Reply) !void {
    _ = harness.send();
    try testing.expectEqual(Verdict.accepted, harness.respond(reply, harness.lookup.server()));
}

test "each rcode that fails a server is the cause that AllServersFailed carries" {
    const rcodes = [_]wire.Rcode{ .server_failure, .refused, .not_implemented, .bad_vers };
    for (rcodes) |rcode| {
        var harness: Harness = .{ .config = one_try };
        try harness.start("example.com.", .a, seed);
        try ask(&harness, .{ .rcode = rcode });
        try expect_failure(&harness, core.Error.AllServersFailed, .{ .rcode = rcode });
    }
}

test "FORMERR to a query without EDNS0 is the cause, and FORMERR to one with it is none" {
    var harness: Harness = .{ .config = one_try };
    try harness.start("example.com.", .a, seed);
    try ask(&harness, fixtures.format_error);
    // The same server, asked again without the OPT record: a retry, and no failure (RFC 6891
    // §6.2.2).
    try testing.expectEqual(@as(?Cause, null), harness.lookup.cause);
    try ask(&harness, fixtures.format_error);
    try expect_failure(&harness, core.Error.AllServersFailed, .{ .rcode = .format_error });
}

test "a connection that fails before it is up is connect, and one that fails after is stream" {
    const config: Config = .{ .servers = &fixtures.servers_one, .use_tcp = true, .attempts = 1 };
    // The connect, or over TLS the handshake, since the lookup hears that a TLS connection is up
    // only at the handshake's end (docs/design.md §21, TLS rule 1).
    var connecting: Harness = .{ .config = config };
    try connecting.start("example.com.", .a, seed);
    try testing.expect(connecting.poll() == .connect_tcp);
    connecting.lookup.on_tcp_failed(connecting.now_ns);
    try expect_failure(&connecting, core.Error.AllServersFailed, .connect);
    // Up, before the query went and after it.
    for ([_]bool{ false, true }) |sent| {
        var up: Harness = .{ .config = config };
        try up.start("example.com.", .a, seed);
        try testing.expect(up.poll() == .connect_tcp);
        up.lookup.on_tcp_connected(up.now_ns);
        if (sent) _ = up.send_over_tcp();
        up.lookup.on_tcp_failed(up.now_ns);
        try expect_failure(&up, core.Error.AllServersFailed, .stream);
    }
}

test "the last server failure is the cause, and a silent server after it leaves it standing" {
    var harness: Harness = .{ .config = .{ .servers = &fixtures.servers_three, .attempts = 1, .failover_retry_chance = 0 } };
    try harness.start("example.com.", .a, seed);
    try ask(&harness, fixtures.server_failure);
    try ask(&harness, .{ .rcode = .refused });
    // The third server says nothing. Silence is no cause, and it clears none (§16 decision 25).
    _ = harness.send();
    const last = run_out(&harness).failed;
    try testing.expectEqual(core.Error.AllServersFailed, last.err);
    try testing.expectEqual(@as(?Cause, .{ .rcode = .refused }), last.cause);
}

test "a stream that fails after an rcode replaces it, and an rcode after a stream replaces that" {
    const config: Config = .{ .servers = &fixtures.servers_two, .attempts = 1, .failover_retry_chance = 0 };
    var rcode_first: Harness = .{ .config = config };
    try rcode_first.start("example.com.", .a, seed);
    try ask(&rcode_first, fixtures.server_failure);
    // The second server's answer is truncated, and its connection fails.
    try ask(&rcode_first, fixtures.truncated);
    try testing.expect(rcode_first.poll() == .connect_tcp);
    rcode_first.lookup.on_tcp_failed(rcode_first.now_ns);
    try expect_failure(&rcode_first, core.Error.AllServersFailed, .connect);

    var stream_first: Harness = .{ .config = config };
    try stream_first.start("example.com.", .a, seed);
    try ask(&stream_first, fixtures.truncated);
    try testing.expect(stream_first.poll() == .connect_tcp);
    stream_first.lookup.on_tcp_connected(stream_first.now_ns);
    _ = stream_first.send_over_tcp();
    stream_first.lookup.on_tcp_failed(stream_first.now_ns);
    try ask(&stream_first, fixtures.server_failure);
    try expect_failure(&stream_first, core.Error.AllServersFailed, .{ .rcode = .server_failure });
}

test "a lookup that no server failed carries no cause" {
    const config: Config = .{ .servers = &fixtures.servers_two, .attempts = 1, .failover_retry_chance = 0 };
    // Every try ran out: Timeout.
    var silent: Harness = .{ .config = config };
    try silent.start("example.com.", .a, seed);
    _ = silent.send();
    try testing.expect(run_out(&silent) == .send_udp);
    silent.lookup.on_sent(silent.now_ns);
    try testing.expectEqual(@as(?Cause, null), run_out(&silent).failed.cause);
    // Every send failed: the loop or the local stack refused it, and no server said a word.
    var unsent: Harness = .{ .config = config };
    try unsent.start("example.com.", .a, seed);
    for (0..config.servers.len) |_| {
        try testing.expect(unsent.poll() == .send_udp);
        unsent.lookup.on_send_failed(unsent.now_ns);
    }
    try expect_failure(&unsent, core.Error.Timeout, null);
    // A name that does not exist, a cancel, and no server at all.
    var missing: Harness = .{ .config = config };
    try missing.start("example.com.", .a, seed);
    try ask(&missing, fixtures.name_error);
    try expect_failure(&missing, core.Error.NameNotFound, null);
    var cancelled: Harness = .{ .config = config };
    try cancelled.start("example.com.", .a, seed);
    _ = cancelled.send();
    cancelled.lookup.cancel();
    try expect_failure(&cancelled, core.Error.Canceled, null);
    var serverless: Harness = .{ .config = .{ .servers = &.{} } };
    try serverless.start("example.com.", .a, seed);
    try expect_failure(&serverless, core.Error.NoServers, null);
}

test "a retry is no cause: FORMERR with EDNS0, a first BADCOOKIE and TC=1, then silence, is Timeout" {
    const retries = [_]fixtures.Reply{ fixtures.format_error, fixtures.bad_cookie_fresh, fixtures.truncated };
    for (retries) |reply| {
        var harness: Harness = .{ .config = one_try };
        try harness.start("example.com.", .a, seed);
        try ask(&harness, reply);
        try testing.expectEqual(@as(?Cause, null), harness.lookup.cause);
        // Asked again, over UDP or over the stream, and the server says nothing.
        if (harness.poll() == .connect_tcp) harness.lookup.on_tcp_connected(harness.now_ns) else harness.lookup.on_sent(harness.now_ns);
        const last = run_out(&harness);
        if (last == .failed) {
            try testing.expectEqual(core.Error.Timeout, last.failed.err);
            try testing.expectEqual(@as(?Cause, null), last.failed.cause);
        } else {
            try testing.expect(last == .send_tcp);
            harness.lookup.on_sent(harness.now_ns);
            try testing.expectEqual(@as(?Cause, null), run_out(&harness).failed.cause);
        }
    }
}

test "an error but AllServersFailed carries the last server failure too" {
    // The first server fails, and the second says the name does not exist (RFC 1035 §4.1.1).
    const config: Config = .{ .servers = &fixtures.servers_two, .failover_retry_chance = 0 };
    var missing: Harness = .{ .config = config };
    try missing.start("example.com.", .a, seed);
    try ask(&missing, fixtures.server_failure);
    try ask(&missing, fixtures.name_error);
    try expect_failure(&missing, core.Error.NameNotFound, .{ .rcode = .server_failure });
    // The first server's connection fails, and the caller gives up.
    var cancelled: Harness = .{ .config = .{ .servers = &fixtures.servers_two, .use_tcp = true, .failover_retry_chance = 0 } };
    try cancelled.start("example.com.", .a, seed);
    try testing.expect(cancelled.poll() == .connect_tcp);
    cancelled.lookup.on_tcp_failed(cancelled.now_ns);
    cancelled.lookup.cancel();
    try expect_failure(&cancelled, core.Error.Canceled, .connect);
}

test "a server error taken as the answer under check_response off is the error, and no cause" {
    var harness: Harness = .{ .config = .{ .servers = &fixtures.servers_one, .check_response = false } };
    try harness.start("example.com.", .a, seed);
    try ask(&harness, fixtures.server_failure);
    try expect_failure(&harness, core.Error.ServerFailure, null);
}

test "a negative that the memory recalls has no cause" {
    // The memory keeps the negative and its TTL alone, and no server was asked (docs/design.md
    // §20).
    var harness: Harness = .{ .config = one_try };
    try harness.start("example.com.", .a, seed);
    recall.failure(&harness.lookup, core.Error.NameNotFound, fixtures.cached_ttl_seconds);
    try expect_failure(&harness, core.Error.NameNotFound, null);
}

test "the size of a failure is pinned, and an answer outweighs it" {
    // 8 octets until the cause came on 2026-10-17. An `Action` holds the larger `Answer`, so it
    // kept its size (docs/design.md §16 decision 45).
    try testing.expectEqual(@as(usize, 12), @sizeOf(Failure));
    try testing.expect(@sizeOf(Failure) < @sizeOf(lookup_module.Answer));
}
