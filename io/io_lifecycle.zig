//! What a consumer does to a whole engine (docs/design.md §19 step 13): ending every lookup at
//! once, which is `ares_cancel`, and taking a new configuration, which is `ares_reinit`. Free
//! functions over the engine, split out of `io.zig` so each is scored on its own.
const std = @import("std");
const assert = std.debug.assert;
const cocuyo = @import("cocuyo");
const drive_module = @import("io_drive.zig");
const tcp = @import("io_tcp.zig");
const send_module = @import("io_send.zig");
const request_module = @import("io_request.zig");
const request_tend = @import("io_request_connection_tend.zig");
const channel_module = @import("io_channel.zig");
const channel_link = @import("io_channel_link.zig");

/// Settles every lookup as cancelled, which is `ares_cancel`. Each failure comes through
/// `take` like any other, so the caller learns of all of them.
pub fn cancel_all(self: anytype, now_ns: u64) void {
    cancel_every(self);
    drive_module.drive(self, now_ns);
}

/// Cancels every lookup in the table. One that has ended keeps its end (`Resolver.cancel`).
pub fn cancel_every(self: anytype) void {
    for (self.slots[0..], 0..) |*slot, index| {
        if (slot.occupied) self.resolver.cancel(self.handles[index]);
    }
}

/// What `init` and `reinit` require of the cache memory they are handed: none, or slices
/// `Cache.init` takes. A caller that reads a slot count at run time refuses a bad one itself,
/// with `cocuyo.cache.slot_count_valid`, so slices of another shape are a programmer error
/// (docs/design.md §18, Sizing the memory).
pub fn assert_cache_memory(cache_memory: ?cocuyo.cache.Slices) void {
    const memory = cache_memory orelse return;
    assert(memory.valid());
}

/// A new table over the engine's slots, and under it a new cache over `cache_memory`, which is
/// what `init` starts with and what `reinit` starts again with. The cache is keyed by `seed`
/// and capped at the configuration's `cache_ttl_seconds_max`, and it starts empty, since
/// `Cache.init` writes every slot and key. Handed no memory, the table gets no `Memory`: the
/// engine has no cache, and every lookup goes to its servers (docs/design.md §19 step 13, the
/// cache's memory; §20). A send the old table made keeps its buffer until its final event, which
/// then speaks for nobody (the stream's rules 6 and 7).
pub fn reset_tables(self: anytype, config: *const cocuyo.Config, cache_memory: ?cocuyo.cache.Slices, seed: u64) void {
    self.resolver = cocuyo.Resolver.init(&self.slots, &self.keys, config, seed);
    self.cache = null;
    if (cache_memory) |memory| {
        self.cache = cocuyo.Cache.init(memory.slots, memory.keys, seed, config.cache_ttl_seconds_max);
        self.resolver.remember_with(cocuyo.remembered_by(&self.cache.?));
    }
    send_module.forget_all(self);
    self.reported = @splat(false);
    self.results = .{};
    self.last_taken = null;
}

/// A new configuration, which is `ares_reinit`: the cache is emptied because its answers
/// came from servers that may be gone, the streams are closed, and the sockets are opened
/// again on the new servers. The table is built again, so every server's latency samples
/// start over, and each waits `Config.timeout_ns` until it has 3 (docs/design.md §5), and a
/// server marked as one that lowercases the name is asked with DNS-0x20 again (§7).
///
/// The cache is built again over `cache_memory`, with the new seed and the new configuration's
/// cap: the memory the engine holds, which comes back empty; other memory, of another size if
/// the caller likes, after which the engine never touches the old; or none, which turns the
/// cache off until a later `reinit` hands some over (§19 step 13, the cache's memory).
///
/// A `reinit` that fails has done all of that but open its sockets. The engine holds the new
/// configuration and a cache over the memory this call handed it, which stays the engine's
/// until a later `reinit` or `close` returns: a caller that got memory for this call must not
/// free it on the error. The memory the engine held before is the caller's either way (rule 5).
///
/// The engine must be idle: a lookup in flight was started against servers that are
/// going away, and its handle would name a slot the new table has never heard of. A
/// caller with lookups in flight calls `cancel_all` and takes their failures first, which
/// is what tells it what it lost.
///
/// `seed` must be a new draw from a CSPRNG, never the seed of `init` or of an earlier
/// `reinit`. The table and its client cookies are drawn from it again, so the same seed
/// sends the same fresh client cookies again, which RFC 9018 §3 and §8.1 forbid; a caller
/// whose address changed calls `reinit` for exactly that (docs/design.md §19 step 10).
pub fn reinit(
    self: anytype,
    config: *const cocuyo.Config,
    cache_memory: ?cocuyo.cache.Slices,
    seed: u64,
    now_ns: u64,
) @TypeOf(self.*).InitErrorType!void {
    config.assert_valid();
    @TypeOf(self.*).assert_tls(config);
    assert_cache_memory(cache_memory);
    assert(self.resolver.in_flight() == 0);
    _ = now_ns;
    tcp.cancel_all(self);
    tcp.close_all(self);
    self.tcp_connection = @splat(null);
    request_tend.cancel_all(self);
    request_tend.close_all(self);
    channel_link.cancel_all(self);
    channel_link.close_all(self);
    channel_module.forget_all(self);
    request_module.forget_all(self);
    self.sockets.cancel(self.loop);
    self.sockets.close();
    self.config = config;
    // A ticket was a server's of the old configuration (docs/design.md §21, TLS rule 8, and §24,
    // request rule 10).
    self.tls_tickets = @splat(null);
    self.quic.tickets = @splat(null);
    reset_tables(self, config, cache_memory, seed);
    try self.sockets.open(self.loop, config, seed, @TypeOf(self.*).tag);
}
