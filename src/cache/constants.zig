//! The limits the cache holds (docs/design.md §18).
const std = @import("std");
const core = @import("core");

/// The most slots one cache may hold. A slot is named by a `u16` in the insertion-order chain and
/// in the key index, with room left for the sentinels, and nobody has asked for more.
pub const slots_max: usize = 16384;

/// The key index holds at least this many entries per slot, so a bounded probe stays short.
pub const keys_per_slot_min: usize = 2;

/// The longest chain a `get` walks before calling it a miss and a `put` before refusing. A peer
/// that chooses the names a process resolves cannot choose where they land, because the hash is
/// keyed by the caller's seed; this bound is what makes a run of collisions cost a miss and never
/// a walk.
pub const probe_max: usize = 16;

/// The TTL cap when the caller sets none: an hour, which is c-ares's default (§18), so a consumer
/// replacing it sees the same ceiling. RFC 8767 §4 asks for a cap and recommends seven days at
/// most, so an hour is inside it. It is `core`'s constant, under the name it has had here, since
/// `Config.cache_ttl_seconds_max` defaults to the same number (docs/design.md §16 decision 37).
pub const ttl_seconds_max_default = core.constants.cache_ttl_seconds_max_default;

/// Where the type and the flag sit in the word the hash starts from: the flag's one bit at 40,
/// the type's sixteen at 48, so the two never overlap whatever the seed.
pub const hash_absolute_shift: u6 = 40;
pub const hash_kind_shift: u6 = 48;

/// Nanoseconds in a second, spelled out because nothing under `src/` may name `std.time`
/// (CLAUDE.md non-negotiable 4).
pub const ns_per_s: u64 = 1_000_000_000;

/// The most steps one eviction sweep takes: one pass over every slot clears every visited bit,
/// and the next pass must then find an unvisited one.
pub fn sweep_steps_max(slot_count: usize) usize {
    return slot_count * 2;
}

comptime {
    if (slots_max * keys_per_slot_min > 1 << 16) @compileError("the key index cannot be indexed by a u16");
    if (slots_max >= 0xfffe) @compileError("a slot index would collide with a sentinel");
    if (probe_max < 2) @compileError("a probe of one entry is a hash lookup with no chain");
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
