//! The fuzz target for the codec: one seed in, one message built by fuzz_generate.zig, every
//! parser run over it by fuzz_check.zig.
//!
//! The gate below is a test, so `zig build test` runs it over `seed_count` seeds and prints
//! nothing unless a seed fails. `zig build fuzz -- --seed <hex>` runs one seed and prints what it
//! built, which is how a failure is reproduced: the seed is the whole input.
//!
//! Zig 0.16 has a coverage-guided fuzzer of its own behind `zig build test --fuzz`, which needs a
//! build with instrumentation. It is not wired here: in Zig 0.16.0 the test runner itself does not
//! compile in fuzz mode (`compiler/test_runner.zig` hands `std.debug.writeStackTrace` a
//! `*builtin.StackTrace`), which a test of nothing but `std.testing.fuzz` showed on 2026-09-26.
//! This gate is portable, deterministic and runs on every host, which is what a check that must
//! pass before every commit needs to be; a guided fuzzer is a good thing to add beside it, not
//! instead of it, once the Zig cocuyo pins can build one.
const std = @import("std");
const generate_module = @import("fuzz_generate.zig");
const check_module = @import("fuzz_check.zig");

pub const Message = generate_module.Message;
pub const Strategy = generate_module.Strategy;
pub const generate = generate_module.generate;
pub const check = check_module.check;

/// How many seeds `zig build test` runs. Every seed builds a message of up to 1232 octets and runs
/// five parsers over it, so this is the largest count that keeps the gate inside a second or two.
pub const seed_count = 4096;

/// Runs one seed. Returns the promise that broke, or null when the message held up.
pub fn run(seed: u64, out: *Message) ?[]const u8 {
    generate(seed, out);
    return verdict(out);
}

/// What the check says of a message, and of a record written whole, whether it was taken whole.
pub fn verdict(message: *const Message) ?[]const u8 {
    if (check(message.slice())) |failure| return failure;
    if (message.whole) return check_module.check_whole(message.slice());
    return null;
}

/// Runs `count` seeds from `first`. Returns the first seed that failed and what broke.
pub const Failure = struct { seed: u64, what: []const u8 };

pub fn gate(first: u64, count: u64) ?Failure {
    var message: Message = .{};
    var seed = first;
    const last = first + count;
    while (seed < last) : (seed += 1) {
        if (run(seed, &message)) |what| return .{ .seed = seed, .what = what };
    }
    return null;
}

// Tests.

const testing = std.testing;

test "the fuzz gate holds over every seed it runs" {
    if (gate(0, seed_count)) |failure| {
        std.debug.print(
            "fuzz: seed 0x{x} broke a promise: {s}\n  reproduce with: zig build fuzz -- --seed 0x{x}\n",
            .{ failure.seed, failure.what, failure.seed },
        );
        return error.FuzzInvariantViolated;
    }
}

test "a seed that built a message reaching the parsers is checked, not merely rejected" {
    // A gate that only ever built unparseable noise would pass while checking nothing, so this
    // pins that some seeds produce messages the record walk actually reads.
    var message: Message = .{};
    var parsed: usize = 0;
    var seed: u64 = 0;
    while (seed < 256) : (seed += 1) {
        generate(seed, &message);
        if (message.strategy == .question_then_noise and message.len > 64) parsed += 1;
    }
    try testing.expect(parsed > 0);
}

test "a long question of every name length from the shortest long one to 255 octets is written" {
    // Its class lies past octet 255 of the message from a name of 242 octets on, and its type from
    // 244, where check 5's offsets overflowed once (docs/mutations.md, QO1): the seeds reach each.
    const core = @import("core");
    const shortest = @import("constants.zig").fuzz_question_name_bytes_min;
    var seen: [core.constants.name_bytes_max - shortest + 1]bool = @splat(false);
    var message: Message = .{};
    for (0..seed_count) |seed| {
        generate(seed, &message);
        if (message.strategy != .long_question) continue;
        var name: core.Name = core.Name.empty;
        const parsed = try @import("question.zig").parse(message.slice(), &name);
        try testing.expect(core.Kind.from_code(parsed.kind_code).?.queryable());
        seen[name.len - shortest] = true;
    }
    for (seen) |reached| try testing.expect(reached);
}

/// The farthest offset a pointer of a maze aims at: every two octets after the header are one.
fn farthest_target(message: *const Message) usize {
    const constants = @import("constants.zig");
    const bytes = message.slice();
    var farthest: usize = 0;
    var offset: usize = @import("core").constants.header_bytes;
    while (offset + constants.pointer_bytes <= bytes.len) : (offset += constants.pointer_bytes) {
        const pointer = @import("integer.zig").read_u16(bytes, offset);
        farthest = @max(farthest, pointer & constants.pointer_offset_mask);
    }
    return farthest;
}

test "a pointer maze aims its pointers anywhere in the message, past offset 255 too" {
    // A pointer's first octet holds the six high bits of the offset it aims at (RFC 1035 §4.1.4).
    var message: Message = .{};
    var mazes: usize = 0;
    var far: usize = 0;
    for (0..seed_count) |seed| {
        generate(seed, &message);
        if (message.strategy != .pointer_maze) continue;
        const farthest = farthest_target(&message);
        try testing.expect(farthest < message.len);
        mazes += 1;
        if (farthest > std.math.maxInt(u8)) far += 1;
    }
    // Most mazes are longer than 256 octets, and hold hundreds of pointers.
    try testing.expect(far > mazes / 2);
}

test "a record written whole that its view refuses fails the verdict, and the same record changed does not" {
    const fixtures = @import("rdata/rdata.zig").fixtures;
    // A CAA whose tag is empty, which RFC 8659 §4.1 forbids and the copy takes as it is.
    const refused = fixtures.caa_response(&fixtures.caa_tag_zero);
    var message: Message = .{ .len = refused.len, .strategy = .record, .whole = true };
    @memcpy(message.bytes[0..refused.len], &refused);
    try testing.expect(verdict(&message) != null);
    message.whole = false;
    try testing.expectEqual(@as(?[]const u8, null), verdict(&message));
}
