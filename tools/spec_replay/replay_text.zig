//! How the replay spells a lookup: what it answers, its state as the model writes one, and the
//! cause it holds (spec/lean/Spec/Tokens.lean). Split from `replay.zig` by the file-length rule.
//!
//! The engine's walks spell each lookup with `state_text`, as TLC writes them: the engine model
//! holds whether a server failed a lookup, and not the cause (spec/README.md). The lookup's
//! transcript ends each line with the cause as well, which `line_text` writes.
const std = @import("std");
const core = @import("core");
const resolver = @import("resolver");
const Lookup = resolver.Lookup;
const Cause = resolver.Cause;

/// The longest state a line writes: the longest stage, four counters, the flags and the cause.
pub const state_bytes_max = 64;

/// What a lookup answers: the model's `Out`, with each failure spelt out.
pub const Out = enum {
    send_udp,
    connect_tcp,
    send_tcp,
    send_request,
    wait,
    done,
    failed_name_not_found,
    failed_no_data,
    failed_timeout,
    failed_all_servers_failed,
    failed_chain_too_long,
    failed_canceled,
    failed_no_servers,
    /// A failure the model has no name for, which is a disagreement whatever the model said.
    failed_other,
    accepted,
    ignored,
    none,
};

/// The lookup's state as the model writes one (spec/lean/Spec/Tokens.lean, `stateToken`).
pub fn state_text(lookup: *const Lookup, out: *[state_bytes_max]u8) []const u8 {
    return switch (lookup.state) {
        .done => "done - -",
        .failed => std.fmt.bufPrint(out, "failed {s} -", .{
            @tagName(failed_out(lookup.failure))["failed_".len..],
        }) catch unreachable,
        else => running_text(lookup, out),
    };
}

/// The state and then the cause, as the lookup's transcript ends a line (`lineToken`). A lookup
/// that has failed reports its cause in its `Failure`, so the replay reads it there.
pub fn line_text(lookup: *const Lookup, out: *[state_bytes_max]u8) []const u8 {
    var state: [state_bytes_max]u8 = undefined;
    const cause = if (lookup.state == .failed) lookup.failure_of().cause else lookup.cause;
    return std.fmt.bufPrint(out, "{s} {s}", .{ state_text(lookup, &state), cause_text(cause) }) catch unreachable;
}

/// A cause as the model spells one (`causeToken`). The model's SERVFAIL, FORMERR and BADCOOKIE
/// replies carry those three rcodes (`fixtures.zig`), so any other rcode is a disagreement.
pub fn cause_text(cause: ?Cause) []const u8 {
    const held = cause orelse return "-";
    return switch (held) {
        .rcode => |rcode| switch (rcode) {
            .server_failure => "servfail",
            .format_error => "formerr",
            .bad_cookie => "badcookie",
            else => "other",
        },
        .connect => "connect",
        .stream => "stream",
        .request => "request",
    };
}

fn running_text(lookup: *const Lookup, out: *[state_bytes_max]u8) []const u8 {
    const flags = lookup.flags;
    return std.fmt.bufPrint(out, "{s} {d}/{d}/{d}/{d} {c}{c}{c}{c}", .{
        @tagName(lookup.state),
        lookup.server_index,
        lookup.round,
        lookup.candidate_index,
        lookup.cname_hops,
        flag(flags.edns_enabled, 'E'),
        flag(flags.had_no_data, 'N'),
        // Whether a server failed the lookup, which the cause says (docs/design.md §5).
        flag(lookup.cause != null, 'F'),
        flag(flags.cookie_retried, 'K'),
    }) catch unreachable;
}

fn flag(set: bool, letter: u8) u8 {
    return if (set) letter else '-';
}

pub fn out_of(action: resolver.Action) Out {
    return switch (action) {
        .send_udp => .send_udp,
        .connect_tcp => .connect_tcp,
        .send_tcp => .send_tcp,
        .send_request => .send_request,
        .wait => .wait,
        .done => .done,
        .failed => |failure| failed_out(failure.err),
    };
}

fn failed_out(err: core.Error) Out {
    return switch (err) {
        error.NameNotFound => .failed_name_not_found,
        error.NoData => .failed_no_data,
        error.Timeout => .failed_timeout,
        error.AllServersFailed => .failed_all_servers_failed,
        error.ChainTooLong => .failed_chain_too_long,
        error.Canceled => .failed_canceled,
        error.NoServers => .failed_no_servers,
        else => .failed_other,
    };
}

// Tests.

const testing = std.testing;

test "each cause is spelt as the model spells it, and an rcode the model has no reply for is other" {
    try testing.expectEqualStrings("-", cause_text(null));
    try testing.expectEqualStrings("servfail", cause_text(.{ .rcode = .server_failure }));
    try testing.expectEqualStrings("formerr", cause_text(.{ .rcode = .format_error }));
    try testing.expectEqualStrings("badcookie", cause_text(.{ .rcode = .bad_cookie }));
    try testing.expectEqualStrings("other", cause_text(.{ .rcode = .refused }));
    try testing.expectEqualStrings("connect", cause_text(.connect));
    try testing.expectEqualStrings("stream", cause_text(.stream));
    try testing.expectEqualStrings("request", cause_text(.request));
}
