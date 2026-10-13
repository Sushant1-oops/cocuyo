//! The limits of DoH that `cocuyo_doh` reads (docs/design.md §24, New limits).
const std = @import("std");

/// A DoH request's slot: the HEADERS frame of its GET (docs/design.md §24, New limits). colibri's
/// bound on the frame is 317 octets beside `:authority` and `:path`, an authority takes 259 at
/// most (a 253-octet name and a port), and 960 are left for the path, whose `dns` value takes 512.
/// The bound was read off colibri's HTTP/3; HTTP/2's HEADERS frame is no longer, since its frame
/// header is nine octets and HPACK's literals are no longer than QPACK's.
pub const doh_request_bytes_max: usize = 1536;

/// A DoH connection's answer buffers when the consumer names none: one for each response in
/// flight, each holding an answer at its longest (docs/design.md §24, New limits). Chosen,
/// not measured.
pub const answers_default: usize = 4;

// A constant with no type is a `comptime_int`, which takes the type of a narrow runtime value it
// meets in a sum. The lint rule reads the shape of each value, and this reads the type, so an
// alias or a call that gives a `comptime_int` is caught here (docs/design.md §16 decision 40).
test "each integer constant here has a type" {
    inline for (@typeInfo(@This()).@"struct".decls) |declaration| {
        const untyped = @TypeOf(@field(@This(), declaration.name)) == comptime_int;
        try std.testing.expectEqualStrings("", if (untyped) declaration.name else "");
    }
}
