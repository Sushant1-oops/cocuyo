//! A datagram at the room that a buffer of the engine's datagram group gives it (docs/design.md
//! §19 step 13, the datagram's rule 3). That room is `buffer_bytes`, 2,048 octets, less rotor's
//! prefix of 192 octets: 1,856 octets. The twin carries 1,232 octets at most, so each test writes
//! the completion of a receive itself, into a buffer of the group, as the kernel writes one. Split
//! from `io_sim_test.zig` by the file-length rule.
const std = @import("std");
const testing = std.testing;
const cocuyo = @import("cocuyo");
const rotor = @import("rotor");
const io = @import("io.zig");

const sim_test = @import("io_sim_test.zig");
const Rig = sim_test.Rig;
const question = sim_test.question;

const integer = cocuyo.wire.integer;
const u16_bytes = cocuyo.wire.constants.u16_bytes;

/// The octets of a datagram that fill a buffer of the group after rotor's prefix.
fn room(rig: *const Rig) usize {
    return rotor.datagram.payload_capacity(io.constants.buffer_bytes, rig.loop.group_options);
}

/// The scripted server's answer to the query of `handle`'s lookup, written into `out`. A Padding
/// option of zeros (RFC 7830 §3) grows its OPT record, the last record, until the message is
/// `total` octets.
fn padded_answer(rig: *Rig, handle: cocuyo.Handle, total: usize, out: []u8) ![]const u8 {
    const server = rotor.Network.server_address(0);
    const query = &rig.engine.send_buffers[handle.index];
    const answer = rotor.server.respond(&.{}, &server, query, false, 0, out) orelse return error.NoAnswer;
    var name: cocuyo.Name = cocuyo.Name.empty;
    _ = try cocuyo.wire.question.parse(out[0..answer.len], &name);
    const opt = (try cocuyo.wire.response_opt.find(out[0..answer.len], &name)) orelse return error.NoOpt;
    try testing.expectEqual(answer.len, opt.end);
    const padding = total - answer.len - cocuyo.constants.opt_option_header_bytes;
    integer.write_u16(out, answer.len, cocuyo.wire.constants.padding_option_code);
    integer.write_u16(out, answer.len + u16_bytes, @intCast(padding));
    @memset(out[answer.len + cocuyo.constants.opt_option_header_bytes ..][0..padding], 0);
    const rdlength_at = opt.end - opt.rdata.len - u16_bytes;
    integer.write_u16(out, rdlength_at, @intCast(total - (opt.end - opt.rdata.len)));
    return out[0..total];
}

/// Hands the engine a completion of server `server`'s current receive, as the kernel writes one:
/// the octets that fit the room of a buffer, and the truncated flag when the datagram was longer.
fn deliver(rig: *Rig, server: u8, datagram: []const u8) !void {
    const group = &rig.loop.groups[io.constants.group_id];
    const id = group.take() orelse return error.NoBuffer;
    const buffer = rig.loop.provided_buffer(io.constants.group_id, id);
    const peer = rotor.Network.server_address(server);
    const kept = datagram[0..@min(datagram.len, room(rig))];
    const len = rotor.buffers.write_delivery(buffer, rig.loop.group_options, &peer, kept);
    const metadata = buffer[rotor.constants.prefix_head_bytes..][0..@sizeOf(rotor.datagram.Received)];
    const received: *rotor.datagram.Received = @ptrCast(@alignCast(metadata));
    received.flags.truncated = datagram.len > kept.len;
    const generation: usize = rig.engine.sockets.items[server].armed_generation;
    const index = @as(usize, server) | (generation << io.constants.receive_generation_shift);
    const event: rotor.Event = .{
        .user_data = @TypeOf(rig.engine).user_data(.udp_receive, index),
        .result = @intCast(len),
        .flags = .{ .buffer = true, .more = true, .buffer_id = id },
    };
    try testing.expect(rig.engine.apply(event, rig.loop.now()));
}

/// A lookup whose query went to server 0, which is down, so only the test answers it.
fn waiting(rig: *Rig, seed: u64) !cocuyo.Handle {
    try rig.init(seed, .{ .{ .down = true }, .{ .down = true } }, .{ .servers = &.{} });
    const handle = try rig.engine.start(question("example.com."), rig.loop.now());
    _ = try rig.step(0);
    try testing.expectEqual(@as(usize, 1), rig.engine.active());
    return handle;
}

test "a datagram that fills a buffer of the group to its last octet is read whole, and answers" {
    var rig: Rig = .{};
    const handle = try waiting(&rig, 31);
    // 2,048 octets, less rotor's prefix: the room a datagram has.
    try testing.expectEqual(@as(usize, 1856), room(&rig));
    var out: [io.constants.buffer_bytes]u8 = undefined;
    const answer = try padded_answer(&rig, handle, room(&rig), &out);
    const free = rig.loop.groups[io.constants.group_id].free_count;
    try deliver(&rig, 0, answer);
    // The table read the datagram, and its buffer went back (rule 3).
    try testing.expectEqual(free, rig.loop.groups[io.constants.group_id].free_count);
    const result = rig.engine.take(rig.loop.now()) orelse return error.TestUnexpectedResult;
    try testing.expectEqual(handle, result.handle);
    try testing.expectEqual(@as(usize, 1), result.outcome.answer.addresses.len);
    _ = rig.engine.take(rig.loop.now());
    try rig.deinit();
}

test "a datagram one octet longer than the room is read cut, and its lookup waits on" {
    // The kernel keeps the octets that fit, and says that the datagram was truncated. The engine
    // reads no such flag: the table reads the cut octets as they are (rule 3). The OPT record now
    // runs past the end, so check 6 finds no OPT to read, and the lookup ignores the message
    // (docs/design.md §7).
    var rig: Rig = .{};
    const handle = try waiting(&rig, 32);
    var out: [io.constants.buffer_bytes]u8 = undefined;
    const answer = try padded_answer(&rig, handle, room(&rig) + 1, &out);
    const free = rig.loop.groups[io.constants.group_id].free_count;
    try deliver(&rig, 0, answer);
    try testing.expectEqual(free, rig.loop.groups[io.constants.group_id].free_count);
    try testing.expect(rig.engine.take(rig.loop.now()) == null);
    try testing.expectEqual(@as(usize, 1), rig.engine.active());
    rig.engine.cancel(handle, rig.loop.now());
    try testing.expectEqual(cocuyo.Error.Canceled, (try rig.until_result()).outcome.failure.err);
    _ = rig.engine.take(rig.loop.now());
    try rig.deinit();
}
