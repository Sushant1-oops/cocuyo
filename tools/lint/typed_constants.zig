//! typed-constants: every integer constant of a constants file carries a type (docs/design.md §16
//! decision 40). An integer constant with no type is a `comptime_int`. When it meets a runtime
//! integer, the sum takes the runtime integer's type. So `header_bytes + name.len` was a sum in
//! the octet that holds a name's length, and it overflowed from a name of 244 octets
//! (docs/mutations.md, Sums at the most their operands reach). A constant of type `usize` makes
//! that sum a `usize`.
//!
//! The rule reads each constants file of `src/` and `io/`: a Zig file whose name holds
//! `constants`, or a Zig file under a directory named `constants`. So it reads the pieces that
//! CLAUDE.md's split rule makes of a constants file: `constants_<piece>.zig`, and
//! `constants/<piece>.zig` once four pieces move into a directory.
//!
//! The rule reads each `const` that is a member of a container: the file's top level, or a
//! `struct`, `union`, `enum` or `opaque` in it. It reports such a `const` when its type is
//! `comptime_int`. It also reports it when it has no type and its value is integer-shaped. These
//! values are integer-shaped:
//!
//! - an integer literal or a character literal;
//! - an arithmetic, bitwise or shift operator, whatever its operands are;
//! - a builtin that gives a `comptime_int` from comptime operands, such as `@sizeOf` or `@min`;
//! - `@as(comptime_int, ...)`;
//! - a call of `maxInt` or `minInt`;
//! - a negation, a bitwise not, parentheses, or an `if`, around one of these;
//! - a `switch` with one of these in a prong, and a block with one of these in a `break`.
//!
//! A prong or a `break` of another type can make a false report. A written type ends it.
//!
//! The rule does not report an identifier or a field access. That is an alias, and it has the type
//! of what it names. It does not report another call, which has its return type, or `@as` of
//! another type. It does not read an `orelse`, a `catch` or an index into a tuple. It does not read
//! the constants of a function body or of a `comptime` block. The test in each constants file reads
//! the types of its public constants, and it catches what this rule cannot see: an alias of a
//! constant with no type, or a call that gives a `comptime_int` (docs/design.md §16 decision 40).
//!
//! The rule cannot see a sum of two narrow runtime values with no constant in it. The type of the
//! sum is the type of its operands, and no constant is there to widen it.
//!
//! The rule is cocuyo's own, and the only rule here that is not pepegrillo's.
const std = @import("std");
const Ast = std.zig.Ast;
const Node = Ast.Node;
const pepegrillo = @import("pepegrillo");
const lint = pepegrillo.lint;
const ast = lint.ast;
const report = lint.report;

pub const Config = struct {
    /// The rule name findings are reported under and `--rule` selects.
    name: []const u8 = "typed-constants",
    /// The files the rule reads.
    scope: lint.Scope,
};

/// The configuration: the Zig files of the library and of the engine, of which `reads_file` takes
/// the constants files. `bench/` and `tools/` are outside it, since neither is linked into the
/// library.
pub const config: Config = .{
    .scope = .{ .extensions = &.{".zig"}, .include_directories = &.{ "src", "io" } },
};

/// The part of a name that makes a file a constants file, or a directory a directory of them.
const constants_name = "constants";

/// Whether the rule reads `path`: a file of the scope whose name holds `constants`, or a file of
/// the scope under a directory named `constants`.
fn reads_file(scope: *const lint.Scope, path: []const u8) bool {
    if (!scope.applies(path)) return false;
    if (std.mem.indexOf(u8, lint.paths.basename(path), constants_name) != null) return true;
    return lint.paths.is_under(path, constants_name);
}

const Rule = TypedConstants(config);
pub const name = Rule.name;
pub const check = Rule.check;

/// The rule for one configuration: a type with the `name` and `check` the driver dispatches to.
fn TypedConstants(comptime rule_config: Config) type {
    comptime std.debug.assert(rule_config.name.len != 0);
    return struct {
        pub const name = rule_config.name;
        const settings: Config = rule_config;

        pub fn check(context: *report.Context, file: report.File) !void {
            if (!reads_file(&settings.scope, file.path)) return;
            const tree = file.tree orelse return;
            var visitor: Visitor = .{
                .tree = tree,
                .findings = &context.findings,
                .path = file.path,
                .name = settings.name,
            };
            visitor.check_members(tree.rootDecls());
            if (visitor.failure) |failure| return failure;
        }
    };
}

const Visitor = struct {
    tree: *const Ast,
    findings: *report.Findings,
    path: []const u8,
    name: []const u8,
    depth: u32 = 0,
    failure: ?anyerror = null,

    /// Each member of one container, and each container inside a member.
    fn check_members(self: *Visitor, members: []const Node.Index) void {
        for (members) |member| {
            if (self.tree.fullVarDecl(member)) |declaration| self.check_declaration(declaration);
            ast.for_each_child(self.tree, member, self);
        }
    }

    /// The walk below a member. It looks for containers, and reads no `const` that is not a
    /// container's member.
    pub fn child(self: *Visitor, node: Node.Index) void {
        self.depth += 1;
        defer self.depth -= 1;
        std.debug.assert(self.depth <= ast.max_tree_depth);
        var buffer: [2]Node.Index = undefined;
        if (self.tree.fullContainerDecl(&buffer, node)) |container| {
            return self.check_members(container.ast.members);
        }
        ast.for_each_child(self.tree, node, self);
    }

    fn check_declaration(self: *Visitor, declaration: Ast.full.VarDecl) void {
        if (self.tree.tokenTag(declaration.ast.mut_token) != .keyword_const) return;
        if (!has_no_type(self.tree, declaration)) return;
        const name_token = declaration.ast.mut_token + 1;
        const location = ast.token_location(self.tree, name_token);
        self.findings.add(
            self.name,
            self.path,
            location.line,
            location.column,
            "const {s} is an integer with no type: write the type of what it names",
            .{self.tree.tokenSlice(name_token)},
        ) catch |failure| {
            self.failure = failure;
        };
    }
};

/// Whether a `const` is a `comptime_int`: its type is written as `comptime_int`, or no type is
/// written and its value is integer-shaped.
fn has_no_type(tree: *const Ast, declaration: Ast.full.VarDecl) bool {
    if (declaration.ast.type_node.unwrap()) |written| return names_comptime_int(tree, written);
    const value = declaration.ast.init_node.unwrap() orelse return false;
    return integer_shaped(tree, value, 0);
}

/// Whether `node` is the identifier `comptime_int`.
fn names_comptime_int(tree: *const Ast, node: Node.Index) bool {
    if (tree.nodeTag(node) != .identifier) return false;
    return std.mem.eql(u8, tree.tokenSlice(tree.nodeMainToken(node)), "comptime_int");
}

/// The builtins that give a `comptime_int` when their operands are comptime integers.
const comptime_int_builtins = [_][]const u8{
    "@sizeOf", "@bitSizeOf", "@alignOf",  "@offsetOf", "@bitOffsetOf",
    "@min",    "@max",       "@divExact", "@divFloor", "@divTrunc",
    "@mod",    "@rem",       "@shlExact", "@shrExact", "@abs",
};

/// The functions of `std.math` that give a `comptime_int`.
const comptime_int_functions = [_][]const u8{ "maxInt", "minInt" };

/// Whether `node` is a value the compiler holds as a `comptime_int`, by its shape alone.
fn integer_shaped(tree: *const Ast, node: Node.Index, depth: u32) bool {
    if (depth > ast.max_tree_depth) return false;
    return switch (tree.nodeTag(node)) {
        .number_literal => is_integer_literal(tree, node),
        .char_literal => true,
        .negation, .negation_wrap, .bit_not => integer_shaped(tree, tree.nodeData(node).node, depth + 1),
        .grouped_expression => integer_shaped(tree, tree.nodeData(node).node_and_token[0], depth + 1),
        .add, .sub, .mul, .div, .mod, .shl, .shr, .bit_and, .bit_or, .bit_xor => true,
        .add_wrap, .sub_wrap, .mul_wrap, .add_sat, .sub_sat, .mul_sat, .shl_sat => true,
        .builtin_call_two, .builtin_call_two_comma, .builtin_call, .builtin_call_comma => builtin_shaped(tree, node),
        .call_one, .call_one_comma, .call, .call_comma => calls_comptime_int(tree, node),
        .@"if", .if_simple => if_shaped(tree, node, depth),
        .@"switch", .switch_comma => switch_shaped(tree, node, depth),
        .block, .block_semicolon, .block_two, .block_two_semicolon => block_shaped(tree, node, depth),
        else => false,
    };
}

fn is_integer_literal(tree: *const Ast, node: Node.Index) bool {
    const literal = tree.tokenSlice(tree.nodeMainToken(node));
    return switch (std.zig.number_literal.parseNumberLiteral(literal)) {
        .int, .big_int => true,
        .float, .failure => false,
    };
}

/// Whether a builtin gives a `comptime_int`: one of `comptime_int_builtins`, or `@as` whose type
/// is `comptime_int`.
fn builtin_shaped(tree: *const Ast, node: Node.Index) bool {
    const builtin = tree.tokenSlice(tree.nodeMainToken(node));
    if (is_any(builtin, &comptime_int_builtins)) return true;
    if (!std.mem.eql(u8, builtin, "@as")) return false;
    var buffer: [2]Node.Index = undefined;
    const parameters = tree.builtinCallParams(&buffer, node).?;
    return parameters.len != 0 and names_comptime_int(tree, parameters[0]);
}

/// Whether a prong of a `switch` is integer-shaped: then the `switch` is a `comptime_int` too.
fn switch_shaped(tree: *const Ast, node: Node.Index, depth: u32) bool {
    const full = tree.fullSwitch(node).?;
    for (full.ast.cases) |case| {
        const prong = tree.fullSwitchCase(case).?;
        if (integer_shaped(tree, prong.ast.target_expr, depth + 1)) return true;
    }
    return false;
}

/// Whether a `break` in a block gives an integer-shaped value: then a labeled block is a
/// `comptime_int` too. It reads each `break` in the block, whatever its label.
fn block_shaped(tree: *const Ast, node: Node.Index, depth: u32) bool {
    var finder: BreakFinder = .{ .tree = tree, .depth = depth };
    ast.for_each_child(tree, node, &finder);
    return finder.found;
}

/// The walk of a block that looks for a `break` with an integer-shaped value.
const BreakFinder = struct {
    tree: *const Ast,
    depth: u32,
    found: bool = false,

    pub fn child(self: *BreakFinder, node: Node.Index) void {
        if (self.found or self.depth > ast.max_tree_depth) return;
        if (self.tree.nodeTag(node) == .@"break") {
            const value = self.tree.nodeData(node).opt_token_and_opt_node[1].unwrap() orelse return;
            self.found = integer_shaped(self.tree, value, self.depth + 1);
            return;
        }
        self.depth += 1;
        defer self.depth -= 1;
        ast.for_each_child(self.tree, node, self);
    }
};

/// Whether either branch of an `if` is integer-shaped: then the `if` is a `comptime_int` too.
fn if_shaped(tree: *const Ast, node: Node.Index, depth: u32) bool {
    const full = tree.fullIf(node).?;
    if (integer_shaped(tree, full.ast.then_expr, depth + 1)) return true;
    const otherwise = full.ast.else_expr.unwrap() orelse return false;
    return integer_shaped(tree, otherwise, depth + 1);
}

/// Whether a call names `maxInt` or `minInt` last: `std.math.maxInt(u16)` or `math.minInt(i8)`.
fn calls_comptime_int(tree: *const Ast, node: Node.Index) bool {
    var buffer: [1]Node.Index = undefined;
    const call = tree.fullCall(&buffer, node).?;
    return is_any(tree.tokenSlice(tree.lastToken(call.ast.fn_expr)), &comptime_int_functions);
}

fn is_any(text: []const u8, names: []const []const u8) bool {
    for (names) |candidate| {
        if (std.mem.eql(u8, text, candidate)) return true;
    }
    return false;
}

// Tests. Each fixture pins one shape from the header.

const testing = std.testing;
const harness = lint.harness;

fn expect_findings(path: []const u8, source: [:0]const u8, expected: []const []const u8) !void {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    try harness.expect_messages(try harness.run(arena_state.allocator(), Rule, path, source), expected);
}

fn message(comptime constant: []const u8) []const u8 {
    return "const " ++ constant ++ " is an integer with no type: write the type of what it names";
}

test "typed-constants reports a literal, an operator and a builtin with no type" {
    try expect_findings("src/core/constants.zig",
        \\pub const header_bytes = 12;
        \\pub const comment_start = '#';
        \\pub const negative = -1;
        \\pub const sum = header_bytes + 4;
        \\pub const mask = (1 << 8) - 1;
        \\pub const wrapped = header_bytes +% 4;
        \\pub const octet_bits = @bitSizeOf(u8);
        \\pub const least = @min(header_bytes, 4);
        \\pub const most = std.math.maxInt(u16);
        \\pub const chosen = if (header_bytes > 4) 1 else 2;
        \\pub const grouped = (4);
        \\const private_bytes = 3;
        \\
    , &.{
        message("header_bytes"), message("comment_start"), message("negative"),
        message("sum"),          message("mask"),          message("wrapped"),
        message("octet_bits"),   message("least"),         message("most"),
        message("chosen"),       message("grouped"),       message("private_bytes"),
    });
}

test "typed-constants reports a switch, a labeled block, @abs and a comptime_int type" {
    try expect_findings("src/core/constants.zig",
        \\pub const page_bytes = switch (builtin.cpu.arch) {
        \\    .x86_64 => 4096,
        \\    else => 16384,
        \\};
        \\pub const chunk_bytes = chunk: {
        \\    const half = @as(u16, 512);
        \\    break :chunk half * 2;
        \\};
        \\pub const distance = @abs(-4);
        \\pub const pinned: comptime_int = 4;
        \\pub const cast = @as(comptime_int, 4);
        \\pub const typed_switch = switch (builtin.cpu.arch) {
        \\    .x86_64 => @as(u16, 4096),
        \\    else => @as(u16, 16384),
        \\};
        \\pub const typed_block = chunk: {
        \\    break :chunk @as(u16, 1024);
        \\};
        \\pub const typed_cast = @as(u16, 4);
        \\
    , &.{
        message("page_bytes"), message("chunk_bytes"), message("distance"),
        message("pinned"),     message("cast"),
    });
}

test "typed-constants reads a container's members, and no function's or block's locals" {
    try expect_findings("io/io_quic_constants.zig",
        \\pub const Limits = struct {
        \\    pub const inner_bytes = 8;
        \\    pub fn sweep(count: usize) usize {
        \\        const local = 4;
        \\        return count * local;
        \\    }
        \\};
        \\comptime {
        \\    const unpadded = 12 + 255;
        \\    _ = unpadded;
        \\}
        \\test "a test's constant" {
        \\    const expected = 3;
        \\    _ = expected;
        \\}
        \\
    , &.{message("inner_bytes")});
}

test "typed-constants passes a typed constant, an alias, a call and every value of another type" {
    try expect_findings("io/constants.zig",
        \\const std = @import("std");
        \\const core = @import("core");
        \\pub const header_bytes: usize = 12;
        \\pub const typed_sum: usize = header_bytes + 4;
        \\pub var counter = 0;
        \\pub const alias = core.constants.servers_max;
        \\pub const local_alias = header_bytes;
        \\pub const length = prefix.len;
        \\pub const prefix = [_]u8{ 1, 2 };
        \\pub const keyword = "nameserver";
        \\pub const seconds = 2.5;
        \\pub const Row = struct { bits: u8 };
        \\pub const size = std.base64.url_safe_no_pad.Encoder.calcSize(384);
        \\pub const named = @as(u16, 443);
        \\pub const kind = .label;
        \\pub const truth = 4 > 3;
        \\
    , &.{});
}

fn reads(path: []const u8) bool {
    return reads_file(&config.scope, path);
}

test "typed-constants reads the constants files of src/ and io/, and nothing else" {
    try testing.expect(reads("src/core/constants.zig"));
    try testing.expect(reads("src/sim/constants.zig"));
    try testing.expect(reads("io/constants.zig"));
    try testing.expect(reads("io/io_quic_constants.zig"));
    try testing.expect(reads("io/io_doh_channel_constants.zig"));
    try testing.expect(!reads("src/core/name.zig"));
    try testing.expect(!reads("io/io_quic_plain.zig"));
    try testing.expect(!reads("bench/end_to_end/constants.zig"));
    try testing.expect(!reads("tools/constants.zig"));
    try testing.expect(!reads("src/core/constants.md"));
}

test "typed-constants reads the pieces that the split rule makes of a constants file" {
    try testing.expect(reads("src/core/constants_address.zig"));
    try testing.expect(reads("src/core/constants/address.zig"));
    try testing.expect(reads("io/io_doh_channel/constants.zig"));
    try testing.expect(!reads("src/core/constant.zig"));
    try testing.expect(!reads("bench/end_to_end/constants/limits.zig"));
}
