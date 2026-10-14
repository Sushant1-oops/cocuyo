//! Every number the wire format fixes: the offsets of the header fields, the flag bits, the
//! response codes, and the two bits that tell a label from a compression pointer. Each is named
//! here and never written at the use site (CLAUDE.md non-negotiable 5), with the RFC section that
//! fixes it.
const std = @import("std");

/// Two octets, the width of every count and every integer in the header (RFC 1035 §4.1.1).
pub const u16_bytes: usize = @sizeOf(u16);

/// Four octets, the width of a TTL and of the OPT record's flag field (RFC 1035 §4.1.3).
pub const u32_bytes: usize = @sizeOf(u32);

/// The bits in an octet, so a shift by a whole octet names what it shifts by.
pub const octet_bits: u4 = @bitSizeOf(u8);

// The header, RFC 1035 §4.1.1: six two-octet fields in this order.
pub const header_id_offset: usize = 0;
pub const header_flags_offset: usize = 2;
pub const header_qdcount_offset: usize = 4;
pub const header_ancount_offset: usize = 6;
pub const header_nscount_offset: usize = 8;
pub const header_arcount_offset: usize = 10;

// A record's fixed part after the owner name, RFC 1035 §4.1.3: type, class, TTL, rdlength.
pub const record_kind_offset: usize = 0;
pub const record_class_offset: usize = 2;
pub const record_ttl_offset: usize = 4;
pub const record_rdlength_offset: usize = 8;

/// An SOA's rdata after its two names: SERIAL, REFRESH, RETRY, EXPIRE and MINIMUM, four octets
/// each (RFC 1035 §3.3.13). MINIMUM is the last, and is the negative-caching TTL (RFC 2308 §5).
pub const soa_fixed_bytes: usize = 20;
pub const soa_minimum_offset: usize = 16;
pub const soa_refresh_offset: usize = 4;
pub const soa_retry_offset: usize = 8;
pub const soa_expire_offset: usize = 12;

/// MX: a 16-bit preference, then the exchange name (RFC 1035 §3.3.9).
pub const mx_fixed_bytes: usize = 2;

/// SRV: priority, weight and port, 16 bits each, then the target name (RFC 2782).
pub const srv_fixed_bytes: usize = 6;
pub const srv_weight_offset: usize = 2;
pub const srv_port_offset: usize = 4;

/// NAPTR: order and preference, 16 bits each, then three character-strings and the replacement
/// name (RFC 3403 §4.1).
pub const naptr_fixed_bytes: usize = 4;
pub const naptr_preference_offset: usize = 2;

/// SIG: type covered (16), algorithm (8), labels (8), original TTL (32), expiration (32),
/// inception (32) and key tag (16), then the signer's name and the signature (RFC 2535 §4.1).
pub const sig_fixed_bytes: usize = 18;
pub const sig_algorithm_offset: usize = 2;
pub const sig_labels_offset: usize = 3;
pub const sig_original_ttl_offset: usize = 4;
pub const sig_expiration_offset: usize = 8;
pub const sig_inception_offset: usize = 12;
pub const sig_key_tag_offset: usize = 16;

/// SVCB and HTTPS: a 16-bit priority, the uncompressed target name, then parameters of a 16-bit
/// key, a 16-bit length and a value (RFC 9460 §2.2).
pub const svcb_fixed_bytes: usize = 2;
pub const svcb_param_fixed_bytes: usize = 4;
pub const svcb_param_length_offset: usize = 2;
/// The parameter keys RFC 9460 §7 defines, whose values have a format a client checks (§2.2).
pub const svcb_key_mandatory: u16 = 0;
pub const svcb_key_alpn: u16 = 1;
pub const svcb_key_no_default_alpn: u16 = 2;
pub const svcb_key_port: u16 = 3;
pub const svcb_key_ipv4hint: u16 = 4;
pub const svcb_key_ech: u16 = 5;
pub const svcb_key_ipv6hint: u16 = 6;

/// TLSA: certificate usage, selector and matching type, one octet each, then the association
/// data (RFC 6698 §2.1).
pub const tlsa_fixed_bytes: usize = 3;
pub const tlsa_selector_offset: usize = 1;
pub const tlsa_matching_type_offset: usize = 2;

/// URI: priority and weight, 16 bits each, then the target, which must not be empty
/// (RFC 7553 §4.5).
pub const uri_fixed_bytes: usize = 4;
pub const uri_weight_offset: usize = 2;

/// CAA: flags and a tag length, one octet each, then the tag, at least one octet, then the
/// value (RFC 8659 §4.1).
pub const caa_fixed_bytes: usize = 2;
pub const caa_tag_length_offset: usize = 1;
pub const caa_tag_bytes_min: usize = 1;
/// The issuer-critical flag, bit 0 in RFC 1035's numbering, which is the high bit (RFC 8659 §4.1).
pub const caa_flag_critical: u8 = 0x80;

/// A `<character-string>`: one length octet, then at most that many octets (RFC 1035 §3.3).
pub const character_string_bytes_max: usize = 255;

/// The shape of a record the fuzz generator writes whole (`fuzz/fuzz_generate_records.zig`,
/// docs/design.md §19, step 9's gate): names of up to three labels of up to twelve letters,
/// character-strings of up to twenty octets and up to four of them in a TXT or an ALPN list,
/// opaque fields of up to thirty-two octets, and up to three addresses in an SVCB hint. A record
/// of every type then fits a message several times over. Chosen, not measured.
pub const fuzz_labels_max: usize = 3;
pub const fuzz_label_bytes_max: usize = 12;
pub const fuzz_string_bytes_max: usize = 20;
pub const fuzz_strings_max: usize = 4;
pub const fuzz_opaque_bytes_max: usize = 32;
pub const fuzz_hints_max: usize = 3;
/// An SVCB key with no format of its own, which a client keeps as it is: RFC 9460 Appendix D's
/// `key667`.
pub const fuzz_svcb_key_generic: u16 = 667;
/// The shortest name of the long questions the fuzz generator writes (`fuzz/fuzz_generate.zig`):
/// 64 lengths, from here to the longest name, 255 octets. They hold the fourteen whose question's
/// class lies past octet 255 of the message, from 242 octets on, and fifty shorter. The gate's
/// 4096 seeds over ten strategies give each length about six seeds, by arithmetic, and a test of
/// `fuzz/fuzz.zig` pins that each is reached. Chosen, not measured.
pub const fuzz_question_name_bytes_min: usize = 192;
/// The answers a long message of the fuzz generator holds (`fuzz/fuzz_generate.zig`): one whose
/// rdata runs past the name at the farthest offset a pointer names, and one at the end of the
/// message owned by a pointer to that name.
pub const fuzz_long_answers: u16 = 2;
/// The fewest octets a label other than the root takes in a name: its length octet and one octet
/// (RFC 1035 §3.1). A long question's labels never leave fewer for the next.
pub const label_wire_bytes_min: usize = 2;

/// An OPT option: a 16-bit code and a 16-bit length, then the data (RFC 6891 §6.1.2).
pub const opt_option_fixed_bytes: usize = 4;
pub const opt_option_length_offset: usize = 2;

/// The EDNS0 options cocuyo reads, by the code IANA assigned each: the name server's identifier
/// (RFC 5001 §2.3), the client subnet (RFC 7871 §6), the padding (RFC 7830 §3) and the extended
/// error (RFC 8914 §2). The state machine acts on the cookie alone; the rest are read for the
/// caller (docs/design.md §19 step 10).
pub const nsid_option_code: u16 = 3;
pub const client_subnet_option_code: u16 = 8;
pub const padding_option_code: u16 = 12;
pub const extended_error_option_code: u16 = 15;

/// The client subnet option's fixed part: the family and the two prefix lengths, before the
/// address (RFC 7871 §6), and where each sits.
pub const client_subnet_fixed_bytes: usize = 4;
pub const client_subnet_source_offset: usize = 2;
pub const client_subnet_scope_offset: usize = 3;

/// The two families RFC 7871 §6 defines a format for, by their IANA Address Family Number.
pub const client_subnet_family_ipv4: u16 = 1;
pub const client_subnet_family_ipv6: u16 = 2;

/// The extended error's fixed part: the info code, before the text (RFC 8914 §2).
pub const extended_error_fixed_bytes: usize = 2;

/// The bits of an octet, for the prefix arithmetic of RFC 7871 §6.
pub const bits_per_octet: usize = 8;

/// The COOKIE option's code (RFC 7873 §4), and the two lengths the option may have: a client
/// cookie alone, or a client cookie and a server cookie of 8 to 32 octets.
pub const cookie_option_code: u16 = 10;
pub const cookie_option_short_bytes: usize = 8;
pub const cookie_option_long_bytes_min: usize = 16;
pub const cookie_option_long_bytes_max: usize = 40;

/// The rcode's high eight bits sit above the header's four (RFC 6891 §6.1.3).
pub const extended_rcode_low_bits: u4 = 4;

/// The most segments a record layout has: NAPTR's fixed part, three strings and a name
/// (`rdata/rdata_layout.zig`).
pub const layout_segments_max: usize = 5;

/// The draws DNS-0x20 takes for one name. A draw that leaves every letter small is drawn again,
/// so that a mixed name carries a capital, and after this many the first letter is made one
/// (`name.mix_case`, docs/design.md §7). One draw leaves a name of L letters all small with chance
/// 2^-L, so the first letter is forced with chance 2^-4L: 1 in 16 for one letter, whose only case
/// with a capital that is, 1 in 256 for two, and 1 in 4096 or less from three on. Chosen, not
/// measured.
pub const case_draws_max: usize = 4;

/// QR: set in a response (RFC 1035 §4.1.1).
pub const flag_response: u16 = 0x8000;

/// OPCODE, four bits (RFC 1035 §4.1.1).
pub const opcode_mask: u16 = 0x7800;
pub const opcode_shift: u4 = 11;

/// The only opcode cocuyo sends or accepts: a standard query (RFC 1035 §4.1.1).
pub const opcode_query: u16 = 0;

/// AA: the answer is authoritative.
pub const flag_authoritative: u16 = 0x0400;

/// TC: the message was truncated, which is what sends a lookup to TCP (RFC 1035 §4.1.1).
pub const flag_truncated: u16 = 0x0200;

/// RD: recursion desired, which every query cocuyo builds sets, because a stub asks a recursive
/// server to do the walking (RFC 1035 §4.1.1).
pub const flag_recursion_desired: u16 = 0x0100;

/// RA: recursion available.
pub const flag_recursion_available: u16 = 0x0080;

/// RCODE, the low four bits (RFC 1035 §4.1.1).
pub const rcode_mask: u16 = 0x000f;

/// The response codes cocuyo reads. The rest are reported as a malformed message rather than
/// guessed at (RFC 1035 §4.1.1, RFC 6895 §2.3).
pub const Rcode = enum(u8) {
    no_error = 0,
    format_error = 1,
    server_failure = 2,
    name_error = 3,
    not_implemented = 4,
    refused = 5,
    /// The responder does not implement the EDNS version asked (RFC 6891 §6.1.3).
    bad_vers = 16,
    /// The server cookie was missing or wrong (RFC 7873 §8, the IANA entry).
    bad_cookie = 23,

    /// The code `bits` names, or null when cocuyo does not know it. A code cocuyo does not know is
    /// a malformed message to its caller rather than a code to guess the meaning of. The header
    /// holds four bits and an OPT record's TTL eight more above them (RFC 6891 §6.1.3), so a
    /// code is twelve bits wide.
    pub fn from_bits(bits: u16) ?Rcode {
        inline for (@typeInfo(Rcode).@"enum".fields) |field| {
            if (field.value == bits) return @enumFromInt(field.value);
        }
        return null;
    }
};

/// The two high bits of a length octet say what follows: `00` a label, `11` a pointer. `01` and
/// `10` are reserved and make a message malformed (RFC 1035 §4.1.4).
pub const label_kind_mask: u8 = 0xc0;
pub const label_kind_label: u8 = 0x00;
pub const label_kind_pointer: u8 = 0xc0;

/// The low fourteen bits of a pointer are the offset it points at (RFC 1035 §4.1.4).
pub const pointer_offset_mask: u16 = 0x3fff;

/// A pointer is two octets (RFC 1035 §4.1.4).
pub const pointer_bytes: usize = 2;

/// The longest `dns` variable a DoH GET carries (RFC 8484 §6): the largest query without the TCP
/// length prefix, 384 octets, in base64url without padding, four characters for three octets,
/// which is 512 (docs/design.md §22).
pub const dns_variable_bytes_max = std.base64.url_safe_no_pad.Encoder.calcSize(
    @import("core").constants.query_bytes_max - @import("core").constants.tcp_prefix_bytes,
);

comptime {
    const core = @import("core");
    // The header's fields must tile the header exactly, or a parser would read past one of them.
    if (header_arcount_offset + u16_bytes != core.constants.header_bytes) {
        @compileError("the header fields do not tile the header");
    }
    if (label_kind_label | label_kind_pointer != label_kind_mask) {
        @compileError("the label kinds do not cover the kind bits");
    }
    if (pointer_offset_mask | @as(u16, label_kind_mask) << octet_bits != 0xffff) {
        @compileError("a pointer's kind bits and offset bits do not cover its two octets");
    }
    // The record's fixed fields must tile its fixed part, or a walk would read past one of them.
    if (record_rdlength_offset + u16_bytes != core.constants.record_fixed_bytes) {
        @compileError("the record fields do not tile the fixed part");
    }
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
