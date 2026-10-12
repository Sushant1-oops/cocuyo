//! The contexts of the engine's encrypted transports (docs/design.md §24, the context a session
//! starts from; §16 decision 39): what every DoT session, every DoQ connection and every DoH
//! channel starts from. The engine has none of its own. Each is null from `init` until the consumer
//! hands one over, with `use_tls`, `use_quic` or `use_doh`, and a lookup started while the
//! transport its configuration speaks has no context stops the program: forgetting the call is a
//! programmer error.
//!
//! This is the one file that reads the three contexts. A session is handed its context from here,
//! after an assertion that one was set, so none starts from a context nobody named.
//!
//! Free functions over the engine, split out of `io.zig` so each is scored on its own.
const std = @import("std");
const assert = std.debug.assert;

/// Whether the transport the engine's configuration speaks has its context: DoT's for a TLS
/// configuration, DoQ's for a QUIC one, DoH's for an HTTPS one. A configuration's servers are all
/// spoken to one way (docs/design.md §22, §23), so one context is read, and the context of
/// another transport counts for nothing. Plain DNS starts no session, and needs none.
pub fn held(self: anytype) bool {
    return switch (self.config.transport()) {
        .cleartext => true,
        .tls => self.tls_context != null,
        .quic => self.quic.context != null,
        .https => self.doh.context != null,
    };
}

/// What a TLS session starts from (docs/design.md §21, the session interface). `start` refused
/// the lookup of an engine that holds none, so a null here is the engine's own error.
pub fn of_tls(self: anytype) *@TypeOf(self.*).Tls.Context {
    assert(self.config.uses_tls());
    assert(self.tls_context != null);
    return &self.tls_context.?;
}

/// What a QUIC connection starts from (docs/design.md §24, the request interface), as `of_tls`
/// says for TLS.
pub fn of_quic(self: anytype) *@TypeOf(self.*).Quic.Context {
    assert(self.config.uses_quic());
    assert(self.quic.context != null);
    return &self.quic.context.?;
}

/// What a channel starts from (docs/design.md §24, DoH over colibri's client), as `of_tls` says
/// for TLS.
pub fn of_doh(self: anytype) *@TypeOf(self.*).Doh.Context {
    assert(self.config.uses_https());
    assert(self.doh.context != null);
    return &self.doh.context.?;
}
