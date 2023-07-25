/// zig-socks - A simple, non-allocating, generic SOCKS 5/4/4a client library in Zig.

// TODO: add UDP associate support
// auth generic blocker: the opaque interface vtable pattern doesn't allow 'anytype' args,
// unless they are comptime known.
const std = @import("std");
const mem = std.mem;
const io = std.io;
const os = std.os;
const net = std.net;

/// Socksv5 is a SOCKS 5 client
pub const Socksv5 = struct {
    pub const VERSION = 5;

    pub const Auth = enum(u8) {
        pub const VERSION = 1;

        MethodNone = 0x00,
        MethodGssApi = 0x01,
        MethodUserPassword = 0x02,
        MethodNotAcceptable = 0xff,
        _, 
    };

    pub const Cmd = enum(u8) {
        Connect = 0x01,
        Bind = 0x02,
        UdpAssociate = 0x03,
        _,
    };

    pub const Addr = enum(u8) {
        TypeIPv4 = 0x01,
        TypeFQDN = 0x03,
        TypeIPv6 = 0x05,
        _,
    };

    pub const Reply = enum(u8) {
        Success = 0x00,
        GeneralFailure = 0x01,
        ConnectionNotAllowed = 0x02,
        NetworkUnreachable = 0x03,
        HostUnreachable = 0x04,
        ConnectionRefused = 0x05,
        TtlExpired = 0x06,
        CmdNotSupported = 0x07,
        AddrTypeNotSupported = 0x08,
        _,
    };

    pub const AuthInfo = struct {
        user: []const u8,
        password: []const u8,
    };

    /// Connect to the specified `host` and `port` via the specified SOCKS 5 `proxy`.
    pub fn connect(proxy: net.Address, auth: ?AuthInfo, host: []const u8, port: u16) !net.Stream {
        const stream = try net.tcpConnectToAddress(proxy);
        try Socksv5.client(stream.reader(), stream.writer(), auth, host, port);

        return stream;
    }

    /// Connect to the specified `destination` via the specified SOCKS 5 `proxy`
    pub fn connectAddress(proxy: net.Address, auth: ?AuthInfo, destination: net.Address) !net.Stream {
        const stream = try net.tcpConnectToAddress(proxy); 
        try Socksv5.clientAddress(stream.reader(), stream.writer(), auth, destination);

        return stream;
    }

    /// Connect an existing `reader` and `writer` to the specified `host` and
    /// `port` via SOCKS 5.
    pub fn client(reader: anytype, writer: anytype, auth: ?AuthInfo, host: []const u8, port: u16) !void {
        if (net.Ip4Address.parse(host, port)) |dst| {
            return Socksv5.clientAddress(reader, writer, auth, dst);
        } else |_| if (net.Ip6Address.parse(host, port)) |dst| {
                return Socksv5.clientAddress(reader, writer, auth, dst);
        } else |_| {
            try negotiate_auth(reader, writer, auth);

            var buf: [7 + 255]u8 = undefined;
            buf[0] = VERSION;
            buf[1] = @intFromEnum(Cmd.Connect);
            buf[2] = 0;
            buf[3] = @intFromEnum(Addr.TypeFQDN);
            if (host.len > 255)
                return error.NameTooLong;
            buf[4] = @truncate(host.len);
            mem.copy(u8, buf[5..5+host.len], host);
            mem.writeIntSliceBig(u16, buf[5+host.len..5+host.len+2], port);

            try writer.writeAll(buf[0..7+host.len]);
            try read_response(reader);
        }
    }

    /// Connect an existing `reader` and `writer` to the specified `destination` via SOCKS 5.
    pub fn clientAddress(reader: anytype, writer: anytype, auth: ?AuthInfo, destination: net.Address) !void {
        try negotiate_auth(reader, writer, auth);

        var buf: [6 + 16]u8 = undefined;
        buf[0] = VERSION;
        buf[1] = @intFromEnum(Cmd.Connect);
        buf[2] = 0;
        switch (destination.any.family) {
            os.AF.INET => {
                buf[3] = @intFromEnum(Addr.TypeIPv4);
                const octets: *const [4]u8 = @ptrCast(&destination.in.sa.addr);
                mem.copy(u8, buf[4..8], octets);
                mem.writeIntSliceBig(u16, buf[8..10], destination.getPort());

                try writer.writeAll(buf[0..10]);
            },
            os.AF.INET6 => {
                buf[3] = @intFromEnum(Addr.TypeIPv6);
                const octets: *const [16]u8 = @ptrCast(&destination.in6.sa.addr);
                mem.copy(u8, buf[4..20], octets);
                mem.writeIntSliceBig(u16, buf[20..22], destination.getPort());

                try writer.writeAll(buf[0..22]);
            },
            else => return error.BadAddress,
        }
        try read_response(reader);
    }

    fn negotiate_auth(reader: anytype, writer: anytype, auth: ?AuthInfo) !void {
        var buf: [1024]u8 = undefined;

        buf[0] = VERSION;
        if (auth) |_| {
            buf[1] = 2;
            buf[2] = @intFromEnum(Auth.MethodNone);
            buf[3] = @intFromEnum(Auth.MethodUserPassword);

            try writer.writeAll(buf[0..4]);
        } else {
            buf[1] = 1;
            buf[2] = @intFromEnum(Auth.MethodNone);

            try writer.writeAll(buf[0..3]);
        }

        try reader.readNoEof(buf[0..2]);
        if (buf[0] != VERSION) {
            return error.BadVersion;
        }
        switch (@as(Auth, @enumFromInt(buf[1]))) {
            .MethodNone => {}, // server says no auth required, so continue.
            .MethodGssApi => return error.MethodNotAcceptable, // not yet
            .MethodNotAcceptable => return error.MethodNotAcceptable, 
            .MethodUserPassword => {
                if (auth) |a| {
                    if (a.user.len > 255 or a.password.len > 255) {
                        return error.ParamTooLarge;
                    }

                    buf[0] = Auth.VERSION;
                    buf[1] = @truncate(a.user.len);
                    mem.copy(u8, buf[2..], a.user);
                    var idx: usize = 2 + a.user.len;
                    buf[idx] = @truncate(a.password.len);
                    idx += 1;
                    mem.copy(u8, buf[idx..], a.password);
                    idx += a.password.len;
                    try writer.writeAll(buf[0..idx]);

                    try reader.readNoEof(buf[0..2]);
                    if (buf[1] != 0) {
                        return error.AuthFailure;
                    }
                } else
                    return error.UnexpectedMethod;
            },
            _ => return error.UnexpectedMethod,
        }
    }

    fn read_response(reader: anytype) !void {
        var buf: [512]u8 = undefined;

        try reader.readNoEof(buf[0..4]);
        if (buf[0] != VERSION) {
            return error.BadVersion;
        }
        switch (@as(Reply, @enumFromInt(buf[1]))) {
            .Success => {},
            .GeneralFailure => return error.GeneralFailure,
            .ConnectionNotAllowed => return error.ConnectionNotAllowed,
            .NetworkUnreachable => return error.NetworkUnreachable,
            .HostUnreachable => return error.HostUnreachable,
            .ConnectionRefused => return error.ConnectionRefused,
            .TtlExpired => return error.TtlExpired,
            .CmdNotSupported => return error.CmdNotSupported,
            .AddrTypeNotSupported => return error.AddrTypeNotSupported,
            _ => return error.UnexpectedReply,
        }
        switch (@as(Addr, @enumFromInt(buf[3]))) {
            .TypeIPv4 => try reader.readNoEof(buf[0..4+2]),
            .TypeIPv6 => try reader.readNoEof(buf[0..16+2]),
            .TypeFQDN => {
                const n = try reader.readByte();
                try reader.readNoEof(buf[0..n+2]);
            },
            _ => return error.InvalidAddress,
        }
    }
};

/// Socksv4 is a SOCKS 4/4a client.
pub const Socksv4 = struct {
    pub const VERSION = 4;

    pub const Cmd = enum(u8) {
        Connect = 0x01,
        Bind = 0x02,
        _,
    };

    pub const Reply = enum(u8) {
        RequestGranted = 0x5a,
        RequestFailure = 0x5b,
        IdentdHostFailure = 0x5c,
        IdentdUserFailure = 0x5d,
        _,
    };

    pub const Options = struct {
        user: []const u8 = "unknown",  // don't "leak" the client's username by default
    };

    /// Connect to the specified `host` and `port` via the specified SOCKS 4 `proxy`.
    /// If a hostname is given, SOCKS 4a will be used.
    pub fn connect(proxy: net.Address, options: Options, host: []const u8, port: u16) !net.Stream {
        const stream = try net.tcpConnectToAddress(proxy);
        try Socksv4.client(stream.reader(), stream.writer(), options, host, port);

        return stream;
    }

    /// Connect to the specified `destination` via the specified SOCKS 4 `proxy`
    pub fn connectAddress(proxy: net.Address, options: Options, destination: net.Address) !net.Stream {
        const stream = try net.tcpConnectToAddress(proxy);
        try Socksv4.clientAddress(stream.reader(), stream.writer(), options, destination);

        return stream;
    }

    /// Connect an existing `reader` and `writer` to the specified `host` and
    /// `port` via SOCKS 4.  If a hostname is given, SOCKS 4a will be used.
    pub fn client(reader: anytype, writer: anytype, options: Options, host: []const u8, port: u16) !void {
        if (net.Ip4Address.parse(host, port)) |dst| {
            return Socksv4.clientAddress(reader, writer, .{}, dst);
        } else |_| if (net.Ip6Address.parse(host, port)) |_| {
            return error.IPv6Unsupported;
        } else |_| {
            if (options.user.len > 128 or host.len > 256)
                return error.ParamTooLarge;

            var buf: [512]u8 = undefined;
            var idx: usize = 0;

            buf[0] = VERSION;
            buf[1] = @intFromEnum(Cmd.Connect);
            mem.writeIntSliceBig(u16, buf[2..4], port);
            mem.copy(u8, buf[4..8], &[_]u8{0, 0, 0, 1}); // SOCKS 4a IP marker
            idx = 8;
            mem.copy(u8, buf[idx..], options.user);
            idx += options.user.len;
            buf[idx] = 0;
            idx += 1;
            mem.copy(u8, buf[idx..], host);
            idx += host.len;
            buf[idx] = 0;
            idx += 1;

            try writer.writeAll(buf[0..idx]);
            try read_response(reader);
        }
    }

    /// Connect an existing `reader` and `writer` to the specified `destination` via SOCKS 4.
    pub fn clientAddress(reader: anytype, writer: anytype, options: Options, destination: net.Address) !void {
        if (options.user.len > 128)
            return error.ParamTooLarge;

        var buf: [256]u8 = undefined;
        buf[0] = VERSION;
        buf[1] = @intFromEnum(Cmd.Connect);
        switch (destination.any.family) {
            os.AF.INET => {
                mem.writeIntSliceBig(u16, buf[2..4], destination.getPort());
                const octets: *const [4]u8 = @ptrCast(&destination.in.sa.addr);
                mem.copy(u8, buf[4..8], octets);
            },
            os.AF.INET6 => return error.IPv6Unsupported,
            else => return error.Unsupported,
        }
        var idx: usize = 8;
        mem.copy(u8, buf[idx..], options.user);
        idx += options.user.len;
        buf[idx] = 0;
        idx += 1;

        try writer.writeAll(buf[0..idx]);
        try read_response(reader);
    }

    fn read_response(reader: anytype) !void {
        var buf: [8]u8 = undefined;

        try reader.readNoEof(&buf);
        if (buf[0] != 0)
            return error.UnexpectedReply;

        switch (@as(Reply, @enumFromInt(buf[1]))) {
            .RequestGranted => {},
            .RequestFailure => return error.RequestFailure,
            .IdentdHostFailure => return error.IdentdFailure,
            .IdentdUserFailure => return error.IdentdFailure,
            _ => return error.UnexpectedReply,
        }
    }
};

test "mock SOCKS 5 server" {
    var client_bytes: [4096]u8 = undefined;
    var client_stream = io.fixedBufferStream(&client_bytes);

    // mock server success response
    var server_bytes = [_]u8{
        // 1st packet
        0x05, 0x00,
        // 2nd packet
        0x05, 0x00, 0x00, 0x01, 127, 0, 0, 1, 0xbb, 0xbb
    };
    var server_stream = io.fixedBufferStream(&server_bytes);

    const dst = net.Address.initIp4([_]u8{127, 0, 0, 1}, 8443);
    try Socksv5.clientAddress(server_stream.reader(), client_stream.writer(), null, dst);

    const expected = [_]u8{
        // 1st packet: method none auth
        Socksv5.VERSION, 0x01, 0,
        // 2nd packet - vers, method, rsrv, atyp, IPv4, port
        Socksv5.VERSION, @intFromEnum(Socksv5.Cmd.Connect), 0x00, 0x01, 127, 0, 0, 1, 0x20, 0xfb
    };
    try std.testing.expectEqualStrings(client_stream.getWritten(), &expected);

    // test user/password authentication
    client_stream.reset();

    // mock server success response
    var server_bytes2 = [_]u8{
        // 1st packet: method auth password
        0x05, @intFromEnum(Socksv5.Auth.MethodUserPassword),
        // 2nd packet: indicate auth success
        0x05, 0x00,
        // 3rd packet
        0x05, 0x00, 0x00, 0x01, 127, 0, 0, 1, 0xbb, 0xbb
    };
    var server_stream2 = io.fixedBufferStream(&server_bytes2);

    const ai = Socksv5.AuthInfo{
        .user = "a",
        .password = "xyz",
    };
    try Socksv5.clientAddress(server_stream2.reader(), client_stream.writer(), ai, dst);

    const expected2 = [_]u8{
        // 1st packet: method userpassword auth 
        Socksv5.VERSION, 0x02, @intFromEnum(Socksv5.Auth.MethodNone), @intFromEnum(Socksv5.Auth.MethodUserPassword),
        // 2nd packet: auth info
        Socksv5.Auth.VERSION, 0x01, 'a', 0x03, 'x', 'y', 'z',
        // 3rd packet - vers, method, rsrv, atyp, IPv4, port
        Socksv5.VERSION, @intFromEnum(Socksv5.Cmd.Connect), 0x00, 0x01, 127, 0, 0, 1, 0x20, 0xfb
    };
    try std.testing.expectEqualStrings(client_stream.getWritten(), &expected2);
}

test "mock SOCKS 4 server" {
    var client_bytes: [4096]u8 = undefined;
    var client_stream = io.fixedBufferStream(&client_bytes);

    // mock server success response
    var server_bytes = [_]u8{
        0, @intFromEnum(Socksv4.Reply.RequestGranted), 0, 0, 0, 0, 0, 0
    };
    var server_stream = io.fixedBufferStream(&server_bytes);

    const options = Socksv4.Options {
        .user = "root",
    };
    const dst = net.Address.initIp4([_]u8{127, 0, 0, 1}, 8443);
    try Socksv4.clientAddress(server_stream.reader(), client_stream.writer(), options, dst);

    const expected = [_]u8{
        Socksv4.VERSION,
        @intFromEnum(Socksv4.Cmd.Connect),
        0x20, 0xfb,  // port
        127, 0, 0, 1,
        'r', 'o', 'o', 't', 0x00
    };
    try std.testing.expectEqualStrings(client_stream.getWritten(), &expected);
}

