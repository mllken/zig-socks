/// zig-socks - A simple, non-allocating, generic SOCKS 5/4/4a client library in Zig.

// TODO: add UDP associate support
// auth generic blocker: the opaque interface vtable pattern doesn't allow 'anytype' args,
// unless they are comptime known.
const std = @import("std");
const mem = std.mem;
const io = std.io;
const ip = std.x.net.ip;
const tcp = std.x.net.tcp;
const IPv4 = std.x.os.IPv4;
const IPv6 = std.x.os.IPv6;
const testing = std.testing;

/// Socksv5 is a SOCKS 5 client
pub const Socksv5 = struct {
    pub const VERSION = 5;

    pub const Auth = enum(u8) {
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
    pub fn connect(proxy: ip.Address, auth: ?AuthInfo, host: []const u8, port: u16) !tcp.Client {
        const tcpClient = try tcp.Client.init(.ip, .{ .close_on_exec = true });
        errdefer tcpClient.deinit();

        try tcpClient.connect(proxy);
        try Socksv5.client(tcpClient.reader(0), tcpClient.writer(0), auth, host, port);

        return tcpClient;
    }

    /// Connect to the specified `destination` via the specified SOCKS 5 `proxy`
    pub fn connectAddress(proxy: ip.Address, auth: ?AuthInfo, destination: ip.Address) !tcp.Client {
        const tcpClient = try tcp.Client.init(.ip, .{ .close_on_exec = true });
        errdefer tcpClient.deinit();

        try tcpClient.connect(proxy);
        try Socksv5.clientAddress(tcpClient.reader(0), tcpClient.writer(0), auth, destination);

        return tcpClient;
    }

    /// Connect an existing `reader` and `writer` to the specified `host` and
    /// `port` via SOCKS 5.
    pub fn client(reader: anytype, writer: anytype, auth: ?AuthInfo, host: []const u8, port: u16) !void {
        if (IPv4.parse(host)) |ip4| {
            const dst = ip.Address.initIPv4(ip4, port);
            return Socksv5.clientAddress(reader, writer, auth, dst);
        } else |_| if (IPv6.parse(host)) |ip6| {
                const dst = ip.Address.initIPv6(ip6, port);
                return Socksv5.clientAddress(reader, writer, auth, dst);
        } else |_| {
            try negotiate_auth(reader, writer, auth);

            var buf: [7 + 255]u8 = undefined;
            buf[0] = VERSION;
            buf[1] = @enumToInt(Cmd.Connect);
            buf[2] = 0;
            buf[3] = @enumToInt(Addr.TypeFQDN);
            if (host.len > 255)
                return error.NameTooLong;
            buf[4] = @truncate(u8, host.len);
            mem.copy(u8, buf[5..5+host.len], host);
            mem.writeIntSliceBig(u16, buf[5+host.len..5+host.len+2], port);

            try writer.writeAll(buf[0..7+host.len]);
            try read_response(reader);
        }
    }

    /// Connect an existing `reader` and `writer` to the specified `destination` via SOCKS 5.
    pub fn clientAddress(reader: anytype, writer: anytype, auth: ?AuthInfo, destination: ip.Address) !void {
        try negotiate_auth(reader, writer, auth);

        var buf: [6 + 16]u8 = undefined;
        buf[0] = VERSION;
        buf[1] = @enumToInt(Cmd.Connect);
        buf[2] = 0;
        switch (destination) {
            .ipv4 => |ip4| {
                buf[3] = @enumToInt(Addr.TypeIPv4);
                mem.copy(u8, buf[4..8], &ip4.host.octets);
                mem.writeIntSliceBig(u16, buf[8..10], ip4.port);

                try writer.writeAll(buf[0..10]);
            },
            .ipv6 => |ip6| {
                buf[3] = @enumToInt(Addr.TypeIPv6);
                mem.copy(u8, buf[4..20], &ip6.host.octets);
                mem.writeIntSliceBig(u16, buf[20..22], ip6.port);

                try writer.writeAll(buf[0..22]);
            }
        }
        try read_response(reader);
    }

    fn negotiate_auth(reader: anytype, writer: anytype, auth: ?AuthInfo) !void {
        var buf: [1024]u8 = undefined;

        buf[0] = VERSION;
        if (auth) |_| {
            buf[1] = 2;
            buf[2] = @enumToInt(Auth.MethodNone);
            buf[3] = @enumToInt(Auth.MethodUserPassword);

            try writer.writeAll(buf[0..4]);
        } else {
            buf[1] = 1;
            buf[2] = @enumToInt(Auth.MethodNone);

            try writer.writeAll(buf[0..3]);
        }

        try reader.readNoEof(buf[0..2]);
        if (buf[0] != VERSION) {
            return error.BadVersion;
        }
        switch (@intToEnum(Auth, buf[1])) {
            .MethodNone => {}, // server says no auth required, so continue.
            .MethodGssApi => return error.MethodNotAcceptable, // not yet
            .MethodNotAcceptable => return error.MethodNotAcceptable, 
            .MethodUserPassword => {
                if (auth) |a| {
                    if (a.user.len > @sizeOf(u8) or a.password.len > @sizeOf(u8)) {
                        return error.ParamTooLarge;
                    }

                    buf[0] = @truncate(u8, a.user.len);
                    mem.copy(u8, buf[1..], a.user);
                    var idx: usize = 1 + a.user.len;
                    buf[idx] = @truncate(u8, a.password.len);
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
        switch (@intToEnum(Reply, buf[1])) {
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
        switch (@intToEnum(Addr, buf[3])) {
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
    pub fn connect(proxy: ip.Address, options: Options, host: []const u8, port: u16) !tcp.Client {
        const tcpClient = try tcp.Client.init(.ip, .{ .close_on_exec = true });
        errdefer tcpClient.deinit();

        try tcpClient.connect(proxy);
        try Socksv4.client(tcpClient.reader(0), tcpClient.writer(0), options, host, port);

        return tcpClient;
    }

    /// Connect to the specified `destination` via the specified SOCKS 4 `proxy`
    pub fn connectAddress(proxy: ip.Address, options: Options, destination: ip.Address) !tcp.Client {
        const tcpClient = try tcp.Client.init(.ip, .{ .close_on_exec = true });
        errdefer tcpClient.deinit();

        try tcpClient.connect(proxy);
        try Socksv4.clientAddress(tcpClient.reader(0), tcpClient.writer(0), options, destination);

        return tcpClient;
    }

    /// Connect an existing `reader` and `writer` to the specified `host` and
    /// `port` via SOCKS 4.  If a hostname is given, SOCKS 4a will be used.
    pub fn client(reader: anytype, writer: anytype, options: Options, host: []const u8, port: u16) !void {
        if (IPv4.parse(host)) |ip4| {
            const dst = ip.Address.initIPv4(ip4, port);
            return Socksv4.clientAddress(reader, writer, .{}, dst);
        } else |_| if (IPv6.parse(host)) |_| {
            return error.IPv6Unsupported;
        } else |_| {
            if (options.user.len > 128 or host.len > 256)
                return error.ParamTooLarge;

            var buf: [512]u8 = undefined;
            var idx: usize = 0;

            buf[0] = VERSION;
            buf[1] = @enumToInt(Cmd.Connect);
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
    pub fn clientAddress(reader: anytype, writer: anytype, options: Options, destination: ip.Address) !void {
        if (options.user.len > 128)
            return error.ParamTooLarge;

        var buf: [256]u8 = undefined;
        buf[0] = VERSION;
        buf[1] = @enumToInt(Cmd.Connect);
        switch (destination) {
            .ipv4 => |ip4| {
                mem.writeIntSliceBig(u16, buf[2..4], ip4.port);
                mem.copy(u8, buf[4..8], &ip4.host.octets);
            },
            .ipv6 => |_| {
                return error.IPv6Unsupported;
            }
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

        switch (@intToEnum(Reply, buf[1])) {
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

    const dst = ip.Address.initIPv4(IPv4.localhost, 8443);
    try Socksv5.clientAddress(server_stream.reader(), client_stream.writer(), null, dst);

    const expected = [_]u8{
        // 1st packet: method none auth
        Socksv5.VERSION, 0x01, 0,
        // 2nd packet
        Socksv5.VERSION, 
        @enumToInt(Socksv5.Cmd.Connect),
        0x00, 0x01, 127, 0, 0, 1, 0x20, 0xfb // rsrv, atyp, IPv4, port
    };
    try std.testing.expectEqualStrings(client_stream.getWritten(), &expected);
}

test "mock SOCKS 4 server" {
    var client_bytes: [4096]u8 = undefined;
    var client_stream = io.fixedBufferStream(&client_bytes);

    // mock server success response
    var server_bytes = [_]u8{
        0, @enumToInt(Socksv4.Reply.RequestGranted), 0, 0, 0, 0, 0, 0
    };
    var server_stream = io.fixedBufferStream(&server_bytes);

    const options = Socksv4.Options {
        .user = "root",
    };
    const dst = ip.Address.initIPv4(IPv4.localhost, 8443);
    try Socksv4.clientAddress(server_stream.reader(), client_stream.writer(), options, dst);

    const expected = [_]u8{
        Socksv4.VERSION,
        @enumToInt(Socksv4.Cmd.Connect),
        0x20, 0xfb,  // port
        127, 0, 0, 1,
        'r', 'o', 'o', 't', 0x00
    };
    try std.testing.expectEqualStrings(client_stream.getWritten(), &expected);
}

