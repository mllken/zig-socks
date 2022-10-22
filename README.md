# zig-socks
A simple, non-allocating SOCKS 5/4/4a client library for Zig

*Tested against Zig 0.10.x and 0.9.1*
## Usage
```zig
const Socksv5 = @import("socks.zig").Socksv5;
const ip = std.x.net.ip;
const IPv4 = std.x.os.IPv4;

pub fn main() void {
    const proxy = ip.Address.initIPv4(IPv4.localhost, 1080);
    const cli = try Socksv5.connect(proxy, null, "www.google.com", 80);
    defer cli.deinit();

    // read/write to cli...
}
```
or
```zig
var gpa = GeneralPurposeAllocator(.{})();
const allocator = gpa.allocator();

const strm = try std.net.tcpConnectToHost(allocator, "localhost", 1080);
defer strm.close();

// use the generic interface
try Socksv5.client(cli.reader(), cli.writer(), null, "www.google.com", 80);
```
