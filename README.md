# zig-socks
A simple, non-allocating SOCKS 5/4/4a client library for Zig

*Tested against Zig 0.10.x and 0.9.1*
## Features
- [x] Protocol version 5
  - [x] Connect command
  - [ ] UDP Associate command
  - [x] Password authentication
  - [x] IPv4 address
  - [x] IPv6 address
  - [x] hostname address
- [x] Protocol version 4 and 4a
  - [x] Connect command
  - [ ] UDP Associate command
  - [x] IPv4 address
  - [x] hostname address
- [x] Remote DNS lookups

## Usage
```zig
const std = @import("std");
const ip = std.x.net.ip;
const IPv4 = std.x.os.IPv4;
const Socksv5 = @import("socks.zig").Socksv5;

pub fn main() !void {
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

// use the generic interface - should work with any std.io.Reader and std.io.Writer
try Socksv5.client(strm.reader(), strm.writer(), null, "www.google.com", 80);

// read/write to strm...
```
