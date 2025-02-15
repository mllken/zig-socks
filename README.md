# zig-socks
A simple, non-allocating SOCKS 5/4/4a client library for Zig

*Tested against Zig 0.13.x*

## Features
- [x] Protocol version 5
  - [x] CONNECT command
  - [ ] BIND command
  - [ ] UDP ASSOCIATE command
  - [x] Password authentication
  - [x] IPv4 address
  - [x] IPv6 address
  - [x] hostname address
- [x] Protocol version 4 and 4a
  - [x] CONNECT command
  - [ ] BIND command
  - [x] IPv4 address
  - [x] hostname address
- [x] Remote DNS lookups

## Usage
```zig
const std = @import("std");
const Socksv5 = @import("socks.zig").Socksv5;

pub fn main() !void {
    const proxy = try std.net.Address.parseIp4("127.0.0.1", 1080);
    const stream = try Socksv5.connect(proxy, null, "www.google.com", 80);
    defer stream.close();

    // read/write to stream...
}
```
or
```zig
var gpa = GeneralPurposeAllocator(.{})();
const allocator = gpa.allocator();

const stream = try std.net.tcpConnectToHost(allocator, "localhost", 1080);
defer stream.close();

// use the generic interface - should work with any std.io.Reader and std.io.Writer
try Socksv5.client(stream.reader(), stream.writer(), null, "www.google.com", 80);

// read/write to stream...
```
