const std = @import("std");

pub const pkg = std.build.Pkg{
    .name = "zig-socks",
    .source = .{ .path = "socks.zig" },
};

pub fn build(b: *std.build.Builder) void {
    const mode = b.standardReleaseOptions();

    const lib = b.addStaticLibrary("zig-socks", "socks.zig");
    lib.setBuildMode(mode);
    lib.install();

    const main_tests = b.addTest("socks.zig");
    main_tests.setBuildMode(mode);

    const test_step = b.step("test", "Run library tests");
    test_step.dependOn(&main_tests.step);
}
