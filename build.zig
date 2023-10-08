const std = @import("std");

pub fn build(b: *std.build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    _ = b.addModule("zig-socks", .{
        .source_file = .{ .path = "socks.zig" },
        .dependencies = &[_]std.Build.ModuleDependency{},
    });

    const lib = b.addStaticLibrary(.{
        .name = "zig-socks",
        .root_source_file = .{ .path = "socks.zig" },
        .target = target,
        .optimize = optimize,
    });
    b.installArtifact(lib);

    const socks_tests = b.addTest(.{
        .root_source_file = .{ .path = "socks.zig" },
        .target = target,
        .optimize = optimize,
    });
    const run_socks_tests = b.addRunArtifact(socks_tests);

    const test_step = b.step("test", "Run library tests");
    test_step.dependOn(&run_socks_tests.step);
}
