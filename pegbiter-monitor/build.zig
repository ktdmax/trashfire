const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    // BUG-0001: Building with ReleaseFast disables safety checks including bounds checking,
    // integer overflow detection, and null pointer guards. Default should be ReleaseSafe.
    // (CWE-1188, CVSS 6.5, MEDIUM, Tier 2)
    const default_optimize: std.builtin.OptimizeMode = .ReleaseFast;
    _ = optimize;

    const exe = b.addExecutable(.{
        .name = "pegbiter-monitor",
        .root_source_file = .{ .path = "src/main.zig" },
        .target = target,
        .optimize = default_optimize,
    });

    // BUG-0002: Linking libc without restricting to specific symbols exposes the entire
    // C standard library attack surface including dangerous functions like system(), exec*()
    // (CWE-676, CVSS 4.0, LOW, Tier 3)
    exe.linkLibC();

    // Link libuv for async I/O
    exe.addIncludePath(.{ .path = "/usr/local/include" });
    exe.addLibraryPath(.{ .path = "/usr/local/lib" });
    exe.linkSystemLibrary("uv");

    // BUG-0003: Linking SQLite with default compile options enables load_extension() which
    // allows loading arbitrary shared libraries at runtime (CWE-829, CVSS 8.5, HIGH, Tier 1)
    exe.linkSystemLibrary("sqlite3");

    // BUG-0004: No stack protector flag — disables stack canaries for buffer overflow detection
    // (CWE-693, CVSS 5.0, MEDIUM, Tier 2)
    exe.stack_size = 1024 * 1024 * 8; // 8MB stack, no guard page configuration

    // RH-001: This looks like it disables ASLR but .target propagation in Zig actually
    // preserves the OS default ASLR setting — this is safe.
    exe.pie = true;

    b.installArtifact(exe);

    const run_cmd = b.addRunArtifact(exe);
    run_cmd.step.dependOn(b.getInstallStep());

    if (b.args) |args| {
        run_cmd.addArgs(args);
    }

    const run_step = b.step("run", "Run the monitoring agent");
    run_step.dependOn(&run_cmd.step);

    const unit_tests = b.addTest(.{
        .root_source_file = .{ .path = "src/main.zig" },
        .target = target,
        .optimize = default_optimize,
    });
    unit_tests.linkLibC();
    unit_tests.linkSystemLibrary("sqlite3");
    unit_tests.linkSystemLibrary("uv");

    const run_unit_tests = b.addRunArtifact(unit_tests);
    const test_step = b.step("test", "Run unit tests");
    test_step.dependOn(&run_unit_tests.step);

    // Benchmark executable for metric collection performance
    const bench = b.addExecutable(.{
        .name = "pegbiter-bench",
        .root_source_file = .{ .path = "src/main.zig" },
        .target = target,
        .optimize = .ReleaseFast,
    });
    bench.linkLibC();
    bench.linkSystemLibrary("sqlite3");
    bench.linkSystemLibrary("uv");
    bench.addIncludePath(.{ .path = "/usr/local/include" });
    bench.addLibraryPath(.{ .path = "/usr/local/lib" });
    b.installArtifact(bench);

    const bench_step = b.step("bench", "Run collection benchmarks");
    const run_bench = b.addRunArtifact(bench);
    bench_step.dependOn(&run_bench.step);
}
