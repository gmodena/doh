const std = @import("std");

// Although this function looks imperative, note that its job is to
// declaratively construct a build graph that will be executed by an external
// runner.
pub fn build(b: *std.Build) void {
    // Standard target options allows the person running `zig build` to choose
    // what target to build for. Here we do not override the defaults, which
    // means any target is allowed, and the default is native. Other options
    // for restricting supported target set are available.
    const target = b.standardTargetOptions(.{});

    // Standard optimization options allow the person running `zig build` to select
    // between Debug, ReleaseSafe, ReleaseFast, and ReleaseSmall. Here we do not
    // set a preferred release mode, allowing the user to decide how to optimize.
    const optimize = b.standardOptimizeOption(.{});

    // Create error module first (public module)
    const error_module = b.addModule("error", .{
        .root_source_file = b.path("src/error.zig"),
        .target = target,
        .optimize = optimize,
    });

    // Create the main executable module
    const exe_module = b.createModule(.{
        .root_source_file = b.path("src/main.zig"),
        .target = target,
        .optimize = optimize,
    });
    exe_module.addImport("error", error_module);
    exe_module.linkSystemLibrary("c", .{});
    exe_module.linkSystemLibrary("wolfssl", .{});
    exe_module.linkSystemLibrary("nghttp2", .{});

    const exe = b.addExecutable(.{
        .name = "doh",
        .root_module = exe_module,
    });

    b.installArtifact(exe);

    // This *creates* a Run step in the build graph, to be executed when another
    // step is evaluated that depends on it. The next line below will establish
    // such a dependency.
    const run_cmd = b.addRunArtifact(exe);

    // By making the run step depend on the install step, it will be run from the
    // installation directory rather than directly from within the cache directory.
    // This is not necessary, however, if the application depends on other installed
    // files, this ensures they will be present and in the expected location.
    run_cmd.step.dependOn(b.getInstallStep());

    // This allows the user to pass arguments to the application in the build
    // command itself, like this: `zig build run -- arg1 arg2 etc`
    if (b.args) |args| {
        run_cmd.addArgs(args);
    }

    // This creates a build step. It will be visible in the `zig build --help` menu,
    // and can be selected like this: `zig build run`
    // This will evaluate the `run` step rather than the default, which is "install".
    const run_step = b.step("run", "Run the app");
    run_step.dependOn(&run_cmd.step);

    // Creates a step for unit testing. This only builds the test executable
    // but does not run it.
    const lib_unit_tests_module = b.createModule(.{
        .root_source_file = b.path("src/main.zig"),
        .target = target,
        .optimize = optimize,
    });
    lib_unit_tests_module.addImport("error", error_module);
    lib_unit_tests_module.linkSystemLibrary("c", .{});
    lib_unit_tests_module.linkSystemLibrary("wolfssl", .{});
    lib_unit_tests_module.linkSystemLibrary("nghttp2", .{});

    const lib_unit_tests = b.addTest(.{
        .root_module = lib_unit_tests_module,
    });

    const run_lib_unit_tests = b.addRunArtifact(lib_unit_tests);

    // Create a module for the server code that tests can import
    const server_module = b.addModule("server", .{
        .root_source_file = b.path("src/server.zig"),
        .target = target,
        .optimize = optimize,
    });
    server_module.addImport("error", error_module);

    // Add comprehensive test suite
    const doh_tests_module = b.createModule(.{
        .root_source_file = b.path("tests/test_suite.zig"),
        .target = target,
        .optimize = optimize,
    });
    doh_tests_module.addImport("server", server_module);
    doh_tests_module.addImport("error", error_module);
    doh_tests_module.linkSystemLibrary("c", .{});
    doh_tests_module.linkSystemLibrary("wolfssl", .{});
    doh_tests_module.linkSystemLibrary("nghttp2", .{});

    const doh_tests = b.addTest(.{
        .root_module = doh_tests_module,
    });

    const run_doh_tests = b.addRunArtifact(doh_tests);

    // Add individual test modules
    const unit_tests_module = b.createModule(.{
        .root_source_file = b.path("tests/unit_tests.zig"),
        .target = target,
        .optimize = optimize,
    });
    unit_tests_module.addImport("server", server_module);
    unit_tests_module.linkSystemLibrary("c", .{});
    unit_tests_module.linkSystemLibrary("wolfssl", .{});
    unit_tests_module.linkSystemLibrary("nghttp2", .{});

    const unit_tests = b.addTest(.{
        .root_module = unit_tests_module,
    });
    const run_unit_tests = b.addRunArtifact(unit_tests);

    const integration_tests_module = b.createModule(.{
        .root_source_file = b.path("tests/integration_tests.zig"),
        .target = target,
        .optimize = optimize,
    });
    integration_tests_module.addImport("server", server_module);
    integration_tests_module.linkSystemLibrary("c", .{});
    integration_tests_module.linkSystemLibrary("wolfssl", .{});
    integration_tests_module.linkSystemLibrary("nghttp2", .{});

    const integration_tests = b.addTest(.{
        .root_module = integration_tests_module,
    });
    const run_integration_tests = b.addRunArtifact(integration_tests);

    const mock_tests_module = b.createModule(.{
        .root_source_file = b.path("tests/mock_tests.zig"),
        .target = target,
        .optimize = optimize,
    });
    mock_tests_module.addImport("server", server_module);
    mock_tests_module.linkSystemLibrary("c", .{});

    const mock_tests = b.addTest(.{
        .root_module = mock_tests_module,
    });
    const run_mock_tests = b.addRunArtifact(mock_tests);

    // Similar to creating the run step earlier, this exposes a `test` step to
    // the `zig build --help` menu, providing a way for the user to request
    // running the unit tests.
    const test_step = b.step("test", "Run all tests");
    test_step.dependOn(&run_lib_unit_tests.step);
    test_step.dependOn(&run_doh_tests.step);

    // Individual test steps
    const unit_test_step = b.step("test-unit", "Run unit tests only");
    unit_test_step.dependOn(&run_unit_tests.step);

    const integration_test_step = b.step("test-integration", "Run integration tests only");
    integration_test_step.dependOn(&run_integration_tests.step);

    const mock_test_step = b.step("test-mock", "Run mock tests only");
    mock_test_step.dependOn(&run_mock_tests.step);

    const retry_tests_module = b.createModule(.{
        .root_source_file = b.path("tests/retry_tests.zig"),
        .target = target,
        .optimize = optimize,
    });
    retry_tests_module.addImport("error", error_module);

    const retry_tests = b.addTest(.{
        .root_module = retry_tests_module,
    });
    const run_retry_tests = b.addRunArtifact(retry_tests);

    const retry_test_step = b.step("test-retry", "Run retry tests only");
    retry_test_step.dependOn(&run_retry_tests.step);
}
