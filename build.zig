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

    // const lib = b.addStaticLibrary(.{
    //     .name = "doh",
    //     // In this case the main source file is merely a path, however, in more
    //     // complicated build scripts, this could be a generated file.
    //     .root_source_file = b.path("src/root.zig"),
    //     .target = target,
    //     .optimize = optimize,
    // });

    // This declares intent for the library to be installed into the standard
    // location when the user invokes the "install" step (the default step when
    // running `zig build`).
    //b.installArtifact(lib);

    const exe = b.addExecutable(.{
        .name = "doh",
        .root_source_file = b.path("src/main.zig"),
        .target = target,
        .optimize = optimize,
    });

    const error_module = b.addModule("error", .{
        .root_source_file = b.path("src/error.zig"),
    });
    exe.root_module.addImport("error", error_module);

    //exe.addLibraryPath(.{ .cwd_relative = "/nix/store/kvaq8j1nww7yq8d1vjgmsy2jqk33yjsp-wolfssl-all-5.7.2-dev/lib" });
    //exe.addLibraryPath(.{ .cwd_relative = "/nix/store/68qv46bl2ww8c3bprmk68qwg2sv3yksi-c-ares-1.27.0/lib/" });
    exe.linkSystemLibrary("c");
    exe.linkSystemLibrary("wolfssl");
    exe.linkSystemLibrary("nghttp2");

    b.installArtifact(exe);

    // This declares intent for the executable to be installed into the
    // standard location when the user invokes the "install" step (the default
    // step when running `zig build`).
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
    const lib_unit_tests = b.addTest(.{
        .root_source_file = b.path("src/main.zig"),
        .target = target,
        .optimize = optimize,
    });

    // Link the same libraries for tests
    lib_unit_tests.linkSystemLibrary("c");
    lib_unit_tests.linkSystemLibrary("wolfssl");
    lib_unit_tests.linkSystemLibrary("nghttp2");
    lib_unit_tests.root_module.addImport("error", error_module);

    const run_lib_unit_tests = b.addRunArtifact(lib_unit_tests);

    // Create a module for the server code that tests can import
    const server_module = b.addModule("server", .{
        .root_source_file = b.path("src/server.zig"),
    });
    server_module.addImport("error", error_module);

    // Add comprehensive test suite
    const doh_tests = b.addTest(.{
        .root_source_file = b.path("tests/test_suite.zig"),
        .target = target,
        .optimize = optimize,
    });

    // Add the server module to tests
    doh_tests.root_module.addImport("server", server_module);
    doh_tests.root_module.addImport("error", error_module);

    // Link libraries for DoH tests
    doh_tests.linkSystemLibrary("c");
    doh_tests.linkSystemLibrary("wolfssl");
    doh_tests.linkSystemLibrary("nghttp2");

    const run_doh_tests = b.addRunArtifact(doh_tests);

    // Add individual test modules
    const unit_tests = b.addTest(.{
        .root_source_file = b.path("tests/unit_tests.zig"),
        .target = target,
        .optimize = optimize,
    });
    unit_tests.root_module.addImport("server", server_module);
    unit_tests.linkSystemLibrary("c");
    unit_tests.linkSystemLibrary("wolfssl");
    unit_tests.linkSystemLibrary("nghttp2");
    const run_unit_tests = b.addRunArtifact(unit_tests);

    const integration_tests = b.addTest(.{
        .root_source_file = b.path("tests/integration_tests.zig"),
        .target = target,
        .optimize = optimize,
    });
    integration_tests.root_module.addImport("server", server_module);
    integration_tests.linkSystemLibrary("c");
    integration_tests.linkSystemLibrary("wolfssl");
    integration_tests.linkSystemLibrary("nghttp2");
    const run_integration_tests = b.addRunArtifact(integration_tests);

    const mock_tests = b.addTest(.{
        .root_source_file = b.path("tests/mock_tests.zig"),
        .target = target,
        .optimize = optimize,
    });
    mock_tests.root_module.addImport("server", server_module);
    mock_tests.linkSystemLibrary("c");
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

    const retry_tests = b.addTest(.{
        .root_source_file = b.path("tests/retry_tests.zig"),
        .target = target,
        .optimize = optimize,
    });
    retry_tests.root_module.addImport("error", error_module);
    const run_retry_tests = b.addRunArtifact(retry_tests);

    const retry_test_step = b.step("test-retry", "Run retry tests only");
    retry_test_step.dependOn(&run_retry_tests.step);
}
