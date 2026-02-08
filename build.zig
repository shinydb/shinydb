const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    const yaml = b.dependency("yaml", .{});
    const proto = b.dependency("proto", .{});
    const bson = b.dependency("bson", .{});

    const lib_mod = b.createModule(.{
        .root_source_file = b.path("src/root.zig"),
        .target = target,
        .optimize = optimize,
    });

    const exe_mod = b.createModule(.{
        .root_source_file = b.path("src/main.zig"),
        .target = target,
        .optimize = optimize,
    });

    exe_mod.addImport("shinydb_lib", lib_mod);

    const lib = b.addLibrary(.{
        .linkage = .static,
        .name = "shinydb_lib",
        .root_module = lib_mod,
    });

    lib.root_module.addImport("yaml", yaml.module("yaml"));
    lib.root_module.addImport("proto", proto.module("proto"));
    lib.root_module.addImport("bson", bson.module("bson"));

    b.installArtifact(lib);

    const exe = b.addExecutable(.{
        .name = "shinydb",
        .root_module = exe_mod,
    });

    exe.root_module.addImport("yaml", yaml.module("yaml"));
    exe.root_module.addImport("proto", proto.module("proto"));
    exe.root_module.addImport("bson", bson.module("bson"));

    b.installArtifact(exe);

    const run_cmd = b.addRunArtifact(exe);

    run_cmd.step.dependOn(b.getInstallStep());

    if (b.args) |args| {
        run_cmd.addArgs(args);
    }

    const run_step = b.step("run", "Run the app");
    run_step.dependOn(&run_cmd.step);

    const lib_unit_tests = b.addTest(.{
        .root_module = lib_mod,
    });
    lib_unit_tests.root_module.addImport("yaml", yaml.module("yaml"));
    lib_unit_tests.root_module.addImport("proto", proto.module("proto"));
    lib_unit_tests.root_module.addImport("bson", bson.module("bson"));

    const run_lib_unit_tests = b.addRunArtifact(lib_unit_tests);

    const exe_unit_tests = b.addTest(.{
        .root_module = exe_mod,
    });
    exe_unit_tests.root_module.addImport("yaml", yaml.module("yaml"));
    exe_unit_tests.root_module.addImport("proto", proto.module("proto"));
    exe_unit_tests.root_module.addImport("bson", bson.module("bson"));

    const run_exe_unit_tests = b.addRunArtifact(exe_unit_tests);

    // Integration tests from tests/ folder
    const integration_tests_mod = b.createModule(.{
        .root_source_file = b.path("tests/integration_test.zig"),
        .target = target,
        .optimize = optimize,
    });
    integration_tests_mod.addImport("shinydb_lib", lib_mod);
    integration_tests_mod.addImport("yaml", yaml.module("yaml"));
    integration_tests_mod.addImport("proto", proto.module("proto"));
    integration_tests_mod.addImport("bson", bson.module("bson"));

    const integration_tests = b.addTest(.{
        .root_module = integration_tests_mod,
    });
    integration_tests.root_module.addImport("shinydb_lib", lib_mod);
    integration_tests.root_module.addImport("yaml", yaml.module("yaml"));
    integration_tests.root_module.addImport("proto", proto.module("proto"));
    integration_tests.root_module.addImport("bson", bson.module("bson"));

    const run_integration_tests = b.addRunArtifact(integration_tests);

    const test_step = b.step("test", "Run unit tests");
    test_step.dependOn(&run_lib_unit_tests.step);
    test_step.dependOn(&run_exe_unit_tests.step);
    // Integration tests are separate since they need special setup
    // Run with: zig build test-integration

    // Separate step for just integration tests
    const integration_step = b.step("test-integration", "Run integration tests only");
    integration_step.dependOn(&run_integration_tests.step);
}
