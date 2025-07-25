"""Wrappers for common build rules.

These wrappers apply common BUILD configurations (e.g., proto_library
automagically creating cc_ and go_ proto targets) and act as a single point of
change for Google-internal and bazel-compatible rules.
"""

load("//tools/bazeldefs:cc.bzl", _cc_binary = "cc_binary", _cc_flags_supplier = "cc_flags_supplier", _cc_grpc_library = "cc_grpc_library", _cc_library = "cc_library", _cc_proto_library = "cc_proto_library", _cc_test = "cc_test", _cc_toolchain = "cc_toolchain", _gbenchmark = "gbenchmark", _gbenchmark_internal = "gbenchmark_internal", _grpcpp = "grpcpp", _gtest = "gtest", _select_gtest = "select_gtest")
load("//tools/bazeldefs:defs.bzl", _BuildSettingInfo = "BuildSettingInfo", _bool_flag = "bool_flag", _bpf_program = "bpf_program", _build_test = "build_test", _bzl_library = "bzl_library", _coreutil = "coreutil", _default_net_util = "default_net_util", _more_shards = "more_shards", _most_shards = "most_shards", _proto_library = "proto_library", _select_system = "select_system", _short_path = "short_path", _version = "version")
load("//tools/bazeldefs:go.bzl", _gazelle = "gazelle", _go_binary = "go_binary", _go_grpc_and_proto_libraries = "go_grpc_and_proto_libraries", _go_library = "go_library", _go_path = "go_path", _go_proto_library = "go_proto_library", _go_test = "go_test", _gotsan_flag_values = "gotsan_flag_values", _gotsan_values = "gotsan_values", _select_goarch = "select_goarch", _select_goos = "select_goos")
load("//tools/bazeldefs:pkg.bzl", _pkg_deb = "pkg_deb", _pkg_tar = "pkg_tar")
load("//tools/bazeldefs:platforms.bzl", _default_platform = "default_platform", _platform_capabilities = "platform_capabilities", _platforms = "platforms", _save_restore_platforms = "save_restore_platforms")
load("//tools/bazeldefs:tags.bzl", _go_suffixes = "go_suffixes", _local_test_tags = "local_test_tags")
load("//tools/go_marshal:defs.bzl", "go_marshal", "marshal_deps", "marshal_test_deps")
load("//tools/go_stateify:defs.bzl", "go_stateify")
load("//tools/nogo:defs.bzl", "nogo_test")

# Core rules.
build_test = _build_test
bzl_library = _bzl_library
bool_flag = _bool_flag
BuildSettingInfo = _BuildSettingInfo
default_net_util = _default_net_util
select_system = _select_system
short_path = _short_path
coreutil = _coreutil
more_shards = _more_shards
most_shards = _most_shards
version = _version

# C++ rules.
cc_binary = _cc_binary
cc_flags_supplier = _cc_flags_supplier
cc_grpc_library = _cc_grpc_library
cc_library = _cc_library
cc_test = _cc_test
cc_toolchain = _cc_toolchain
gbenchmark = _gbenchmark
gbenchmark_internal = _gbenchmark_internal
gtest = _gtest
grpcpp = _grpcpp
select_gtest = _select_gtest

# Go rules.
gazelle = _gazelle
go_path = _go_path
select_goos = _select_goos
select_goarch = _select_goarch
go_proto_library = _go_proto_library
gotsan_values = _gotsan_values
gotsan_flag_values = _gotsan_flag_values

# BPF rules.
bpf_program = _bpf_program

# Packaging rules.
pkg_deb = _pkg_deb
pkg_tar = _pkg_tar

# Platform options.
default_platform = _default_platform
platforms = _platforms
platform_capabilities = _platform_capabilities
save_restore_platforms = _save_restore_platforms

# Tags.
local_test_tags = _local_test_tags

def go_binary(name, nogo = True, pure = False, static = False, x_defs = None, **kwargs):
    """Wraps the standard go_binary.

    Args:
      name: the rule name.
      nogo: enable nogo analysis.
      pure: build a pure Go (no CGo) binary.
      static: build a static binary.
      x_defs: additional linker definitions.
      **kwargs: standard go_binary arguments.
    """
    _go_binary(
        name = name,
        pure = pure,
        static = static,
        x_defs = x_defs,
        **kwargs
    )
    if nogo:
        # Note that the nogo rule applies only for go_library and go_test
        # targets, therefore we construct a library from the binary sources.
        # This is done because the binary may not be in a form that objdump
        # supports (i.e. a pure Go binary).
        _go_library(
            name = name + "_nogo_library",
            srcs = kwargs.get("srcs", []),
            deps = kwargs.get("deps", []),
            embedsrcs = kwargs.get("embedsrcs", []),
            testonly = 1,
        )
        nogo_test(
            name = name + "_nogo",
            config = "//:nogo_config",
            srcs = kwargs.get("srcs", []),
            deps = [":" + name + "_nogo_library"],
            tags = ["nogo"],
        )

def calculate_sets(srcs):
    """Calculates special Go sets for templates.

    Args:
      srcs: the full set of Go sources.

    Returns:
      A dictionary of the form:

      "": [src1.go, src2.go]
      "suffix": [src3suffix.go, src4suffix.go]

      Note that suffix will typically start with '_'.
    """
    result = dict()
    for file in srcs:
        if not file.endswith(".go"):
            continue
        target = ""
        for suffix in _go_suffixes:
            if file.endswith(suffix + ".go"):
                target = suffix
        if not target in result:
            result[target] = [file]
        else:
            result[target].append(file)
    return result

def go_imports(name, src, out):
    """Simplify a single Go source file by eliminating unused imports."""
    native.genrule(
        name = name,
        srcs = [src],
        outs = [out],
        tools = ["@org_golang_x_tools//cmd/goimports:goimports"],
        cmd = ("$(location @org_golang_x_tools//cmd/goimports:goimports) $(SRCS) > $@"),
    )

def go_library(name, srcs, deps = [], imports = [], stateify = True, force_add_state_pkg = False, marshal = False, marshal_debug = False, nogo = True, **kwargs):
    """Wraps the standard go_library and does stateification and marshalling.

    The recommended way is to use this rule with mostly identical configuration as the native
    go_library rule.

    These definitions provide additional flags (stateify, marshal) that can be used
    with the generators to automatically supplement the library code.

    load("//tools:defs.bzl", "go_library")

    go_library(
        name = "foo",
        srcs = ["foo.go"],
    )

    Args:
      name: the rule name.
      srcs: the library sources.
      deps: the library dependencies.
      imports: imports required for stateify.
      stateify: whether statify is enabled (default: true).
      force_add_state_pkg: whether to skip checking whether the state package
        is included in `deps`, and to just instead include it outright.
        This allows `go_library` to be used in conjunction with `select`
        statements in `deps`.
      marshal: whether marshal is enabled (default: false).
      marshal_debug: whether the gomarshal tools emits debugging output (default: false).
      nogo: enable nogo analysis.
      **kwargs: standard go_library arguments.
    """
    all_srcs = srcs
    all_deps = deps
    dirname, _, _ = native.package_name().rpartition("/")
    full_pkg = dirname + "/" + name
    if stateify:
        # Only do stateification for non-state packages without manual autogen.
        # First, we need to segregate the input files via the special suffixes,
        # and calculate the final output set.
        state_sets = calculate_sets(srcs)
        for (suffix, src_subset) in state_sets.items():
            go_stateify(
                name = name + suffix + "_state_autogen_with_imports",
                srcs = src_subset,
                imports = imports,
                package = full_pkg,
                out = name + suffix + "_state_autogen_with_imports.go",
            )
            go_imports(
                name = name + suffix + "_state_autogen",
                src = name + suffix + "_state_autogen_with_imports.go",
                out = name + suffix + "_state_autogen.go",
            )
        all_srcs = all_srcs + [
            name + suffix + "_state_autogen.go"
            for suffix in state_sets.keys()
        ]

        if force_add_state_pkg or "//pkg/state" not in all_deps:
            all_deps = all_deps + ["//pkg/state"]

    if marshal:
        # See above.
        marshal_sets = calculate_sets(srcs)
        for (suffix, src_subset) in marshal_sets.items():
            go_marshal(
                name = name + suffix + "_abi_autogen",
                srcs = src_subset,
                debug = select({
                    "//tools/go_marshal:marshal_config_verbose": True,
                    "//conditions:default": marshal_debug,
                }),
                imports = imports,
                package = name,
            )
        extra_deps = [
            dep
            for dep in marshal_deps
            if not dep in all_deps
        ]
        all_deps = all_deps + extra_deps
        all_srcs = all_srcs + [
            name + suffix + "_abi_autogen_unsafe.go"
            for suffix in marshal_sets.keys()
        ]

    _go_library(
        name = name,
        srcs = all_srcs,
        deps = all_deps,
        **kwargs
    )
    if nogo:
        nogo_test(
            name = name + "_nogo",
            config = "//:nogo_config",
            srcs = all_srcs,
            deps = [":" + name],
            tags = ["nogo"],
        )

    if marshal:
        # Ignore importpath for go_test.
        kwargs.pop("importpath", None)

        # See above.
        marshal_sets = calculate_sets(srcs)
        for (suffix, _) in marshal_sets.items():
            _go_test(
                name = name + suffix + "_abi_autogen_test",
                srcs = [
                    name + suffix + "_abi_autogen_test.go",
                    name + suffix + "_abi_autogen_unconditional_test.go",
                ],
                library = ":" + name,
                deps = marshal_test_deps,
                **kwargs
            )

def go_test(name, nogo = True, **kwargs):
    """Wraps the standard go_test.

    Args:
      name: the rule name.
      nogo: enable nogo analysis.
      **kwargs: standard go_test arguments.
    """
    _go_test(
        name = name,
        **kwargs
    )
    if nogo:
        nogo_test(
            name = name + "_nogo",
            config = "//:nogo_config",
            srcs = kwargs.get("srcs", []),
            deps = [":" + name],
            tags = ["nogo"],
        )

def proto_library(name, srcs, deps = None, has_services = 0, **kwargs):
    """Wraps the standard proto_library.

    Given a proto_library named "foo", this produces up to five different
    targets:
    - foo_proto: proto_library rule.
    - foo_go_proto: go_proto_library rule.
    - foo_cc_proto: cc_proto_library rule.
    - foo_go_grpc_proto: go_grpc_library rule.
    - foo_cc_grpc_proto: cc_grpc_library rule.

    Args:
      name: the name to which _proto, _go_proto, etc, will be appended.
      srcs: the proto sources.
      deps: for the proto library and the go_proto_library.
      has_services: 1 to build gRPC code, otherwise 0.
      **kwargs: standard proto_library arguments.
    """
    _proto_library(
        name = name + "_proto",
        srcs = srcs,
        deps = deps,
        has_services = has_services,
        **kwargs
    )
    if has_services:
        _go_grpc_and_proto_libraries(
            name = name,
            deps = deps,
            **kwargs
        )
    else:
        _go_proto_library(
            name = name,
            deps = deps,
            **kwargs
        )
    _cc_proto_library(
        name = name + "_cc_proto",
        deps = [":" + name + "_proto"],
        **kwargs
    )
    if has_services:
        _cc_grpc_library(
            name = name + "_cc_grpc_proto",
            srcs = [":" + name + "_proto"],
            deps = [":" + name + "_cc_proto"],
            **kwargs
        )
