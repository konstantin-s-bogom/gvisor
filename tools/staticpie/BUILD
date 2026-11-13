load("//tools:defs.bzl", "go_binary", "go_test")

package(
    default_applicable_licenses = ["//:license"],
    licenses = ["notice"],
)

go_binary(
    name = "staticpie",
    srcs = [
        "convert.go",
        "main.go",
    ],
    pure = True,
    visibility = ["//:sandbox"],
)

go_test(
    name = "staticpie_test",
    size = "small",
    srcs = [
        "convert.go",
        "convert_test.go",
    ],
    data = ["//tools/staticpie/testbinary"],
    deps = [
        "//pkg/test/testutil",
        "@org_golang_x_sys//unix:go_default_library",
    ],
)

go_test(
    name = "release_test",
    size = "small",
    srcs = [
        "convert.go",
        "release_test.go",
    ],
    args = select({
        "//tools:gotsan": ["--want_static_pie=false"],
        "//conditions:default": [],
    }),
    data = ["//:release"],
    deps = ["//pkg/test/testutil"],
)
