load("//tools:defs.bzl", "go_binary")

package(
    default_applicable_licenses = ["//:license"],
    licenses = ["notice"],
)

go_binary(
    name = "testbinary",
    testonly = True,
    srcs = ["main.go"],
    pure = True,
    static_pie = True,
    visibility = ["//tools/staticpie:__pkg__"],
)
