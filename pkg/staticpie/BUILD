load("//tools:defs.bzl", "go_library")

package(
    default_applicable_licenses = ["//:license"],
    licenses = ["notice"],
)

go_library(
    name = "staticpie",
    srcs = [
        "staticpie.go",
        "staticpie_amd64.s",
        "staticpie_arm64.s",
    ],
    stateify = False,
    visibility = ["//:sandbox"],
)
