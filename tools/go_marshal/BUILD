load("@io_bazel_rules_go//go:def.bzl", "go_binary")

package(licenses = ["notice"])

go_binary(
    name = "go_marshal",
    srcs = ["main.go"],
    visibility = [
        "//:sandbox",
    ],
    deps = [
        "//tools/go_marshal/gomarshal",
    ],
)
