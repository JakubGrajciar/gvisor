load("//tools/go_stateify:defs.bzl", "go_library")
#load("@io_bazel_rules_go//go:def.bzl", "go_test")

package(licenses = ["notice"])

go_library(
    name = "memif",
    srcs = [
        "endpoint.go",
	"endpoint_unsafe.go",
	"socket.go",
	"socket_unsafe.go",
	"memif.go",
	"packet_dispatchers.go",
	"packet_writers.go",
	"atomic16_amd64.s",
	"atomic16.go",
    ],
    importpath = "gvisor.dev/gvisor/pkg/tcpip/link/memif",
    visibility = [
        "//visibility:public",
    ],
    deps = [
        "//pkg/tcpip",
        "//pkg/tcpip/buffer",
        "//pkg/tcpip/header",
        "//pkg/tcpip/link/rawfile",
        "//pkg/tcpip/stack",
        "@org_golang_x_sys//unix:go_default_library",
    ],
)

#go_test(
#    name = "fdbased_test",
#    size = "small",
#    srcs = ["endpoint_test.go"],
#    embed = [":fdbased"],
#    deps = [
#        "//pkg/tcpip",
#        "//pkg/tcpip/buffer",
#        "//pkg/tcpip/header",
#        "//pkg/tcpip/link/rawfile",
#        "//pkg/tcpip/stack",
#    ],
#)
