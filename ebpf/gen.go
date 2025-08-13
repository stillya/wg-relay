package ebpf

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go WgForwardProxy wg_forward_proxy.c -- -Iinclude
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go WgReverseProxy wg_reverse_proxy.c -- -Iinclude
