package proxy

import (
	"context"
	"net"

	log "log/slog"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/pkg/errors"

	wgebpf "github.com/stillya/wg-relay/ebpf"
	"github.com/stillya/wg-relay/pkg/dataplane/config"
	"github.com/stillya/wg-relay/pkg/dataplane/maps"
)

// ReverseLoader manages TC-based reverse proxy
type ReverseLoader struct {
	cfg          config.ProxyConfig
	objs         *wgebpf.WgReverseProxyObjects
	ingressLinks []link.Link
	egressLinks  []link.Link
}

// NewReverseLoader creates a new reverse proxy loader
func NewReverseLoader() (*ReverseLoader, error) {
	return &ReverseLoader{}, nil
}

// LoadAndAttach loads the reverse proxy program and attaches it to interfaces
func (rp *ReverseLoader) LoadAndAttach(ctx context.Context, cfg config.ProxyConfig) error {
	rp.cfg = cfg

	if err := rp.loadEBPF(); err != nil {
		return errors.Wrap(err, "failed to load eBPF objects")
	}

	if err := rp.configure(cfg); err != nil {
		return errors.Wrap(err, "failed to configure eBPF maps")
	}

	if err := rp.attachToInterfaces(); err != nil {
		rp.Close()
		return errors.Wrap(err, "failed to attach to interfaces")
	}

	log.Info("Reverse proxy loaded and attached", "interfaces", cfg.Interfaces)
	return nil
}

// configure configures the eBPF maps with the provided configuration
func (rp *ReverseLoader) configure(cfg config.ProxyConfig) error {
	if rp.objs == nil || rp.objs.ObfuscationConfigMap == nil {
		return errors.New("eBPF objects not loaded")
	}

	keyBytes := cfg.GetKeyBytes()
	ebpfConfig := wgebpf.WgReverseProxyObfuscationConfig{
		Enabled: 1,
		Method:  uint32(cfg.GetMethod()),
		KeyLen:  uint32(len(keyBytes)),
	}

	if !cfg.Enabled {
		ebpfConfig.Enabled = 0
	}

	if len(keyBytes) > len(ebpfConfig.Key) {
		return errors.Errorf("key too long: %d bytes, max %d", len(keyBytes), len(ebpfConfig.Key))
	}
	copy(ebpfConfig.Key[:], keyBytes)

	configKey := uint32(0)
	if err := rp.objs.ObfuscationConfigMap.Put(&configKey, &ebpfConfig); err != nil {
		return errors.Wrap(err, "failed to update reverse ebpfConfig map")
	}

	log.Info("Reverse mode configuration updated",
		"enabled", cfg.Enabled,
		"method", cfg.Method,
		"key_len", len(keyBytes))

	return nil
}

// loadEBPF loads the reverse proxy eBPF program
func (rp *ReverseLoader) loadEBPF() error {
	rp.objs = &wgebpf.WgReverseProxyObjects{}

	// Enable verbose eBPF verifier logging
	opts := &ebpf.CollectionOptions{
		Programs: ebpf.ProgramOptions{
			LogLevel:     2,
			LogSizeStart: 16777216, // 16 MB log size
		},
	}

	if err := wgebpf.LoadWgReverseProxyObjects(rp.objs, opts); err != nil {
		return errors.Wrap(err, "failed to load reverse proxy eBPF objects")
	}

	log.Info("Reverse proxy eBPF program loaded")
	return nil
}

// attachToInterfaces attaches the TC program to configured interfaces
func (rp *ReverseLoader) attachToInterfaces() error {
	for _, interfaceName := range rp.cfg.Interfaces {
		if err := rp.attachToInterface(interfaceName); err != nil {
			rp.cleanupLinks()
			return errors.Wrapf(err, "failed to attach to interface %s", interfaceName)
		}
	}
	return nil
}

// attachToInterface attaches TC program to a single interface (both ingress and egress)
func (rp *ReverseLoader) attachToInterface(interfaceName string) error {
	iface, err := net.InterfaceByName(interfaceName)
	if err != nil {
		return errors.Wrapf(err, "failed to get interface %s", interfaceName)
	}

	log.Info("Attaching TC reverse proxy", "interface", interfaceName, "index", iface.Index)

	ingressLink, err := rp.attachTCProgram(iface, true, false)
	if err != nil {
		return errors.Wrapf(err, "failed to attach TC program on ingress for interface %s", interfaceName)
	}
	rp.ingressLinks = append(rp.ingressLinks, ingressLink)

	egressLink, err := rp.attachTCProgram(iface, false, true)
	if err != nil {
		return errors.Wrapf(err, "failed to attach TC program on egress for interface %s", interfaceName)
	}
	rp.egressLinks = append(rp.egressLinks, egressLink)

	return nil
}

// attachTCProgram attaches the TC program to the specified interface for either ingress or egress
func (rp *ReverseLoader) attachTCProgram(iface *net.Interface, ingress, egress bool) (link.Link, error) {
	if !ingress && !egress {
		return nil, errors.New("must specify either ingress or egress attachment")
	}

	var attach ebpf.AttachType
	var direction string

	if ingress {
		attach = ebpf.AttachTCXIngress
		direction = "ingress"
	} else {
		attach = ebpf.AttachTCXEgress
		direction = "egress"
	}

	log.Debug("Attempting TCX attachment", "interface", iface.Name, "direction", direction)
	tcxLink, err := link.AttachTCX(link.TCXOptions{
		Program:   rp.objs.WgReverseProxy,
		Attach:    attach,
		Interface: iface.Index,
	})

	if err != nil {
		log.Warn("TCX attachment failed", "interface", iface.Name, "direction", direction, "error", err)

		return nil, errors.Wrapf(err, "failed to attach TCX program on %s for interface %s", direction, iface.Name)
	}

	log.Info("Successfully attached program using TCX", "interface", iface.Name, "direction", direction)
	return tcxLink, nil
}

// cleanupLinks cleans up all attached links
func (rp *ReverseLoader) cleanupLinks() {
	for _, l := range rp.ingressLinks {
		if l != nil {
			l.Close()
		}
	}
	for _, l := range rp.egressLinks {
		if l != nil {
			l.Close()
		}
	}
	rp.ingressLinks = nil
	rp.egressLinks = nil
}

// Close cleans up all resources
func (rp *ReverseLoader) Close() error {
	var errs []error

	for i, l := range rp.ingressLinks {
		if l != nil {
			if err := l.Close(); err != nil {
				errs = append(errs, errors.Wrapf(err, "failed to close ingress TC l %d", i))
			}
		}
	}

	for i, l := range rp.egressLinks {
		if l != nil {
			if err := l.Close(); err != nil {
				errs = append(errs, errors.Wrapf(err, "failed to close egress TC l %d", i))
			}
		}
	}

	if rp.objs != nil {
		if err := rp.objs.Close(); err != nil {
			errs = append(errs, errors.Wrap(err, "failed to close reverse proxy eBPF objects"))
		}
	}

	if len(errs) > 0 {
		return errs[0]
	}

	return nil
}

// Maps returns all eBPF maps used by the reverse proxy
func (rp *ReverseLoader) Maps() *maps.Maps {
	mapsCollection := maps.NewMaps()

	if rp.objs != nil {
		if rp.objs.StatsMap != nil {
			mapsCollection.AddStatsMap("StatsMap", rp.objs.StatsMap)
		}

		// Set the new metrics map
		if rp.objs.MetricsMap != nil {
			mapsCollection.SetMetricsMap(rp.objs.MetricsMap)
		}
	}

	return mapsCollection
}
