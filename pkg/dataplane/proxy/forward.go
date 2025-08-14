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

// ForwardLoader manages XDP-based forward proxy
type ForwardLoader struct {
	cfg   config.Config
	objs  *wgebpf.WgForwardProxyObjects
	links []link.Link
}

// NewForwardLoader creates a new forward proxy loader
func NewForwardLoader() (*ForwardLoader, error) {
	return &ForwardLoader{}, nil
}

// LoadAndAttach loads the forward proxy program and attaches it to interfaces
func (fp *ForwardLoader) LoadAndAttach(ctx context.Context, cfg config.Config) error {
	fp.cfg = cfg

	if err := fp.loadEBPF(); err != nil {
		return errors.Wrap(err, "failed to load eBPF objects")
	}

	if err := fp.configure(cfg); err != nil {
		return errors.Wrap(err, "failed to configure eBPF maps")
	}

	if err := fp.attachToInterfaces(); err != nil {
		fp.Close()
		return errors.Wrap(err, "failed to attach to interfaces")
	}

	log.Info("Forward proxy loaded and attached",
		"enabled", cfg.Enabled,
		"method", cfg.Proxy.Method,
		"target_server_ip", cfg.Proxy.Forward.TargetServerIP)

	return nil
}

// configure configures the eBPF maps with the provided configuration
func (fp *ForwardLoader) configure(cfg config.Config) error {
	if fp.objs == nil || fp.objs.ObfuscationConfigMap == nil {
		return errors.New("eBPF objects not loaded")
	}

	targetServerIP, err := cfg.GetTargetServerIP()
	if err != nil {
		return errors.Wrap(err, "failed to get target server IP")
	}

	keyBytes := cfg.GetKeyBytes()
	epbfConfig := wgebpf.WgForwardProxyObfuscationConfig{
		Enabled:        1,
		Method:         uint32(cfg.GetMethod()),
		KeyLen:         uint32(len(keyBytes)),
		TargetServerIp: targetServerIP,
	}

	if !cfg.Enabled {
		epbfConfig.Enabled = 0
	}

	if len(keyBytes) > len(epbfConfig.Key) {
		return errors.Errorf("key too long: %d bytes, max %d", len(keyBytes), len(epbfConfig.Key))
	}
	copy(epbfConfig.Key[:], keyBytes)

	configKey := uint32(0)
	if err := fp.objs.ObfuscationConfigMap.Put(&configKey, &epbfConfig); err != nil {
		return errors.Wrap(err, "failed to update forward epbfConfig map")
	}

	return nil
}

// loadEBPF loads the forward proxy eBPF program
func (fp *ForwardLoader) loadEBPF() error {
	fp.objs = &wgebpf.WgForwardProxyObjects{}

	opts := &ebpf.CollectionOptions{
		Programs: ebpf.ProgramOptions{
			LogLevel:     2,
			LogSizeStart: 16777216, // 16 MB log size
		},
	}

	if err := wgebpf.LoadWgForwardProxyObjects(fp.objs, opts); err != nil {
		return errors.Wrap(err, "failed to load forward proxy eBPF objects")
	}

	log.Info("Forward proxy eBPF program loaded")
	return nil
}

// attachToInterfaces attaches the XDP program to configured interfaces
func (fp *ForwardLoader) attachToInterfaces() error {
	for _, interfaceName := range fp.cfg.Proxy.Interfaces {
		if err := fp.attachToInterface(interfaceName); err != nil {
			fp.cleanupLinks()
			return errors.Wrapf(err, "failed to attach to interface %s", interfaceName)
		}
	}
	return nil
}

// attachToInterface attaches XDP program to a single interface
func (fp *ForwardLoader) attachToInterface(interfaceName string) error {
	iface, err := net.InterfaceByName(interfaceName)
	if err != nil {
		return errors.Wrapf(err, "failed to get interface %s", interfaceName)
	}

	var flags link.XDPAttachFlags
	var mode string
	switch fp.cfg.Proxy.DriverMode {
	case "generic":
		flags = link.XDPGenericMode
		mode = "generic"
	case "driver":
		flags = link.XDPDriverMode
		mode = "driver"
	default:
		// Default to driver mode
		flags = link.XDPDriverMode
		mode = "driver"
	}

	log.Info("Attaching XDP forward proxy", "interface", interfaceName, "index", iface.Index, "mode", mode)

	xdpLink, err := link.AttachXDP(link.XDPOptions{
		Program:   fp.objs.WgForwardProxy,
		Interface: iface.Index,
		Flags:     flags,
	})
	if err != nil {
		return errors.Wrapf(err, "failed to attach XDP program to interface %s in %s mode", interfaceName, mode)
	}

	log.Info("XDP forward proxy attached successfully", "interface", interfaceName, "mode", mode)
	fp.links = append(fp.links, xdpLink)
	return nil
}

// cleanupLinks cleans up all attached links
func (fp *ForwardLoader) cleanupLinks() {
	for _, l := range fp.links {
		if l != nil {
			err := l.Close()
			if err != nil {
				log.Error("Failed to close XDP link", "error", err)
			} else {
				log.Info("XDP link closed successfully")
			}
		}
	}
	fp.links = nil
}

// Close cleans up all resources
func (fp *ForwardLoader) Close() error {
	var errs []error

	for i, l := range fp.links {
		if l != nil {
			if err := l.Close(); err != nil {
				errs = append(errs, errors.Wrapf(err, "failed to close XDP l %d", i))
			}
		}
	}

	if fp.objs != nil {
		if err := fp.objs.Close(); err != nil {
			errs = append(errs, errors.Wrap(err, "failed to close forward proxy eBPF objects"))
		}
	}

	if len(errs) > 0 {
		return errs[0]
	}

	return nil
}

// Maps returns all eBPF maps used by the forward proxy
func (fp *ForwardLoader) Maps() *maps.Maps {
	mapsCollection := maps.NewMaps()

	if fp.objs != nil {
		if fp.objs.StatsMap != nil {
			mapsCollection.AddStatsMap("StatsMap", fp.objs.StatsMap)
		}

		if fp.objs.ConnectionMap != nil {
			mapsCollection.AddOtherMap("ConnectionMap", fp.objs.ConnectionMap)
		}

		if fp.objs.NatReverseMap != nil {
			mapsCollection.AddOtherMap("NatReverseMap", fp.objs.NatReverseMap)
		}
	}

	return mapsCollection
}
