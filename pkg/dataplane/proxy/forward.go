package proxy

import (
	"context"
	"net"

	log "log/slog"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/pkg/errors"
	"github.com/stillya/wg-relay/pkg/dataplane/config"

	wgebpf "github.com/stillya/wg-relay/ebpf"
	"github.com/stillya/wg-relay/pkg/dataplane/maps"
)

// ForwardLoader manages XDP-based forward proxy
type ForwardLoader struct {
	cfg   config.ProxyConfig
	objs  *wgebpf.WgForwardProxyObjects
	links []link.Link
}

// NewForwardLoader creates a new forward proxy loader
func NewForwardLoader() (*ForwardLoader, error) {
	return &ForwardLoader{}, nil
}

func (fp *ForwardLoader) LoadAndAttach(ctx context.Context, cfg config.ProxyConfig) error {
	fp.cfg = cfg

	if err := fp.loadEBPF(); err != nil {
		return errors.Wrap(err, "failed to load eBPF objects")
	}

	if err := fp.attachToInterfaces(); err != nil {
		fp.Close()
		return errors.Wrap(err, "failed to attach to interfaces")
	}

	log.Info("Forward proxy loaded and attached",
		"enabled", cfg.Enabled,
		"target_server_ip", cfg.Forward.TargetServerIP)

	return nil
}

func (fp *ForwardLoader) configureStaticVars(spec *ebpf.CollectionSpec) error {
	xorEnabled := fp.cfg.Instrumentations.XOR != nil && fp.cfg.Instrumentations.XOR.Enabled
	if err := spec.Variables["__cfg_xor_enabled"].Set(xorEnabled); err != nil {
		return errors.Wrap(err, "failed to set xor_enabled")
	}

	if xorEnabled {
		keyBytes := fp.cfg.GetXORKey()
		if keyBytes != nil {
			var keyArray [32]byte
			copy(keyArray[:], keyBytes)

			if err := spec.Variables["__cfg_xor_key"].Set(keyArray); err != nil {
				return errors.Wrap(err, "failed to set xor_key")
			}
			if err := spec.Variables["__cfg_xor_key_len"].Set(uint8(len(keyBytes))); err != nil {
				return errors.Wrap(err, "failed to set xor_key_len")
			}
		}
	} else {
		if err := spec.Variables["__cfg_xor_key_len"].Set(uint8(0)); err != nil {
			return errors.Wrap(err, "failed to set xor_key_len to 0")
		}
	}

	paddingEnabled := fp.cfg.Instrumentations.Padding != nil && fp.cfg.Instrumentations.Padding.Enabled
	if err := spec.Variables["__cfg_padding_enabled"].Set(paddingEnabled); err != nil {
		return errors.Wrap(err, "failed to set padding_enabled")
	}

	if paddingEnabled {
		minPad, maxPad, fillMode := fp.cfg.GetPaddingConfig()
		if err := spec.Variables["__cfg_padding_min"].Set(minPad); err != nil {
			return errors.Wrap(err, "failed to set padding_min")
		}
		if err := spec.Variables["__cfg_padding_max"].Set(maxPad); err != nil {
			return errors.Wrap(err, "failed to set padding_max")
		}
		if err := spec.Variables["__cfg_padding_fill_mode"].Set(fillMode); err != nil {
			return errors.Wrap(err, "failed to set padding_fill_mode")
		}
	} else {
		if err := spec.Variables["__cfg_padding_min"].Set(uint16(0)); err != nil {
			return errors.Wrap(err, "failed to set padding_min to 0")
		}
	}

	if err := spec.Variables["__cfg_wg_port"].Set(fp.cfg.WGPort); err != nil {
		return errors.Wrap(err, "failed to set wg_port")
	}

	return nil
}

func (fp *ForwardLoader) loadEBPF() error {
	spec, err := wgebpf.LoadWgForwardProxy()
	if err != nil {
		return errors.Wrap(err, "failed to load forward proxy spec")
	}

	if err := fp.configureStaticVars(spec); err != nil {
		return errors.Wrap(err, "failed to configure static variables")
	}

	fp.objs = &wgebpf.WgForwardProxyObjects{}
	opts := &ebpf.CollectionOptions{
		Programs: ebpf.ProgramOptions{
			LogLevel:     2,
			LogSizeStart: 16777216,
		},
	}

	if err := spec.LoadAndAssign(fp.objs, opts); err != nil {
		return errors.Wrap(err, "failed to load forward proxy eBPF objects")
	}

	if err := fp.configureBackendMap(); err != nil {
		return errors.Wrap(err, "failed to configure backend map")
	}

	log.Info("Forward proxy eBPF program loaded")
	return nil
}

func (fp *ForwardLoader) configureBackendMap() error {
	targetServerIP, err := fp.cfg.GetTargetServerIP()
	if err != nil {
		return errors.Wrap(err, "failed to get target server IP")
	}

	key := uint32(0)
	_ = key
	_ = targetServerIP

	log.Info("Backend map configured", "target_server_ip", fp.cfg.Forward.TargetServerIP)
	return nil
}

// attachToInterfaces attaches the XDP program to configured interfaces
func (fp *ForwardLoader) attachToInterfaces() error {
	for _, interfaceName := range fp.cfg.Interfaces {
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
	switch fp.cfg.DriverMode {
	case "generic":
		flags = link.XDPGenericMode
		mode = "generic"
	case "driver":
		flags = link.XDPDriverMode
		mode = "driver"
	case "offload":
		flags = link.XDPOffloadMode
		mode = "offload"
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
	var metricsMap *ebpf.Map
	if fp.objs != nil {
		metricsMap = fp.objs.MetricsMap
	}

	mapsCollection := maps.NewMaps(metricsMap)

	if fp.objs != nil {
		if fp.objs.ConnectionMap != nil {
			mapsCollection.AddOtherMap("ConnectionMap", fp.objs.ConnectionMap)
		}

		if fp.objs.NatReverseMap != nil {
			mapsCollection.AddOtherMap("NatReverseMap", fp.objs.NatReverseMap)
		}
	}

	return mapsCollection
}
