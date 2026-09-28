package proxy

import (
	"testing"

	"github.com/cilium/ebpf"

	wgebpf "github.com/stillya/wg-relay/ebpf"
)

func TestForwardLoaderMaps(t *testing.T) {
	t.Run("nil objs leaves conntrack maps nil", func(t *testing.T) {
		m := (&ForwardLoader{}).Maps()

		if m.CT != nil {
			t.Error("expected CT to be nil")
		}
		if m.CTRev != nil {
			t.Error("expected CTRev to be nil")
		}
	})

	t.Run("objs populate conntrack maps", func(t *testing.T) {
		ct, ctRev := &ebpf.Map{}, &ebpf.Map{}
		fp := &ForwardLoader{objs: &wgebpf.WgForwardProxyObjects{
			WgForwardProxyMaps: wgebpf.WgForwardProxyMaps{
				Ipv4CtMap:    ct,
				Ipv4CtRevMap: ctRev,
			},
		}}

		m := fp.Maps()

		if m.CT != ct {
			t.Error("expected CT to be Ipv4CtMap")
		}
		if m.CTRev != ctRev {
			t.Error("expected CTRev to be Ipv4CtRevMap")
		}
	})
}
