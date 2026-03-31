package discovery

// StaticBackendDiscovery implements BackendDiscovery with a fixed labels map.
type StaticBackendDiscovery struct {
	labels map[uint8]string
}

// NewStaticBackendDiscovery creates a new StaticBackendDiscovery.
func NewStaticBackendDiscovery(labels map[uint8]string) *StaticBackendDiscovery {
	if labels == nil {
		labels = make(map[uint8]string)
	}
	return &StaticBackendDiscovery{labels: labels}
}

// Backends returns the fixed backend labels map.
func (s *StaticBackendDiscovery) Backends() map[uint8]string {
	return s.labels
}
