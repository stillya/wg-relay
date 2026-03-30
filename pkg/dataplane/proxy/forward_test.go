package proxy

import (
	"testing"

	"github.com/stillya/wg-relay/pkg/dataplane/config"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestForwardLoader_generateBackendLabels(t *testing.T) {
	tests := []struct {
		name     string
		backends []config.BackendServer
		expected map[uint8]string
	}{
		{
			name: "named backends",
			backends: []config.BackendServer{
				{Name: "wg-server-1", IP: "10.0.0.1", Port: 51820},
				{Name: "wg-server-2", IP: "10.0.0.2", Port: 51820},
			},
			expected: map[uint8]string{
				0: "wg-server-1",
				1: "wg-server-2",
			},
		},
		{
			name: "unnamed backends",
			backends: []config.BackendServer{
				{IP: "10.0.0.1", Port: 51820},
				{IP: "10.0.0.2", Port: 51820},
			},
			expected: map[uint8]string{
				0: "backend_0",
				1: "backend_1",
			},
		},
		{
			name: "mixed named and unnamed",
			backends: []config.BackendServer{
				{Name: "wg-primary", IP: "10.0.0.1", Port: 51820},
				{IP: "10.0.0.2", Port: 51820},
				{Name: "wg-backup", IP: "10.0.0.3", Port: 51820},
			},
			expected: map[uint8]string{
				0: "wg-primary",
				1: "backend_1",
				2: "wg-backup",
			},
		},
		{
			name: "single backend with name",
			backends: []config.BackendServer{
				{Name: "main-wg", IP: "10.0.0.1", Port: 51820},
			},
			expected: map[uint8]string{
				0: "main-wg",
			},
		},
		{
			name: "single backend without name",
			backends: []config.BackendServer{
				{IP: "10.0.0.1", Port: 51820},
			},
			expected: map[uint8]string{
				0: "backend_0",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			loader := &ForwardLoader{
				cfg: config.ProxyConfig{
					Forward: config.ForwardConfig{
						Backends: tt.backends,
					},
				},
			}

			loader.generateBackendLabels()

			assert.Equal(t, tt.expected, loader.backendLabels)
		})
	}
}

func TestForwardLoader_BackendLabels(t *testing.T) {
	t.Run("returns copy of backend labels", func(t *testing.T) {
		loader := &ForwardLoader{
			cfg: config.ProxyConfig{
				Forward: config.ForwardConfig{
					Backends: []config.BackendServer{
						{Name: "wg-1", IP: "10.0.0.1", Port: 51820},
						{IP: "10.0.0.2", Port: 51820},
					},
				},
			},
		}

		loader.generateBackendLabels()

		labels1 := loader.BackendLabels()
		labels2 := loader.BackendLabels()

		require.Equal(t, labels1, labels2)

		labels1[0] = "modified"
		assert.NotEqual(t, labels1, labels2, "modifying returned map should not affect internal state")
	})

	t.Run("returns empty map when backendLabels is nil", func(t *testing.T) {
		loader := &ForwardLoader{}

		labels := loader.BackendLabels()

		assert.NotNil(t, labels)
		assert.Empty(t, labels)
	})

	t.Run("returns empty map when no backends", func(t *testing.T) {
		loader := &ForwardLoader{
			cfg: config.ProxyConfig{
				Forward: config.ForwardConfig{
					Backends: []config.BackendServer{},
				},
			},
		}

		loader.generateBackendLabels()
		labels := loader.BackendLabels()

		assert.NotNil(t, labels)
		assert.Empty(t, labels)
	})
}

func TestForwardLoader_generateBackendLabels_CalledInLoadAndAttach(t *testing.T) {
	loader := &ForwardLoader{}

	cfg := config.ProxyConfig{
		Forward: config.ForwardConfig{
			Backends: []config.BackendServer{
				{Name: "test-backend", IP: "10.0.0.1", Port: 51820},
			},
		},
	}

	loader.cfg = cfg
	loader.generateBackendLabels()

	labels := loader.BackendLabels()
	assert.Equal(t, "test-backend", labels[0])
}
