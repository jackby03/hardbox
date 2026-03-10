package config

import (
	"reflect"
	"testing"
)

func TestConfig_ModuleCfg(t *testing.T) {
	tests := []struct {
		name       string
		config     *Config
		moduleName string
		expected   ModuleConfig
	}{
		{
			name: "Modules is nil",
			config: &Config{
				Modules: nil,
			},
			moduleName: "test-module",
			expected:   ModuleConfig{},
		},
		{
			name: "Module not found",
			config: &Config{
				Modules: map[string]ModuleConfig{
					"other-module": {"key": "value"},
				},
			},
			moduleName: "test-module",
			expected:   ModuleConfig{},
		},
		{
			name: "Module found",
			config: &Config{
				Modules: map[string]ModuleConfig{
					"test-module": {"key": "value"},
				},
			},
			moduleName: "test-module",
			expected:   ModuleConfig{"key": "value"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tt.config.ModuleCfg(tt.moduleName)
			if !reflect.DeepEqual(got, tt.expected) {
				t.Errorf("ModuleCfg() = %v, want %v", got, tt.expected)
			}
		})
	}
}
