package mac

import "context"

// TestOptions customizes module internals for tests.
type TestOptions struct {
	Backend         string
	SELinuxConfig   string
	AppArmorEnabled string
	Runner          func(ctx context.Context, name string, args ...string) (string, error)
}

// NewModuleForTest returns a Module with injected test hooks.
func NewModuleForTest(o TestOptions) *Module {
	return &Module{
		run:             o.Runner,
		backendOverride: o.Backend,
		selinuxConfig:   o.SELinuxConfig,
		apparmorEnabled: o.AppArmorEnabled,
	}
}
