// export_test.go exposes internal constructor knobs for package-external tests.
package ntp

import "context"

// NewModuleForTest returns a Module with an injected command runner and chrony path.
func NewModuleForTest(
	run func(ctx context.Context, name string, args ...string) (string, error),
	chronyPath string,
) *Module {
	return &Module{
		run:            run,
		chronyConfPath: chronyPath,
	}
}
