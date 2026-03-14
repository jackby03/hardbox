// export_test.go exposes internal constructor knobs for package-external tests.
package auditd

import "context"

// NewModuleForTest returns a Module with an injected command runner, rules dir, and conf path.
func NewModuleForTest(
	run func(ctx context.Context, name string, args ...string) (string, error),
	rulesDir string,
	confPath string,
) *Module {
	return &Module{
		run:      run,
		rulesDir: rulesDir,
		confPath: confPath,
	}
}

// HardboxRulesContent exposes the hardened rules string for test assertions.
func HardboxRulesContent() string { return hardboxRulesContent() }
