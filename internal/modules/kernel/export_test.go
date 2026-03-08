// export_test.go exposes internal fields for package-external tests only.
package kernel

// NewModuleWithProcBase returns a Module with a custom procBase for testing.
func NewModuleWithProcBase(procBase string) *Module {
	return &Module{procBase: procBase}
}
