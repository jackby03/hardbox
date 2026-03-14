package services

import "context"

// NewModuleForTest creates a Module with an injected command runner for testing.
func NewModuleForTest(run func(ctx context.Context, name string, args ...string) (string, error)) *Module {
	return &Module{run: run}
}
