package engine

import (
	"testing"
)

// TestRegisteredModules_ContainsSSH verifies that the SSH module is present in
// the built-in registry so that audit and apply flows include SSH checks.
func TestRegisteredModules_ContainsSSH(t *testing.T) {
	mods := registeredModules()
	for _, m := range mods {
		if m.Name() == "ssh" {
			return
		}
	}
	t.Fatal("ssh module is not registered in registeredModules(); add &ssh.Module{} to registry.go")
}

// TestRegisteredModules_NoDuplicates ensures no module name appears more than once.
func TestRegisteredModules_NoDuplicates(t *testing.T) {
	seen := make(map[string]bool)
	for _, m := range registeredModules() {
		if seen[m.Name()] {
			t.Errorf("duplicate module name %q in registeredModules()", m.Name())
		}
		seen[m.Name()] = true
	}
}
