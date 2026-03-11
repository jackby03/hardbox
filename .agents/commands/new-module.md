---
name: new-module
description: Scaffold a new hardbox hardening module with the required file structure. Use when the user wants to add a new check domain (e.g. firewall, kernel, auditd).
input: module_name
---

## Task

Create the boilerplate directory and files for a new hardening module named `<module_name>` under `internal/modules/<module_name>/`.

## Steps

1. Create the directory `internal/modules/<module_name>/`.
2. Create `internal/modules/<module_name>/module.go` with:
   - Package declaration: `package <module_name>`
   - A `Module` struct implementing the engine's `Module` interface
   - A `New()` constructor returning `*Module`
   - Stub implementations for all interface methods (`Name()`, `Description()`, `Run()`)
   - A `zerolog` logger field initialized in `New()`
   - `// TODO:` comments inside `Run()` indicating where checks should be implemented
3. Create `internal/modules/<module_name>/module_test.go` with:
   - A table-driven test skeleton for the module
   - At least one placeholder test case
4. After scaffolding, print the list of created files and remind the user to:
   - Register the module in `internal/engine/registry.go`
   - Add documentation to `docs/MODULES.md`

## Constraints

- Use the atomic write pattern from `internal/engine/snapshot.go` for any file operations inside `Run()`
- Use `zerolog` for all logging — never `fmt.Print*`
- Follow the naming conventions in `.agents/context/project.md`
