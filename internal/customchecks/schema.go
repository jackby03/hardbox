// Copyright (C) 2024 Jack (jackby03)
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published
// by the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU Affero General Public License for more details.
//
// You should have received a copy of the GNU Affero General Public License
// along with this program. If not, see <https://www.gnu.org/licenses/>.

// Package customchecks loads operator-defined hardening checks from YAML.
//
// The point of the package is that an operator with a compliance rule but no Go
// toolchain can express and remediate it. Assertions are therefore declarative:
// file expectations and sysctl values, never a shell command. A check file is
// written by someone who already has root, but turning a config file into
// arbitrary code execution is a class of bug worth designing out rather than
// documenting away.
package customchecks

import (
	"fmt"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"gopkg.in/yaml.v3"

	"github.com/hardbox-io/hardbox/internal/modules"
)

// File is one YAML document on disk.
type File struct {
	Version string  `yaml:"version"`
	Checks  []Check `yaml:"checks"`
}

// Check is a single operator-defined check.
type Check struct {
	ID          string          `yaml:"id"`
	Title       string          `yaml:"title"`
	Description string          `yaml:"description"`
	Remediation string          `yaml:"remediation"`
	Severity    string          `yaml:"severity"`
	Compliance  []ComplianceRef `yaml:"compliance"`
	// AuditOnly marks a check hardbox will report but never fix. Required when
	// the check cannot be remediated declaratively.
	AuditOnly bool         `yaml:"audit_only"`
	Assert    Assertion    `yaml:"assert"`
	Remediate *Remediation `yaml:"remediate"`
}

// ComplianceRef maps a check to a control, same shape as the built-in checks.
type ComplianceRef struct {
	Framework string `yaml:"framework"`
	Control   string `yaml:"control"`
}

// Assertion is what the check verifies. Exactly one target may be set.
type Assertion struct {
	File   *FileAssertion   `yaml:"file"`
	Sysctl *SysctlAssertion `yaml:"sysctl"`
}

// FileAssertion describes the expected state of a file. Every field is optional;
// a check must set at least one.
type FileAssertion struct {
	Path        string `yaml:"path"`
	Exists      *bool  `yaml:"exists"`
	Contains    string `yaml:"contains"`
	NotContains string `yaml:"not_contains"`
	Equals      string `yaml:"equals"`
	Mode        string `yaml:"mode"`
	Owner       string `yaml:"owner"`
}

// SysctlAssertion describes the expected value of a kernel parameter.
type SysctlAssertion struct {
	Key    string `yaml:"key"`
	Equals string `yaml:"equals"`
}

// Remediation is how hardbox fixes the check. v1 supports writing a file.
type Remediation struct {
	Write *WriteRemediation `yaml:"write"`
}

// WriteRemediation writes Content to Path.
type WriteRemediation struct {
	Path    string `yaml:"path"`
	Content string `yaml:"content"`
	Mode    string `yaml:"mode"`
}

var (
	idPattern = regexp.MustCompile(`^([a-z][a-z0-9]{1,11})-[0-9]{3}$`)

	// builtinPrefixes are used by the shipped modules. A custom check must not
	// reuse one: the report groups findings by the prefix of the check ID, so a
	// collision would merge custom findings into a built-in module's section and
	// corrupt its score.
	builtinPrefixes = map[string]bool{
		"fs": true, "ssh": true, "kn": true, "km": true, "usr": true, "aud": true,
		"svc": true, "net": true, "ntp": true, "upd": true, "log": true, "mac": true,
		"cnt": true, "cry": true, "boot": true, "mnt": true, "stg": true, "int": true,
		"mal": true, "shl": true, "prc": true, "db": true, "web": true, "dns": true,
	}

	validSeverities = map[string]modules.Severity{
		"low":      modules.SeverityLow,
		"medium":   modules.SeverityMedium,
		"high":     modules.SeverityHigh,
		"critical": modules.SeverityCritical,
	}
)

// Load reads every *.yaml file in dir. A missing directory is not an error: it
// means the operator has no custom checks, which is the default.
func Load(dir string) ([]Check, error) {
	if dir == "" {
		return nil, nil
	}
	entries, err := os.ReadDir(dir)
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("reading custom check dir %s: %w", dir, err)
	}

	var paths []string
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		switch strings.ToLower(filepath.Ext(e.Name())) {
		case ".yaml", ".yml":
			paths = append(paths, filepath.Join(dir, e.Name()))
		}
	}
	sort.Strings(paths)

	var all []Check
	seen := make(map[string]string)
	for _, path := range paths {
		data, readErr := os.ReadFile(path)
		if readErr != nil {
			return nil, fmt.Errorf("reading %s: %w", path, readErr)
		}
		var file File
		if err := yaml.Unmarshal(data, &file); err != nil {
			return nil, fmt.Errorf("%s: %w", path, err)
		}
		if file.Version != "1" {
			return nil, fmt.Errorf("%s: unsupported version %q, want \"1\"", path, file.Version)
		}
		if len(file.Checks) == 0 {
			return nil, fmt.Errorf("%s: no checks defined", path)
		}
		for i := range file.Checks {
			if err := Validate(&file.Checks[i]); err != nil {
				return nil, fmt.Errorf("%s: %w", path, err)
			}
			c := file.Checks[i]
			if prev, dup := seen[c.ID]; dup {
				return nil, fmt.Errorf("%s: duplicate check id %q, already defined in %s", path, c.ID, prev)
			}
			seen[c.ID] = path
			all = append(all, c)
		}
	}
	return all, nil
}

// Validate rejects a check that cannot be evaluated or remediated safely.
func Validate(c *Check) error {
	if !idPattern.MatchString(c.ID) {
		return fmt.Errorf("check id %q must look like <prefix>-NNN with a lowercase prefix", c.ID)
	}
	prefix := c.ID[:strings.IndexByte(c.ID, '-')]
	if builtinPrefixes[prefix] {
		return fmt.Errorf("check id %q reuses the built-in prefix %q; pick a distinct one", c.ID, prefix)
	}
	if strings.TrimSpace(c.Title) == "" {
		return fmt.Errorf("%s: title is required", c.ID)
	}
	if _, ok := validSeverities[strings.ToLower(c.Severity)]; !ok {
		return fmt.Errorf("%s: severity %q must be one of low, medium, high, critical", c.ID, c.Severity)
	}
	for _, ref := range c.Compliance {
		if strings.TrimSpace(ref.Framework) == "" || strings.TrimSpace(ref.Control) == "" {
			return fmt.Errorf("%s: compliance entries need both framework and control", c.ID)
		}
	}

	hasFile, hasSysctl := c.Assert.File != nil, c.Assert.Sysctl != nil
	switch {
	case hasFile && hasSysctl:
		return fmt.Errorf("%s: assert must set either file or sysctl, not both", c.ID)
	case hasFile:
		if err := validateFileAssertion(c.ID, c.Assert.File); err != nil {
			return err
		}
	case hasSysctl:
		if c.Assert.Sysctl.Key == "" || c.Assert.Sysctl.Equals == "" {
			return fmt.Errorf("%s: sysctl assertion needs key and equals", c.ID)
		}
	default:
		return fmt.Errorf("%s: assert must set file or sysctl", c.ID)
	}

	if c.AuditOnly {
		return nil
	}
	if c.Remediate == nil || c.Remediate.Write == nil {
		return fmt.Errorf("%s: a remediable check needs remediate.write, or set audit_only: true", c.ID)
	}
	if hasSysctl {
		return fmt.Errorf("%s: sysctl checks are audit-only in this version; set audit_only: true", c.ID)
	}
	w := c.Remediate.Write
	if !path.IsAbs(w.Path) {
		return fmt.Errorf("%s: remediate.write.path must be absolute", c.ID)
	}
	if w.Path != c.Assert.File.Path {
		return fmt.Errorf("%s: remediate.write.path must match assert.file.path", c.ID)
	}
	if _, err := ParseMode(w.Mode); err != nil {
		return fmt.Errorf("%s: remediate.write.mode: %w", c.ID, err)
	}
	return nil
}

func validateFileAssertion(id string, f *FileAssertion) error {
	if !path.IsAbs(f.Path) {
		return fmt.Errorf("%s: assert.file.path must be absolute", id)
	}
	if f.Exists == nil && f.Contains == "" && f.NotContains == "" && f.Equals == "" &&
		f.Mode == "" && f.Owner == "" {
		return fmt.Errorf("%s: assert.file needs at least one expectation", id)
	}
	if _, err := ParseMode(f.Mode); err != nil {
		return fmt.Errorf("%s: assert.file.mode: %w", id, err)
	}
	return nil
}

// ParseMode converts "0644" to an os.FileMode. An empty string yields 0, which
// callers treat as "not asserted".
func ParseMode(s string) (os.FileMode, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return 0, nil
	}
	v, err := strconv.ParseUint(s, 8, 32)
	if err != nil {
		return 0, fmt.Errorf("%q is not an octal mode", s)
	}
	return os.FileMode(v), nil
}

// severity maps the YAML string to the module enum.
func (c *Check) severity() modules.Severity {
	return validSeverities[strings.ToLower(c.Severity)]
}

// toCheck converts the loaded definition into the engine's Check type.
func (c *Check) toCheck() modules.Check {
	refs := make([]modules.ComplianceRef, 0, len(c.Compliance))
	for _, r := range c.Compliance {
		refs = append(refs, modules.ComplianceRef{Framework: r.Framework, Control: r.Control})
	}
	return modules.Check{
		ID:          c.ID,
		Title:       c.Title,
		Description: c.Description,
		Remediation: c.Remediation,
		Severity:    c.severity(),
		Compliance:  refs,
	}
}
