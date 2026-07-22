package shells

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/hardbox-io/hardbox/internal/modules"
)

type Module struct{}

func (m *Module) Name() string { return "shells" }
func (m *Module) Version() string { return "1.0" }

func (m *Module) Audit(ctx context.Context, _ modules.ModuleConfig) ([]modules.Finding, error) {
	var f []modules.Finding
	f = append(f, m.checkTMOUT())
	f = append(f, m.checkHISTSIZE())
	f = append(f, m.checkBashRC())
	f = append(f, m.checkShellPerms())
	f = append(f, m.checkHISTFILESIZE())
	return f, nil
}

func (m *Module) Plan(ctx context.Context, cfg modules.ModuleConfig) ([]modules.Change, error) {
	findings, _ := m.Audit(ctx, cfg)
	var c []modules.Change
	for _, f := range findings {
		if f.IsCompliant() || f.Status == modules.StatusSkipped { continue }
		if f.Check.ID == "shl-001" || f.Check.ID == "shl-003" {
			c = append(c, modules.Change{
				Description: "Shells: set TMOUT=900 in /etc/profile.d/timeout.sh",
				DryRunOutput: "  echo 'TMOUT=900' >> /etc/profile.d/timeout.sh",
				Apply: func() error {
					return os.WriteFile("/etc/profile.d/timeout.sh", []byte("TMOUT=900\nexport TMOUT\nreadonly TMOUT\n"), 0o644)
				},
				Revert: func() error { os.Remove("/etc/profile.d/timeout.sh"); return nil },
			})
			break
		}
	}
	return c, nil
}

func (m *Module) checkTMOUT() modules.Finding {
	chk := checkSHL001()
	for _, p := range []string{"/etc/profile.d/timeout.sh", "/etc/profile.d/autologout.sh"} {
		if d, err := os.ReadFile(p); err == nil && strings.Contains(string(d), "TMOUT=") {
			return modules.Finding{Check: chk, Status: modules.StatusCompliant, Current: p, Target: "TMOUT set"}
		}
	}
	return modules.Finding{Check: chk, Status: modules.StatusNonCompliant, Current: "not set", Target: "TMOUT=900"}
}

func (m *Module) checkHISTSIZE() modules.Finding {
	chk := checkSHL002()
	data, _ := os.ReadFile("/etc/profile")
	for _, line := range strings.Split(string(data), "\n") {
		if strings.Contains(line, "HISTSIZE=") {
			return modules.Finding{Check: chk, Status: modules.StatusCompliant, Current: strings.TrimSpace(line)}
		}
	}
	return modules.Finding{Check: chk, Status: modules.StatusNonCompliant, Current: "not set", Target: "HISTSIZE<=2000"}
}

func (m *Module) checkBashRC() modules.Finding {
	chk := checkSHL003()
	data, _ := os.ReadFile("/etc/bash.bashrc")
	if strings.Contains(string(data), "TMOUT") {
		return modules.Finding{Check: chk, Status: modules.StatusCompliant}
	}
	return modules.Finding{Check: chk, Status: modules.StatusNonCompliant, Current: "not set", Target: "TMOUT set"}
}

func (m *Module) checkShellPerms() modules.Finding {
	chk := checkSHL004()
	var bad []string
	for _, fn := range []string{".bashrc", ".bash_profile", ".profile"} {
		home, _ := os.UserHomeDir()
		info, err := os.Stat(filepath.Join(home, fn))
		if err != nil { continue }
		if info.Mode().Perm()&0o022 != 0 {
			bad = append(bad, fn)
		}
	}
	if len(bad) > 0 {
		return modules.Finding{Check: chk, Status: modules.StatusNonCompliant, Current: fmt.Sprintf("%v world-writable", bad), Target: "not world-writable"}
	}
	return modules.Finding{Check: chk, Status: modules.StatusCompliant}
}

func (m *Module) checkHISTFILESIZE() modules.Finding {
	chk := checkSHL005()
	data, _ := os.ReadFile("/etc/profile")
	for _, line := range strings.Split(string(data), "\n") {
		if strings.Contains(line, "HISTFILESIZE=") {
			return modules.Finding{Check: chk, Status: modules.StatusCompliant, Current: strings.TrimSpace(line)}
		}
	}
	return modules.Finding{Check: chk, Status: modules.StatusNonCompliant, Current: "not set", Target: "HISTFILESIZE<=2000"}
}
