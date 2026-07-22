package processes

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"strings"

	"github.com/hardbox-io/hardbox/internal/modules"
)

type Module struct{}

func (m *Module) Name() string { return "processes" }
func (m *Module) Version() string { return "1.0" }

func (m *Module) Audit(ctx context.Context, _ modules.ModuleConfig) ([]modules.Finding, error) {
	var f []modules.Finding
	f = append(f, m.checkAcct())
	f = append(f, m.checkCoreLimits())
	f = append(f, m.checkCoreSysctl())
	f = append(f, m.checkCoreUlimit())
	f = append(f, m.checkAcctLogrotate())
	return f, nil
}

func (m *Module) Plan(ctx context.Context, cfg modules.ModuleConfig) ([]modules.Change, error) {
	findings, _ := m.Audit(ctx, cfg)
	var c []modules.Change
	for _, f := range findings {
		if f.IsCompliant() || f.Status == modules.StatusSkipped { continue }
		switch f.Check.ID {
		case "prc-001":
			c = append(c, modules.Change{
				Description: "Processes: install and enable process accounting",
				DryRunOutput: "  apt-get install -y acct && systemctl enable --now acct",
				Apply: func() error {
					if err := exec.CommandContext(ctx, "apt-get", "install", "-y", "acct").Run(); err != nil {
						return err
					}
					return exec.CommandContext(ctx, "systemctl", "enable", "--now", "acct").Run()
				},
				Revert: func() error { return nil },
			})
		case "prc-002":
			c = append(c, modules.Change{
				Description: "Processes: disable core dumps in limits.conf",
				DryRunOutput: "  add '* hard core 0' to /etc/security/limits.conf",
				Apply: func() error {
					return m.appendLimits("* hard core 0")
				},
				Revert: func() error { return nil },
			})
		}
	}
	return c, nil
}

func (m *Module) checkAcct() modules.Finding {
	chk := checkPRC001()
	if _, err := exec.LookPath("accton"); err == nil {
		return modules.Finding{Check: chk, Status: modules.StatusCompliant}
	}
	return modules.Finding{Check: chk, Status: modules.StatusNonCompliant, Current: "not installed", Target: "acct installed"}
}

func (m *Module) checkCoreLimits() modules.Finding {
	chk := checkPRC002()
	data, err := os.ReadFile("/etc/security/limits.conf")
	if err != nil {
		return modules.Finding{Check: chk, Status: modules.StatusNonCompliant, Current: "not configured"}
	}
	if strings.Contains(string(data), "* hard core 0") || strings.Contains(string(data), "*\t\thard\tcore\t0") {
		return modules.Finding{Check: chk, Status: modules.StatusCompliant}
	}
	return modules.Finding{Check: chk, Status: modules.StatusNonCompliant, Current: "not set", Target: "* hard core 0"}
}

func (m *Module) checkCoreSysctl() modules.Finding {
	chk := checkPRC003()
	data, _ := os.ReadFile("/proc/sys/fs/suid_dumpable")
	if strings.TrimSpace(string(data)) == "0" {
		return modules.Finding{Check: chk, Status: modules.StatusCompliant, Current: "0"}
	}
	return modules.Finding{Check: chk, Status: modules.StatusNonCompliant, Current: strings.TrimSpace(string(data)), Target: "0"}
}

func (m *Module) checkCoreUlimit() modules.Finding {
	chk := checkPRC004()
	data, err := os.ReadFile("/etc/security/limits.conf")
	if err != nil {
		return modules.Finding{Check: chk, Status: modules.StatusNonCompliant}
	}
	if strings.Contains(string(data), "* soft core 0") {
		return modules.Finding{Check: chk, Status: modules.StatusCompliant}
	}
	return modules.Finding{Check: chk, Status: modules.StatusNonCompliant, Current: "not set", Target: "* soft core 0"}
}

func (m *Module) checkAcctLogrotate() modules.Finding {
	chk := checkPRC005()
	path := "/etc/logrotate.d/psacct"
	if _, err := os.Stat(path); err == nil {
		return modules.Finding{Check: chk, Status: modules.StatusCompliant, Current: path}
	}
	return modules.Finding{Check: chk, Status: modules.StatusNonCompliant, Current: "not configured", Target: "logrotate for /var/log/account"}
}

func (m *Module) appendLimits(line string) error {
	path := "/etc/security/limits.conf"
	data, _ := os.ReadFile(path)
	content := strings.TrimSpace(string(data))
	if strings.Contains(content, line) {
		return nil
	}
	content += fmt.Sprintf("\n%s\n", line)
	return os.WriteFile(path, []byte(content), 0o644)
}
