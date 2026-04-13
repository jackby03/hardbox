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
package containers

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/hardbox-io/hardbox/internal/modules"
)

const (
	defaultDaemonJSONPath = "/etc/docker/daemon.json"
	defaultAuditRulesDir  = "/etc/audit/rules.d"
	dockerSocket          = "/var/run/docker.sock"

	// Format strings used when calling docker inspect/info.
	securityOptsFmt = "{{range .SecurityOptions}}{{println .}}{{end}}"
	privilegedFmt   = "{{.HostConfig.Privileged}}"
	mountsFmt       = "{{range .Mounts}}{{.Source}} {{end}}"
)

type commandRunner func(ctx context.Context, name string, args ...string) (string, error)
type binaryChecker func(name string) bool

// Module implements container host hardening checks (cnt-001..cnt-010).
type Module struct {
	run            commandRunner
	hasBinary      binaryChecker
	daemonJSONPath string
	auditRulesDir  string
}

func (m *Module) Name() string    { return "containers" }
func (m *Module) Version() string { return "0.1.0" }

func (m *Module) runner() commandRunner {
	if m.run != nil {
		return m.run
	}
	return runCommand
}

func (m *Module) checker() binaryChecker {
	if m.hasBinary != nil {
		return m.hasBinary
	}
	return func(name string) bool {
		_, err := exec.LookPath(name)
		return err == nil
	}
}

func (m *Module) daemonJSON() string {
	if m.daemonJSONPath != "" {
		return m.daemonJSONPath
	}
	return defaultDaemonJSONPath
}

func (m *Module) auditDir() string {
	if m.auditRulesDir != "" {
		return m.auditRulesDir
	}
	return defaultAuditRulesDir
}

func runCommand(ctx context.Context, name string, args ...string) (string, error) {
	out, err := exec.CommandContext(ctx, name, args...).Output()
	return strings.TrimSpace(string(out)), err
}

// daemonConfig holds the relevant fields of /etc/docker/daemon.json.
type daemonConfig struct {
	ICC             *bool    `json:"icc"`
	UsernsRemap     string   `json:"userns-remap"`
	TLS             bool     `json:"tls"`
	TLSVerify       bool     `json:"tlsverify"`
	TLSCert         string   `json:"tlscert"`
	TLSKey          string   `json:"tlskey"`
	Hosts           []string `json:"hosts"`
	SeccompProfile  string   `json:"seccomp-profile"`
	NoNewPrivileges bool     `json:"no-new-privileges"`
}

// Audit runs all container hardening checks. When Docker is not installed every
// check is returned as StatusSkipped so the engine can still produce a report.
func (m *Module) Audit(ctx context.Context, _ modules.ModuleConfig) ([]modules.Finding, error) {
	if !m.checker()("docker") {
		return m.allSkipped("docker binary not found"), nil
	}

	cfg := m.readDaemonConfig()
	secOpts := m.dockerSecurityOptions(ctx)
	containerIDs := m.runningContainerIDs(ctx)

	findings := make([]modules.Finding, 0, 10)
	findings = append(findings, m.findRootless(secOpts))
	findings = append(findings, m.findICC(cfg))
	findings = append(findings, m.findUsernsRemap(cfg))
	findings = append(findings, m.findTLS(cfg))
	findings = append(findings, m.findSeccomp(secOpts))
	findings = append(findings, m.findMACProfile(secOpts))
	findings = append(findings, m.findPrivileged(ctx, containerIDs))
	findings = append(findings, m.findSocketMount(ctx, containerIDs))
	findings = append(findings, m.findImageScanning())
	findings = append(findings, m.findAuditRules())
	return findings, nil
}

// Plan is read-only for this iteration; remediation varies per container runtime.
func (m *Module) Plan(_ context.Context, _ modules.ModuleConfig) ([]modules.Change, error) {
	return nil, nil
}

// allSkipped returns StatusSkipped for every check with the given detail message.
func (m *Module) allSkipped(detail string) []modules.Finding {
	checks := []modules.Check{
		checkCNT001(), checkCNT002(), checkCNT003(), checkCNT004(), checkCNT005(),
		checkCNT006(), checkCNT007(), checkCNT008(), checkCNT009(), checkCNT010(),
	}
	out := make([]modules.Finding, len(checks))
	for i, c := range checks {
		out[i] = modules.Finding{Check: c, Status: modules.StatusSkipped, Detail: detail}
	}
	return out
}

// readDaemonConfig reads /etc/docker/daemon.json.
// Returns an empty config struct when the file is missing or unparseable.
func (m *Module) readDaemonConfig() *daemonConfig {
	data, err := os.ReadFile(m.daemonJSON())
	if err != nil {
		return &daemonConfig{}
	}
	var cfg daemonConfig
	if err := json.Unmarshal(data, &cfg); err != nil {
		return &daemonConfig{}
	}
	return &cfg
}

// dockerSecurityOptions returns security option strings from "docker info".
func (m *Module) dockerSecurityOptions(ctx context.Context) []string {
	out, err := m.runner()(ctx, "docker", "info", "--format", securityOptsFmt)
	if err != nil || out == "" {
		return nil
	}
	var opts []string
	for _, line := range strings.Split(out, "\n") {
		if line = strings.TrimSpace(strings.ToLower(line)); line != "" {
			opts = append(opts, line)
		}
	}
	return opts
}

// runningContainerIDs returns IDs of currently running containers.
func (m *Module) runningContainerIDs(ctx context.Context) []string {
	out, err := m.runner()(ctx, "docker", "ps", "-q")
	if err != nil || out == "" {
		return nil
	}
	var ids []string
	for _, id := range strings.Split(out, "\n") {
		if id = strings.TrimSpace(id); id != "" {
			ids = append(ids, id)
		}
	}
	return ids
}

// hasSecOpt returns true when any option starts with the given prefix.
func hasSecOpt(opts []string, prefix string) bool {
	for _, o := range opts {
		if strings.HasPrefix(o, strings.ToLower(prefix)) {
			return true
		}
	}
	return false
}

// hasTCPHost returns true when at least one daemon host uses the tcp:// scheme.
func hasTCPHost(hosts []string) bool {
	for _, h := range hosts {
		if strings.HasPrefix(strings.ToLower(h), "tcp://") {
			return true
		}
	}
	return false
}

// findRootless checks cnt-001: Docker should run in rootless mode.
func (m *Module) findRootless(secOpts []string) modules.Finding {
	ch := checkCNT001()
	if hasSecOpt(secOpts, "name=rootless") {
		return modules.Finding{Check: ch, Status: modules.StatusCompliant, Current: "rootless", Target: "rootless"}
	}
	return modules.Finding{
		Check:   ch,
		Status:  modules.StatusNonCompliant,
		Current: "rootful",
		Target:  "rootless",
		Detail:  "Docker is running in rootful mode; consider rootless setup for a reduced attack surface.",
	}
}

// findICC checks cnt-002: icc must be explicitly false.
func (m *Module) findICC(cfg *daemonConfig) modules.Finding {
	ch := checkCNT002()
	if cfg.ICC != nil && !*cfg.ICC {
		return modules.Finding{Check: ch, Status: modules.StatusCompliant, Current: "false", Target: "false"}
	}
	cur := "true (default)"
	if cfg.ICC != nil && *cfg.ICC {
		cur = "true"
	}
	return modules.Finding{
		Check:   ch,
		Status:  modules.StatusNonCompliant,
		Current: cur,
		Target:  "false",
		Detail:  "Set \"icc\": false in /etc/docker/daemon.json to disable inter-container communication.",
	}
}

// findUsernsRemap checks cnt-003: userns-remap must be configured.
func (m *Module) findUsernsRemap(cfg *daemonConfig) modules.Finding {
	ch := checkCNT003()
	if cfg.UsernsRemap != "" {
		return modules.Finding{Check: ch, Status: modules.StatusCompliant, Current: cfg.UsernsRemap, Target: "non-empty"}
	}
	return modules.Finding{
		Check:   ch,
		Status:  modules.StatusNonCompliant,
		Current: "(not set)",
		Target:  "default",
		Detail:  "Set \"userns-remap\": \"default\" in /etc/docker/daemon.json.",
	}
}

// findTLS checks cnt-004: TLS must be enforced when a TCP host is present.
// The check is skipped when Docker is only accessible via a local socket.
func (m *Module) findTLS(cfg *daemonConfig) modules.Finding {
	ch := checkCNT004()
	if !hasTCPHost(cfg.Hosts) {
		return modules.Finding{
			Check:  ch,
			Status: modules.StatusSkipped,
			Detail: "No TCP host configured in daemon.json; TLS check not applicable.",
		}
	}
	if cfg.TLS && cfg.TLSVerify && cfg.TLSCert != "" && cfg.TLSKey != "" {
		return modules.Finding{Check: ch, Status: modules.StatusCompliant, Current: "tls+tlsverify", Target: "tls+tlsverify"}
	}
	return modules.Finding{
		Check:   ch,
		Status:  modules.StatusNonCompliant,
		Current: fmt.Sprintf("tls=%v, tlsverify=%v, cert=%q, key=%q", cfg.TLS, cfg.TLSVerify, cfg.TLSCert, cfg.TLSKey),
		Target:  "tls=true, tlsverify=true, with valid cert and key",
		Detail:  "Enable TLS mutual authentication for the exposed Docker remote API.",
	}
}

// findSeccomp checks cnt-005: default seccomp profile must be active.
func (m *Module) findSeccomp(secOpts []string) modules.Finding {
	ch := checkCNT005()
	if hasSecOpt(secOpts, "name=seccomp") {
		return modules.Finding{Check: ch, Status: modules.StatusCompliant, Current: "seccomp active", Target: "seccomp active"}
	}
	return modules.Finding{
		Check:   ch,
		Status:  modules.StatusNonCompliant,
		Current: "(seccomp not in security options)",
		Target:  "name=seccomp,profile=default",
		Detail:  "Ensure the default seccomp profile is not disabled on the Docker daemon.",
	}
}

// findMACProfile checks cnt-006: AppArmor or SELinux must be active.
func (m *Module) findMACProfile(secOpts []string) modules.Finding {
	ch := checkCNT006()
	if hasSecOpt(secOpts, "name=apparmor") || hasSecOpt(secOpts, "name=selinux") {
		return modules.Finding{Check: ch, Status: modules.StatusCompliant, Current: "mac active", Target: "apparmor|selinux"}
	}
	return modules.Finding{
		Check:   ch,
		Status:  modules.StatusNonCompliant,
		Current: "(no apparmor or selinux in security options)",
		Target:  "name=apparmor or name=selinux",
		Detail:  "Enable AppArmor (Debian/Ubuntu) or SELinux (RHEL/CentOS) on the container host.",
	}
}

// findPrivileged checks cnt-007: no running container should use --privileged.
func (m *Module) findPrivileged(ctx context.Context, ids []string) modules.Finding {
	ch := checkCNT007()
	if len(ids) == 0 {
		return modules.Finding{Check: ch, Status: modules.StatusCompliant, Detail: "No running containers found."}
	}
	var flagged []string
	run := m.runner()
	for _, id := range ids {
		out, err := run(ctx, "docker", "inspect", "--format", privilegedFmt, id)
		if err != nil {
			continue
		}
		if strings.TrimSpace(out) == "true" {
			flagged = append(flagged, id)
		}
	}
	if len(flagged) > 0 {
		return modules.Finding{
			Check:   ch,
			Status:  modules.StatusNonCompliant,
			Current: fmt.Sprintf("%d privileged container(s): %s", len(flagged), strings.Join(flagged, ", ")),
			Target:  "no privileged containers",
			Detail:  "Remove the --privileged flag from the flagged containers.",
		}
	}
	return modules.Finding{Check: ch, Status: modules.StatusCompliant, Current: "no privileged containers", Target: "no privileged containers"}
}

// findSocketMount checks cnt-008: /var/run/docker.sock must not be mounted in containers.
func (m *Module) findSocketMount(ctx context.Context, ids []string) modules.Finding {
	ch := checkCNT008()
	if len(ids) == 0 {
		return modules.Finding{Check: ch, Status: modules.StatusCompliant, Detail: "No running containers found."}
	}
	var flagged []string
	run := m.runner()
	for _, id := range ids {
		out, err := run(ctx, "docker", "inspect", "--format", mountsFmt, id)
		if err != nil {
			continue
		}
		if strings.Contains(out, dockerSocket) {
			flagged = append(flagged, id)
		}
	}
	if len(flagged) > 0 {
		return modules.Finding{
			Check:   ch,
			Status:  modules.StatusNonCompliant,
			Current: fmt.Sprintf("%d container(s) mounting docker socket: %s", len(flagged), strings.Join(flagged, ", ")),
			Target:  "no docker socket mount",
			Detail:  "Remove the /var/run/docker.sock bind-mount from the flagged containers.",
		}
	}
	return modules.Finding{Check: ch, Status: modules.StatusCompliant, Current: "no socket mounts", Target: "no docker socket mount"}
}

// findImageScanning checks cnt-009 — always advisory (manual verification required).
func (m *Module) findImageScanning() modules.Finding {
	return modules.Finding{
		Check:  checkCNT009(),
		Status: modules.StatusManual,
		Detail: "Integrate a vulnerability scanner (Trivy, Grype) into your CI/CD pipeline.",
	}
}

// findAuditRules checks cnt-010: /etc/audit/rules.d/ must reference /var/run/docker.sock.
func (m *Module) findAuditRules() modules.Finding {
	ch := checkCNT010()
	entries, err := os.ReadDir(m.auditDir())
	if err != nil {
		return modules.Finding{
			Check:  ch,
			Status: modules.StatusNonCompliant,
			Detail: fmt.Sprintf("cannot read audit rules directory: %v", err),
		}
	}
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".rules") {
			continue
		}
		data, err := os.ReadFile(filepath.Join(m.auditDir(), e.Name()))
		if err != nil {
			continue
		}
		if strings.Contains(string(data), dockerSocket) {
			return modules.Finding{
				Check:   ch,
				Status:  modules.StatusCompliant,
				Current: fmt.Sprintf("rule found in %s", e.Name()),
				Target:  "audit rule for /var/run/docker.sock",
			}
		}
	}
	return modules.Finding{
		Check:   ch,
		Status:  modules.StatusNonCompliant,
		Current: "(no audit rule for docker socket found)",
		Target:  "audit rule for /var/run/docker.sock",
		Detail:  "Add '-w /var/run/docker.sock -p rwxa -k docker' to /etc/audit/rules.d/docker.rules.",
	}
}

