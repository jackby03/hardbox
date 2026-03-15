package firewall

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"regexp"
	"strings"

	"github.com/hardbox-io/hardbox/internal/distro"
	"github.com/hardbox-io/hardbox/internal/modules"
)

const defaultIPv6DisablePath = "/proc/sys/net/ipv6/conf/all/disable_ipv6"

type commandRunner func(ctx context.Context, name string, args ...string) (string, error)
type distroDetector func() (*distro.Info, error)
type binaryChecker func(name string) bool

type backend string

const (
	backendUFW       backend = "ufw"
	backendFirewalld backend = "firewalld"
	backendNftables  backend = "nftables"
)

type auditState struct {
	backend backend

	serviceKnown  bool
	serviceActive bool
	serviceDetail string

	inboundKnown bool
	inboundDrop  bool
	inboundValue string

	outboundKnown bool
	outboundOK    bool
	outboundValue string

	loopbackKnown   bool
	loopbackAllowed bool
	loopbackValue   string

	permissiveKnown bool
	permissiveFound bool
	permissiveValue string

	ipv6RulesKnown bool
	ipv6RulesFound bool
	ipv6Value      string
}

// Module implements firewall hardening checks for UFW, firewalld, and nftables.
type Module struct {
	run             commandRunner
	detectDistro    distroDetector
	hasBinary       binaryChecker
	backendOverride backend
	ipv6DisablePath string
}

func (m *Module) Name() string    { return "firewall" }
func (m *Module) Version() string { return "0.1.0" }

func (m *Module) runner() commandRunner {
	if m.run != nil {
		return m.run
	}
	return runCommand
}

func (m *Module) detector() distroDetector {
	if m.detectDistro != nil {
		return m.detectDistro
	}
	return distro.Detect
}

func (m *Module) binaryExists() binaryChecker {
	if m.hasBinary != nil {
		return m.hasBinary
	}
	return func(name string) bool {
		_, err := exec.LookPath(name)
		return err == nil
	}
}

func (m *Module) ipv6Path() string {
	if m.ipv6DisablePath != "" {
		return m.ipv6DisablePath
	}
	return defaultIPv6DisablePath
}

// Audit executes backend-specific parsing and returns firewall findings.
func (m *Module) Audit(ctx context.Context, _ modules.ModuleConfig) ([]modules.Finding, error) {
	selected, err := m.detectBackend()
	if err != nil {
		return m.errorFindings(err), nil
	}

	state, err := m.auditBackend(ctx, selected)
	if err != nil {
		return m.errorFindings(err), nil
	}

	ipv6Enabled := m.isIPv6Enabled()

	findings := make([]modules.Finding, 0, 6)
	findings = append(findings, m.findingService(state))
	findings = append(findings, m.findingInbound(state))
	findings = append(findings, m.findingOutbound(state))
	findings = append(findings, m.findingLoopback(state))
	findings = append(findings, m.findingPermissive(state))
	findings = append(findings, m.findingIPv6(state, ipv6Enabled))
	return findings, nil
}

// Plan is intentionally read-only for now; remediation differs heavily by backend.
func (m *Module) Plan(_ context.Context, _ modules.ModuleConfig) ([]modules.Change, error) {
	return nil, nil
}

func (m *Module) detectBackend() (backend, error) {
	if m.backendOverride != "" {
		return m.backendOverride, nil
	}
	if info, err := m.detector()(); err == nil && info != nil {
		switch info.Family {
		case distro.FamilyDebian:
			return backendUFW, nil
		case distro.FamilyRHEL:
			return backendFirewalld, nil
		}
	}

	has := m.binaryExists()
	switch {
	case has("ufw"):
		return backendUFW, nil
	case has("firewall-cmd"):
		return backendFirewalld, nil
	case has("nft"):
		return backendNftables, nil
	default:
		return "", fmt.Errorf("firewall: no supported backend detected")
	}
}

func (m *Module) auditBackend(ctx context.Context, b backend) (auditState, error) {
	switch b {
	case backendUFW:
		return m.auditUFW(ctx)
	case backendFirewalld:
		return m.auditFirewalld(ctx)
	case backendNftables:
		return m.auditNftables(ctx)
	default:
		return auditState{}, fmt.Errorf("firewall: unsupported backend %q", b)
	}
}

func (m *Module) auditUFW(ctx context.Context) (auditState, error) {
	out, err := m.runner()(ctx, "ufw", "status", "verbose")
	if err != nil && strings.TrimSpace(out) == "" {
		return auditState{}, fmt.Errorf("firewall: ufw status verbose: %w", err)
	}
	lower := strings.ToLower(out)
	inbound, outbound := parseUFWDefaults(lower)
	permissive := ufwHasSensitiveAny(lower)

	return auditState{
		backend:         backendUFW,
		serviceKnown:    true,
		serviceActive:   strings.Contains(lower, "status: active"),
		serviceDetail:   strings.TrimSpace(firstLine(out)),
		inboundKnown:    inbound != "",
		inboundDrop:     inbound == "deny" || inbound == "drop" || inbound == "reject",
		inboundValue:    inbound,
		outboundKnown:   outbound != "",
		outboundOK:      outbound == "allow" || outbound == "accept" || outbound == "deny" || outbound == "drop",
		outboundValue:   outbound,
		loopbackKnown:   true,
		loopbackAllowed: ufwHasLoopbackRule(lower),
		loopbackValue:   "parsed ufw status",
		permissiveKnown: true,
		permissiveFound: permissive,
		permissiveValue: ufwSensitiveEvidence(lower),
		ipv6RulesKnown:  true,
		ipv6RulesFound:  strings.Contains(lower, "(v6)"),
		ipv6Value:       "looked for (v6) rules",
	}, nil
}

func (m *Module) auditFirewalld(ctx context.Context) (auditState, error) {
	stateOut, stateErr := m.runner()(ctx, "firewall-cmd", "--state")
	listOut, listErr := m.runner()(ctx, "firewall-cmd", "--list-all")
	if stateErr != nil && listErr != nil {
		return auditState{}, fmt.Errorf("firewall: firewalld unavailable")
	}

	target := parseFirewalldTarget(listOut)
	permissive := firewalldHasSensitivePorts(listOut)
	loopback := firewalldHasLoopback(listOut)

	return auditState{
		backend:         backendFirewalld,
		serviceKnown:    true,
		serviceActive:   strings.Contains(strings.ToLower(stateOut), "running"),
		serviceDetail:   strings.TrimSpace(stateOut),
		inboundKnown:    target != "",
		inboundDrop:     target == "drop",
		inboundValue:    target,
		outboundKnown:   false,
		outboundOK:      false,
		outboundValue:   "zone model",
		loopbackKnown:   true,
		loopbackAllowed: loopback,
		loopbackValue:   "checked interfaces/rules for lo",
		permissiveKnown: true,
		permissiveFound: permissive,
		permissiveValue: firewalldSensitiveEvidence(listOut),
		ipv6RulesKnown:  true,
		ipv6RulesFound:  true,
		ipv6Value:       "firewalld zones apply to IPv4 and IPv6",
	}, nil
}

func (m *Module) auditNftables(ctx context.Context) (auditState, error) {
	enabledOut, _ := m.runner()(ctx, "systemctl", "is-enabled", "nftables")
	activeOut, _ := m.runner()(ctx, "systemctl", "is-active", "nftables")
	rulesetOut, err := m.runner()(ctx, "nft", "list", "ruleset")
	if err != nil && strings.TrimSpace(rulesetOut) == "" {
		return auditState{}, fmt.Errorf("firewall: nft list ruleset: %w", err)
	}

	inbound := parseNftPolicy(rulesetOut, "input")
	outbound := parseNftPolicy(rulesetOut, "output")
	permissive := nftHasSensitiveAny(rulesetOut)

	return auditState{
		backend:         backendNftables,
		serviceKnown:    true,
		serviceActive:   strings.Contains(strings.ToLower(activeOut), "active") || strings.Contains(strings.ToLower(enabledOut), "enabled"),
		serviceDetail:   strings.TrimSpace(activeOut),
		inboundKnown:    inbound != "",
		inboundDrop:     inbound == "drop",
		inboundValue:    inbound,
		outboundKnown:   outbound != "",
		outboundOK:      outbound == "accept" || outbound == "drop",
		outboundValue:   outbound,
		loopbackKnown:   true,
		loopbackAllowed: nftHasLoopbackRule(rulesetOut),
		loopbackValue:   "looked for iif lo accept",
		permissiveKnown: true,
		permissiveFound: permissive,
		permissiveValue: nftSensitiveEvidence(rulesetOut),
		ipv6RulesKnown:  true,
		ipv6RulesFound:  nftHasIPv6Rules(rulesetOut),
		ipv6Value:       "checked ip6/inet tables",
	}, nil
}

func (m *Module) findingService(s auditState) modules.Finding {
	status := modules.StatusError
	if s.serviceKnown {
		status = boolStatus(s.serviceActive)
	}
	return modules.Finding{
		Check:   checkFW001(),
		Status:  status,
		Current: fmt.Sprintf("backend=%s active=%t", s.backend, s.serviceActive),
		Target:  "service enabled and active",
		Detail:  s.serviceDetail,
	}
}

func (m *Module) findingInbound(s auditState) modules.Finding {
	if !s.inboundKnown {
		return modules.Finding{Check: checkFW002(), Status: modules.StatusManual, Current: "unknown", Target: "DROP", Detail: "could not infer inbound default policy"}
	}
	return modules.Finding{Check: checkFW002(), Status: boolStatus(s.inboundDrop), Current: s.inboundValue, Target: "drop"}
}

func (m *Module) findingOutbound(s auditState) modules.Finding {
	if !s.outboundKnown {
		return modules.Finding{Check: checkFW003(), Status: modules.StatusSkipped, Current: s.outboundValue, Target: "drop or accept", Detail: "backend does not expose global outbound default in the same way"}
	}
	return modules.Finding{Check: checkFW003(), Status: boolStatus(s.outboundOK), Current: s.outboundValue, Target: "drop or accept"}
}

func (m *Module) findingLoopback(s auditState) modules.Finding {
	if !s.loopbackKnown {
		return modules.Finding{Check: checkFW004(), Status: modules.StatusManual, Current: "unknown", Target: "loopback explicitly allowed"}
	}
	return modules.Finding{Check: checkFW004(), Status: boolStatus(s.loopbackAllowed), Current: s.loopbackValue, Target: "loopback explicitly allowed"}
}

func (m *Module) findingPermissive(s auditState) modules.Finding {
	if !s.permissiveKnown {
		return modules.Finding{Check: checkFW005(), Status: modules.StatusManual, Current: "unknown", Target: "no global sensitive port exposure"}
	}
	return modules.Finding{Check: checkFW005(), Status: boolStatus(!s.permissiveFound), Current: s.permissiveValue, Target: "no sensitive ports open to any source"}
}

func (m *Module) findingIPv6(s auditState, ipv6Enabled bool) modules.Finding {
	if !ipv6Enabled {
		return modules.Finding{Check: checkFW006(), Status: modules.StatusSkipped, Current: "ipv6 disabled", Target: "rules present when enabled", Detail: "net.ipv6.conf.all.disable_ipv6=1"}
	}
	if !s.ipv6RulesKnown {
		return modules.Finding{Check: checkFW006(), Status: modules.StatusManual, Current: "unknown", Target: "ipv6 rules present"}
	}
	return modules.Finding{Check: checkFW006(), Status: boolStatus(s.ipv6RulesFound), Current: s.ipv6Value, Target: "ipv6 rules present"}
}

func (m *Module) errorFindings(err error) []modules.Finding {
	ids := []modules.Check{checkFW001(), checkFW002(), checkFW003(), checkFW004(), checkFW005(), checkFW006()}
	out := make([]modules.Finding, 0, len(ids))
	for _, chk := range ids {
		out = append(out, modules.Finding{Check: chk, Status: modules.StatusError, Current: "unavailable", Target: "see check", Detail: err.Error()})
	}
	return out
}

func (m *Module) isIPv6Enabled() bool {
	data, err := os.ReadFile(m.ipv6Path())
	if err != nil {
		return true
	}
	return strings.TrimSpace(string(data)) != "1"
}

func boolStatus(ok bool) modules.Status {
	if ok {
		return modules.StatusCompliant
	}
	return modules.StatusNonCompliant
}

func parseUFWDefaults(out string) (string, string) {
	out = strings.ToLower(out)
	re := regexp.MustCompile(`default:\s*([a-z]+)\s*\(incoming\),\s*([a-z]+)\s*\(outgoing\)`)
	m := re.FindStringSubmatch(out)
	if len(m) != 3 {
		return "", ""
	}
	return strings.ToLower(m[1]), strings.ToLower(m[2])
}

func ufwHasLoopbackRule(out string) bool {
	re := regexp.MustCompile(`(?m)(allow|accept).*\blo\b|\blo\b.*(allow|accept)`)
	return re.MatchString(out)
}

func ufwHasSensitiveAny(out string) bool {
	re := regexp.MustCompile(`(?m)\b(22|23|3389|3306|5432|6379|27017)(/(tcp|udp))?\b.*\b(allow|accept)\b.*\b(anywhere|0\.0\.0\.0/0)\b`)
	return re.MatchString(out)
}

func ufwSensitiveEvidence(out string) string {
	if !ufwHasSensitiveAny(out) {
		return "no sensitive any-source rule found"
	}
	for _, line := range strings.Split(out, "\n") {
		l := strings.ToLower(strings.TrimSpace(line))
		if l == "" {
			continue
		}
		if regexp.MustCompile(`\b(22|23|3389|3306|5432|6379|27017)(/(tcp|udp))?\b`).MatchString(l) && strings.Contains(l, "allow") && (strings.Contains(l, "anywhere") || strings.Contains(l, "0.0.0.0/0")) {
			return line
		}
	}
	return "sensitive any-source rule found"
}

func parseFirewalldTarget(out string) string {
	re := regexp.MustCompile(`(?m)^\s*target:\s*(\S+)`)
	m := re.FindStringSubmatch(strings.ToLower(out))
	if len(m) != 2 {
		return ""
	}
	return m[1]
}

func firewalldHasLoopback(out string) bool {
	l := strings.ToLower(out)
	if regexp.MustCompile(`(?m)^\s*interfaces:\s*.*\blo\b`).MatchString(l) {
		return true
	}
	return strings.Contains(l, "127.0.0.1") || strings.Contains(l, "::1")
}

func firewalldHasSensitivePorts(out string) bool {
	re := regexp.MustCompile(`(?m)^\s*ports:\s*(.*)$`)
	m := re.FindStringSubmatch(strings.ToLower(out))
	if len(m) != 2 {
		return false
	}
	return regexp.MustCompile(`\b(22|23|3389|3306|5432|6379|27017)/(tcp|udp)\b`).MatchString(m[1])
}

func firewalldSensitiveEvidence(out string) string {
	if !firewalldHasSensitivePorts(out) {
		return "no sensitive ports line detected"
	}
	for _, line := range strings.Split(out, "\n") {
		l := strings.ToLower(strings.TrimSpace(line))
		if strings.HasPrefix(l, "ports:") {
			return strings.TrimSpace(line)
		}
	}
	return "sensitive ports exposed"
}

func parseNftPolicy(out, chain string) string {
	re := regexp.MustCompile(fmt.Sprintf(`hook\s+%s\s+priority\s+\S+;\s+policy\s+(accept|drop);`, regexp.QuoteMeta(chain)))
	m := re.FindStringSubmatch(strings.ToLower(out))
	if len(m) != 2 {
		return ""
	}
	return m[1]
}

func nftHasLoopbackRule(out string) bool {
	l := strings.ToLower(out)
	return regexp.MustCompile(`iif(name)?\s+"lo"\s+accept`).MatchString(l)
}

func nftHasSensitiveAny(out string) bool {
	l := strings.ToLower(out)
	if regexp.MustCompile(`tcp\s+dport\s+(22|23|3389|3306|5432|6379|27017)\s+accept`).MatchString(l) {
		return true
	}
	return regexp.MustCompile(`(ip|ip6)\s+saddr\s+(0\.0\.0\.0/0|::/0).*tcp\s+dport\s+(22|23|3389|3306|5432|6379|27017).*accept`).MatchString(l)
}

func nftSensitiveEvidence(out string) string {
	if !nftHasSensitiveAny(out) {
		return "no sensitive permissive nft rule found"
	}
	for _, line := range strings.Split(out, "\n") {
		l := strings.ToLower(strings.TrimSpace(line))
		if l == "" {
			continue
		}
		if regexp.MustCompile(`tcp\s+dport\s+(22|23|3389|3306|5432|6379|27017)\s+accept`).MatchString(l) {
			return line
		}
	}
	return "sensitive permissive nft rule found"
}

func nftHasIPv6Rules(out string) bool {
	l := strings.ToLower(out)
	return strings.Contains(l, "table ip6") || strings.Contains(l, "ip6 saddr") || strings.Contains(l, "nfproto ipv6")
}

func firstLine(s string) string {
	for _, line := range strings.Split(s, "\n") {
		if strings.TrimSpace(line) != "" {
			return line
		}
	}
	return ""
}

func runCommand(ctx context.Context, name string, args ...string) (string, error) {
	cmd := exec.CommandContext(ctx, name, args...)
	out, err := cmd.CombinedOutput()
	result := strings.TrimSpace(string(out))
	if err != nil {
		if result == "" {
			return "", fmt.Errorf("run %s %s: %w", name, strings.Join(args, " "), err)
		}
		return result, fmt.Errorf("run %s %s: %s", name, strings.Join(args, " "), result)
	}
	return result, nil
}
