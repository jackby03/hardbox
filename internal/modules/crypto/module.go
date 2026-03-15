package crypto

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"

	"github.com/hardbox-io/hardbox/internal/distro"
	"github.com/hardbox-io/hardbox/internal/modules"
)

const (
	defaultCryptoPolicyPath = "/etc/crypto-policies/config"
	defaultOpenSSLConfPath  = "/etc/ssl/openssl.cnf"
	defaultFIPSEnabledPath  = "/proc/sys/crypto/fips_enabled"
	defaultSystemGPGConf    = "/etc/gnupg/gpg.conf"
	defaultUserGPGConfRel   = ".gnupg/gpg.conf"
)

type distroDetector func() (*distro.Info, error)

// Module implements cryptography baseline checks for Linux hosts.
type Module struct {
	detectDistro     distroDetector
	cryptoPolicyPath string
	opensslConfPath  string
	fipsEnabledPath  string
	systemGPGConf    string
	userGPGConf      string
	homeDir          string
}

func (m *Module) Name() string    { return "crypto" }
func (m *Module) Version() string { return "0.1.0" }

func (m *Module) detector() distroDetector {
	if m.detectDistro != nil {
		return m.detectDistro
	}
	return distro.Detect
}

func (m *Module) cryptoPolicy() string {
	if m.cryptoPolicyPath != "" {
		return m.cryptoPolicyPath
	}
	return defaultCryptoPolicyPath
}

func (m *Module) opensslConf() string {
	if m.opensslConfPath != "" {
		return m.opensslConfPath
	}
	return defaultOpenSSLConfPath
}

func (m *Module) fipsPath() string {
	if m.fipsEnabledPath != "" {
		return m.fipsEnabledPath
	}
	return defaultFIPSEnabledPath
}

func (m *Module) gpgSystemPath() string {
	if m.systemGPGConf != "" {
		return m.systemGPGConf
	}
	return defaultSystemGPGConf
}

func (m *Module) gpgUserPath() string {
	if m.userGPGConf != "" {
		return m.userGPGConf
	}
	h := m.homeDir
	if h == "" {
		h = os.Getenv("HOME")
	}
	if h == "" {
		return ""
	}
	return filepath.Join(h, defaultUserGPGConfRel)
}

// Audit inspects crypto policy, TLS protocol baseline, FIPS status, and GPG key-id settings.
func (m *Module) Audit(_ context.Context, _ modules.ModuleConfig) ([]modules.Finding, error) {
	family := distro.FamilyUnknown
	if info, err := m.detector()(); err == nil && info != nil {
		family = info.Family
	}

	rhelPolicy, _ := readTrimmedIfExists(m.cryptoPolicy())
	opensslContent, _ := readStringIfExists(m.opensslConf())
	gpgContent, gpgSource := m.readGPGConfig()

	findings := make([]modules.Finding, 0, 6)
	findings = append(findings, m.auditPolicy(family, rhelPolicy, opensslContent))
	findings = append(findings, m.auditTLSMin(family, rhelPolicy, opensslContent))
	findings = append(findings, m.auditSSLv2v3(family, rhelPolicy, opensslContent))
	findings = append(findings, m.auditWeakCiphers(family, rhelPolicy, opensslContent))
	findings = append(findings, m.auditFIPS())
	findings = append(findings, m.auditGPG(gpgContent, gpgSource))

	return findings, nil
}

// Plan is intentionally read-only for crypto checks in this iteration.
func (m *Module) Plan(_ context.Context, _ modules.ModuleConfig) ([]modules.Change, error) {
	return nil, nil
}

func (m *Module) auditPolicy(family distro.Family, rhelPolicy, opensslContent string) modules.Finding {
	chk := checkCRY001()
	switch family {
	case distro.FamilyRHEL:
		if rhelPolicy == "" {
			return modules.Finding{Check: chk, Status: modules.StatusError, Current: "missing", Target: "DEFAULT/FUTURE/FIPS", Detail: "missing /etc/crypto-policies/config"}
		}
		ok := policyIsDefaultOrStronger(rhelPolicy)
		return modules.Finding{Check: chk, Status: boolStatus(ok), Current: normalizePolicy(rhelPolicy), Target: "DEFAULT/FUTURE/FIPS", Detail: "read crypto policy config"}
	case distro.FamilyDebian:
		min := parseOpenSSLMinProtocol(opensslContent)
		level := parseOpenSSLSecLevel(opensslContent)
		ok := minProtocolAtLeast12(min) && level >= 2
		return modules.Finding{Check: chk, Status: boolStatus(ok), Current: fmt.Sprintf("MinProtocol=%s SECLEVEL=%d", orUnknown(min), level), Target: "TLSv1.2+ and SECLEVEL>=2", Detail: "derived from openssl.cnf"}
	default:
		if rhelPolicy != "" {
			ok := policyIsDefaultOrStronger(rhelPolicy)
			return modules.Finding{Check: chk, Status: boolStatus(ok), Current: normalizePolicy(rhelPolicy), Target: "DEFAULT/FUTURE/FIPS", Detail: "fallback to crypto policy file"}
		}
		if opensslContent != "" {
			min := parseOpenSSLMinProtocol(opensslContent)
			ok := minProtocolAtLeast12(min)
			return modules.Finding{Check: chk, Status: boolStatus(ok), Current: fmt.Sprintf("MinProtocol=%s", orUnknown(min)), Target: "TLSv1.2+", Detail: "fallback to openssl.cnf"}
		}
		return modules.Finding{Check: chk, Status: modules.StatusError, Current: "unknown", Target: "DEFAULT or stronger", Detail: "no crypto-policy or openssl config found"}
	}
}

func (m *Module) auditTLSMin(family distro.Family, rhelPolicy, opensslContent string) modules.Finding {
	chk := checkCRY002()
	switch family {
	case distro.FamilyRHEL:
		if rhelPolicy == "" {
			return modules.Finding{Check: chk, Status: modules.StatusError, Current: "missing", Target: "TLS1.2+", Detail: "missing crypto policy"}
		}
		ok := policyDisablesLegacyTLS(rhelPolicy)
		return modules.Finding{Check: chk, Status: boolStatus(ok), Current: normalizePolicy(rhelPolicy), Target: "policy without legacy TLS"}
	default:
		min := parseOpenSSLMinProtocol(opensslContent)
		ok := minProtocolAtLeast12(min)
		return modules.Finding{Check: chk, Status: boolStatus(ok), Current: orUnknown(min), Target: "TLSv1.2 or higher", Detail: "parsed MinProtocol"}
	}
}

func (m *Module) auditSSLv2v3(family distro.Family, rhelPolicy, opensslContent string) modules.Finding {
	chk := checkCRY003()
	switch family {
	case distro.FamilyRHEL:
		if rhelPolicy == "" {
			return modules.Finding{Check: chk, Status: modules.StatusError, Current: "missing", Target: "disabled"}
		}
		ok := policyDisablesLegacyTLS(rhelPolicy)
		return modules.Finding{Check: chk, Status: boolStatus(ok), Current: normalizePolicy(rhelPolicy), Target: "SSLv2/v3 disabled"}
	default:
		min := parseOpenSSLMinProtocol(opensslContent)
		ok := minProtocolAtLeast12(min) || opensslDisablesSSLv2v3(opensslContent)
		return modules.Finding{Check: chk, Status: boolStatus(ok), Current: fmt.Sprintf("MinProtocol=%s", orUnknown(min)), Target: "SSLv2/v3 disabled"}
	}
}

func (m *Module) auditWeakCiphers(family distro.Family, rhelPolicy, opensslContent string) modules.Finding {
	chk := checkCRY004()
	switch family {
	case distro.FamilyRHEL:
		if rhelPolicy == "" {
			return modules.Finding{Check: chk, Status: modules.StatusError, Current: "missing", Target: "weak ciphers disabled"}
		}
		ok := policyDisablesWeakCiphers(rhelPolicy)
		return modules.Finding{Check: chk, Status: boolStatus(ok), Current: normalizePolicy(rhelPolicy), Target: "no RC4/DES/3DES/EXPORT"}
	default:
		cs := parseOpenSSLCipherString(opensslContent)
		ok := cipherStringHardened(cs)
		return modules.Finding{Check: chk, Status: boolStatus(ok), Current: orUnknown(cs), Target: "excludes RC4/DES/3DES/EXP", Detail: "parsed CipherString"}
	}
}

func (m *Module) auditFIPS() modules.Finding {
	chk := checkCRY005()
	v, err := readTrimmedIfExists(m.fipsPath())
	if err != nil || v == "" {
		return modules.Finding{Check: chk, Status: modules.StatusError, Current: "unreadable", Target: "0 or 1", Detail: "cannot read fips_enabled"}
	}
	if v == "1" {
		return modules.Finding{Check: chk, Status: modules.StatusCompliant, Current: "enabled", Target: "enabled when required", Detail: "fips_enabled=1"}
	}
	return modules.Finding{Check: chk, Status: modules.StatusManual, Current: "disabled", Target: "optional", Detail: "enable for regulated environments if mandated"}
}

func (m *Module) auditGPG(content, source string) modules.Finding {
	chk := checkCRY006()
	if content == "" {
		return modules.Finding{Check: chk, Status: modules.StatusNonCompliant, Current: "missing", Target: "keyid-format 0xlong", Detail: "no gpg.conf found in user or system path"}
	}
	ok := gpgUsesLongKeyID(content)
	return modules.Finding{Check: chk, Status: boolStatus(ok), Current: source, Target: "keyid-format long", Detail: "parsed gpg.conf"}
}

func (m *Module) readGPGConfig() (string, string) {
	if p := m.gpgUserPath(); p != "" {
		if content, _ := readStringIfExists(p); content != "" {
			return content, p
		}
	}
	if content, _ := readStringIfExists(m.gpgSystemPath()); content != "" {
		return content, m.gpgSystemPath()
	}
	return "", ""
}

func readStringIfExists(path string) (string, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return "", nil
		}
		return "", err
	}
	return string(b), nil
}

func readTrimmedIfExists(path string) (string, error) {
	s, err := readStringIfExists(path)
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(s), nil
}

func policyIsDefaultOrStronger(policy string) bool {
	p := normalizePolicy(policy)
	return strings.HasPrefix(p, "DEFAULT") || strings.HasPrefix(p, "FUTURE") || strings.HasPrefix(p, "FIPS")
}

func policyDisablesLegacyTLS(policy string) bool {
	return policyIsDefaultOrStronger(policy)
}

func policyDisablesWeakCiphers(policy string) bool {
	return policyIsDefaultOrStronger(policy)
}

func normalizePolicy(policy string) string {
	return strings.ToUpper(strings.TrimSpace(policy))
}

func parseOpenSSLMinProtocol(content string) string {
	m := regexp.MustCompile(`(?mi)^\s*MinProtocol\s*=\s*([^\s#;]+)`).FindStringSubmatch(content)
	if len(m) != 2 {
		return ""
	}
	return strings.TrimSpace(m[1])
}

func parseOpenSSLSecLevel(content string) int {
	m := regexp.MustCompile(`(?i)@SECLEVEL\s*=\s*([0-9]+)`).FindStringSubmatch(content)
	if len(m) != 2 {
		return 0
	}
	n, _ := strconv.Atoi(m[1])
	return n
}

func parseOpenSSLCipherString(content string) string {
	m := regexp.MustCompile(`(?mi)^\s*CipherString\s*=\s*(.+)$`).FindStringSubmatch(content)
	if len(m) != 2 {
		return ""
	}
	return strings.TrimSpace(m[1])
}

func minProtocolAtLeast12(v string) bool {
	v = strings.ToUpper(strings.TrimSpace(v))
	switch v {
	case "TLSV1.2", "TLSV1.3":
		return true
	default:
		return false
	}
}

func opensslDisablesSSLv2v3(content string) bool {
	l := strings.ToLower(content)
	hasV2 := strings.Contains(l, "-sslv2") || strings.Contains(l, "!sslv2")
	hasV3 := strings.Contains(l, "-sslv3") || strings.Contains(l, "!sslv3")
	return hasV2 && hasV3
}

func cipherStringHardened(cs string) bool {
	l := strings.ToUpper(cs)
	if l == "" {
		return false
	}
	for _, tok := range []string{"!RC4", "!DES", "!3DES", "!EXP"} {
		if !strings.Contains(l, tok) {
			return false
		}
	}
	return true
}

func gpgUsesLongKeyID(content string) bool {
	for _, line := range strings.Split(content, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		fields := strings.Fields(strings.ToLower(line))
		if len(fields) < 2 || fields[0] != "keyid-format" {
			continue
		}
		v := fields[1]
		return v == "long" || v == "0xlong"
	}
	return false
}

func boolStatus(ok bool) modules.Status {
	if ok {
		return modules.StatusCompliant
	}
	return modules.StatusNonCompliant
}

func orUnknown(v string) string {
	if strings.TrimSpace(v) == "" {
		return "unknown"
	}
	return strings.TrimSpace(v)
}
