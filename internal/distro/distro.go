// Package distro detects the Linux distribution and version at runtime.
// It reads /etc/os-release (primary source) and falls back to
// /etc/lsb-release and /etc/redhat-release for older systems.
package distro

import (
	"bufio"
	"fmt"
	"os"
	"strings"
)

// Family groups distributions by package manager / init ecosystem.
type Family string

const (
	FamilyDebian  Family = "debian" // Ubuntu, Debian, Mint, …
	FamilyRHEL    Family = "rhel"   // RHEL, CentOS, Rocky, AlmaLinux, Fedora, Amazon Linux, …
	FamilyUnknown Family = "unknown"
)

// Info holds the parsed distribution metadata.
type Info struct {
	// ID is the lowercase distro identifier (e.g. "ubuntu", "debian", "rhel",
	// "rocky", "amzn", "fedora").
	ID string

	// VersionID is the numeric release string (e.g. "22.04", "9", "2023").
	VersionID string

	// PrettyName is the human-readable description from os-release.
	PrettyName string

	// Family classifies the distro as "debian" or "rhel".
	Family Family
}

// Detect identifies the host Linux distribution by reading release files.
// It never executes external binaries; it only reads from the filesystem.
func Detect() (*Info, error) {
	return detectFromPaths(
		"/etc/os-release",
		"/etc/lsb-release",
		"/etc/redhat-release",
	)
}

// detectFromPaths is the internal implementation — it accepts explicit paths so
// tests can inject fixture files without touching the real filesystem.
func detectFromPaths(osRelease, lsbRelease, redhatRelease string) (*Info, error) {
	// 1. Primary: /etc/os-release (systemd standard, available on all modern distros)
	if fields, err := parseKeyValueFile(osRelease); err == nil {
		return buildFromOsRelease(fields), nil
	}

	// 2. Fallback: /etc/lsb-release (Ubuntu legacy, some Debian versions)
	if fields, err := parseKeyValueFile(lsbRelease); err == nil {
		return buildFromLsbRelease(fields), nil
	}

	// 3. Fallback: /etc/redhat-release (RHEL 5/6, CentOS 6 — plain text)
	if content, err := os.ReadFile(redhatRelease); err == nil {
		return buildFromRedhatRelease(string(content)), nil
	}

	return nil, fmt.Errorf("distro: unable to detect distribution — no release file found")
}

// parseKeyValueFile parses a KEY="value" or KEY=value file into a map.
// Lines starting with '#' are ignored.
func parseKeyValueFile(path string) (map[string]string, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	fields := make(map[string]string)
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		k, v, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		// Strip surrounding quotes (" or ')
		v = strings.Trim(v, `"'`)
		fields[strings.TrimSpace(k)] = v
	}
	return fields, scanner.Err()
}

func buildFromOsRelease(f map[string]string) *Info {
	info := &Info{
		ID:         strings.ToLower(f["ID"]),
		VersionID:  f["VERSION_ID"],
		PrettyName: f["PRETTY_NAME"],
	}
	// Some distros set ID_LIKE for the parent family (e.g. "ubuntu" → "debian")
	idLike := strings.ToLower(f["ID_LIKE"])
	info.Family = resolveFamily(info.ID, idLike)
	return info
}

func buildFromLsbRelease(f map[string]string) *Info {
	id := strings.ToLower(f["DISTRIB_ID"])
	info := &Info{
		ID:         id,
		VersionID:  f["DISTRIB_RELEASE"],
		PrettyName: f["DISTRIB_DESCRIPTION"],
		Family:     resolveFamily(id, ""),
	}
	return info
}

func buildFromRedhatRelease(content string) *Info {
	// e.g. "Red Hat Enterprise Linux Server release 6.10 (Santiago)"
	line := strings.TrimSpace(content)
	info := &Info{
		PrettyName: line,
		Family:     FamilyRHEL,
	}
	lower := strings.ToLower(line)
	switch {
	case strings.Contains(lower, "centos"):
		info.ID = "centos"
	case strings.Contains(lower, "red hat"):
		info.ID = "rhel"
	case strings.Contains(lower, "fedora"):
		info.ID = "fedora"
	default:
		info.ID = "rhel"
	}
	// Best-effort version extraction: "release X.Y"
	if idx := strings.Index(lower, "release "); idx != -1 {
		rest := line[idx+len("release "):]
		parts := strings.Fields(rest)
		if len(parts) > 0 {
			info.VersionID = parts[0]
		}
	}
	return info
}

// resolveFamily classifies the distribution into a Family value.
func resolveFamily(id, idLike string) Family {
	debianIDs := []string{"debian", "ubuntu", "linuxmint", "mint", "pop", "elementary", "kali", "raspbian", "mx"}
	rhelIDs := []string{"rhel", "centos", "fedora", "rocky", "alma", "almalinux", "amzn", "ol", "scientific", "oracle"}

	check := func(s string, list []string) bool {
		for _, v := range list {
			if strings.Contains(s, v) {
				return true
			}
		}
		return false
	}

	if check(id, debianIDs) || check(idLike, debianIDs) {
		return FamilyDebian
	}
	if check(id, rhelIDs) || check(idLike, rhelIDs) {
		return FamilyRHEL
	}
	return FamilyUnknown
}
