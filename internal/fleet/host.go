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
// Package fleet provides concurrent multi-host hardening via SSH.
package fleet

import (
	"bufio"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"
)

// Host represents a single remote target.
type Host struct {
	User string
	Addr string
	Port int
}

// String returns "user@host:port" suitable for logging.
func (h Host) String() string {
	return fmt.Sprintf("%s@%s:%d", h.User, h.Addr, h.Port)
}

// HostResult holds the outcome of a fleet operation on a single host.
type HostResult struct {
	Host     Host
	Output   string
	Err      error
	Duration time.Duration
}

// OK reports whether the host completed without error.
func (r HostResult) OK() bool {
	return r.Err == nil
}

// ParseHostsFile reads a hosts file with one entry per line in the format:
//
//	user@host:port
//	user@host        (port defaults to 22)
//
// Empty lines and lines starting with '#' are ignored.
func ParseHostsFile(path string) ([]Host, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open hosts file %s: %w", path, err)
	}
	defer f.Close()

	var hosts []Host
	scanner := bufio.NewScanner(f)
	lineNum := 0
	for scanner.Scan() {
		lineNum++
		raw := strings.TrimSpace(scanner.Text())
		if raw == "" || strings.HasPrefix(raw, "#") {
			continue
		}
		h, err := parseHostEntry(raw)
		if err != nil {
			return nil, fmt.Errorf("hosts file %s line %d: %w", path, lineNum, err)
		}
		hosts = append(hosts, h)
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("read hosts file %s: %w", path, err)
	}
	if len(hosts) == 0 {
		return nil, fmt.Errorf("hosts file %s is empty or contains only comments", path)
	}
	return hosts, nil
}

// parseHostEntry parses "user@host:port" or "user@host".
func parseHostEntry(s string) (Host, error) {
	atIdx := strings.LastIndex(s, "@")
	if atIdx < 0 {
		return Host{}, fmt.Errorf("missing '@' in %q (expected user@host or user@host:port)", s)
	}
	user := s[:atIdx]
	if user == "" {
		return Host{}, fmt.Errorf("missing user in %q", s)
	}

	rest := s[atIdx+1:]
	addr := rest
	port := 22

	if colonIdx := strings.LastIndex(rest, ":"); colonIdx >= 0 {
		portStr := rest[colonIdx+1:]
		p, err := strconv.Atoi(portStr)
		if err != nil || p < 1 || p > 65535 {
			return Host{}, fmt.Errorf("invalid port in %q", s)
		}
		addr = rest[:colonIdx]
		port = p
	}

	if addr == "" {
		return Host{}, fmt.Errorf("missing hostname in %q", s)
	}

	return Host{User: user, Addr: addr, Port: port}, nil
}

