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
package hardbox

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"strconv"
	"strings"

	"github.com/hashicorp/terraform-plugin-log/tflog"
)

// Install downloads and installs the hardbox binary on the remote host.
// Returns the installed version string.
func Install(ctx context.Context, conn *SSHClient, version string) (string, error) {
	// Resolve "latest" to a concrete tag.
	if version == "latest" {
		resolved, err := resolveLatestVersion()
		if err != nil {
			return "", fmt.Errorf("resolve latest hardbox version: %w", err)
		}
		version = resolved
		tflog.Debug(ctx, "Resolved latest hardbox version", map[string]any{"version": version})
	}

	// Check if already installed at the correct version.
	existingOut, _ := conn.Run("hardbox version --short 2>/dev/null || true")
	if strings.Contains(existingOut, version) {
		tflog.Debug(ctx, "hardbox already at target version — skipping install", map[string]any{"version": version})
		return version, nil
	}

	// Detect remote architecture.
	archOut, err := conn.Run("uname -m")
	if err != nil {
		return "", fmt.Errorf("detect remote architecture: %w", err)
	}
	goarch, ok := map[string]string{
		"x86_64":  "amd64",
		"aarch64": "arm64",
	}[strings.TrimSpace(archOut)]
	if !ok {
		return "", fmt.Errorf("unsupported architecture: %s", archOut)
	}

	binaryName := fmt.Sprintf("hardbox_Linux_%s", goarch)
	versionTag := strings.TrimPrefix(version, "v")
	checksumFile := fmt.Sprintf("hardbox_%s_checksums.txt", versionTag)
	baseURL := fmt.Sprintf("https://github.com/jackby03/hardbox/releases/download/%s", version)

	installScript := fmt.Sprintf(`
set -euo pipefail
mkdir -p /var/lib/hardbox/reports
curl -fsSL "%s/%s" -o /tmp/hb_binary
curl -fsSL "%s/%s" -o /tmp/hb_checksums

EXPECTED=$(grep "%s" /tmp/hb_checksums | awk '{print $1}')
ACTUAL=$(sha256sum /tmp/hb_binary | awk '{print $1}')
if [ "$EXPECTED" != "$ACTUAL" ]; then
  echo "Checksum mismatch: expected=$EXPECTED actual=$ACTUAL" >&2
  exit 1
fi

install -m 0755 /tmp/hb_binary /usr/local/bin/hardbox
rm -f /tmp/hb_binary /tmp/hb_checksums
hardbox version
`, baseURL, binaryName, baseURL, checksumFile, binaryName)

	out, err := conn.Run(installScript)
	if err != nil {
		return "", fmt.Errorf("install hardbox %s: %w\nOutput: %s", version, err, out)
	}

	// Extract version from output.
	installed := strings.TrimSpace(out)
	return installed, nil
}

// resolveLatestVersion queries the GitHub API for the latest hardbox release tag.
func resolveLatestVersion() (string, error) {
	resp, err := http.Get("https://api.github.com/repos/jackby03/hardbox/releases/latest") //nolint:noctx
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}

	var release struct {
		TagName string `json:"tag_name"`
	}
	if err := json.Unmarshal(body, &release); err != nil {
		return "", err
	}
	if release.TagName == "" {
		return "", fmt.Errorf("empty tag_name in GitHub API response")
	}
	return release.TagName, nil
}

// ParseFindings extracts severity counts from a hardbox JSON report.
// Returns a map of {"critical": "N", "high": "N", "medium": "N", "low": "N", "info": "N"}.
// Non-JSON report formats return an empty map.
func ParseFindings(reportContent, format string) map[string]string {
	result := map[string]string{
		"critical": "0",
		"high":     "0",
		"medium":   "0",
		"low":      "0",
		"info":     "0",
	}

	if format != "json" || reportContent == "" {
		return result
	}

	var report struct {
		Summary struct {
			Critical int `json:"critical"`
			High     int `json:"high"`
			Medium   int `json:"medium"`
			Low      int `json:"low"`
			Info     int `json:"info"`
		} `json:"summary"`
	}

	// Attempt to find the summary block anywhere in the JSON.
	re := regexp.MustCompile(`"summary"\s*:\s*\{[^}]+\}`)
	match := re.FindString(reportContent)
	if match == "" {
		return result
	}

	wrapped := fmt.Sprintf(`{%s}`, match)
	if err := json.Unmarshal([]byte(wrapped), &report); err != nil {
		return result
	}

	result["critical"] = strconv.Itoa(report.Summary.Critical)
	result["high"] = strconv.Itoa(report.Summary.High)
	result["medium"] = strconv.Itoa(report.Summary.Medium)
	result["low"] = strconv.Itoa(report.Summary.Low)
	result["info"] = strconv.Itoa(report.Summary.Info)
	return result
}

