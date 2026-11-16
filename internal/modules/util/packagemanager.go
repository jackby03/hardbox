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

package util

import (
	"errors"
	"os/exec"
	"strings"

	"github.com/hardbox-io/hardbox/internal/distro"
)

// ErrNoPackageManager means no supported package manager was found on this
// host. Callers must surface it rather than silently doing nothing: a check
// that reports a problem and then skips the fix is the defect this package
// exists to remove.
var ErrNoPackageManager = errors.New("no supported package manager found on this host")

// PackageCommand is a resolved package-manager invocation: the binary to run,
// its arguments, and the line to show an operator in --dry-run output.
type PackageCommand struct {
	Bin    string
	Args   []string
	DryRun string
}

// pkgManager describes how one package manager installs and removes packages.
type pkgManager struct {
	bin     string
	install func(pkgs []string) []string
	remove  func(pkgs []string) []string
}

var pkgManagers = map[string]pkgManager{
	"apt-get": {
		bin: "apt-get",
		install: func(p []string) []string {
			return append([]string{"install", "-y"}, p...)
		},
		remove: func(p []string) []string {
			return append([]string{"remove", "-y"}, p...)
		},
	},
	"dnf": {
		bin: "dnf",
		install: func(p []string) []string {
			return append([]string{"install", "-y"}, p...)
		},
		remove: func(p []string) []string {
			return append([]string{"remove", "-y"}, p...)
		},
	},
	"yum": {
		bin: "yum",
		install: func(p []string) []string {
			return append([]string{"install", "-y"}, p...)
		},
		remove: func(p []string) []string {
			return append([]string{"remove", "-y"}, p...)
		},
	},
	"zypper": {
		bin: "zypper",
		install: func(p []string) []string {
			return append([]string{"--non-interactive", "install"}, p...)
		},
		remove: func(p []string) []string {
			return append([]string{"--non-interactive", "remove"}, p...)
		},
	},
	"pacman": {
		bin: "pacman",
		install: func(p []string) []string {
			return append([]string{"-S", "--noconfirm"}, p...)
		},
		remove: func(p []string) []string {
			return append([]string{"-R", "--noconfirm"}, p...)
		},
	},
}

// pkgPreference is the fallback probe order used when the distro family does not
// determine the answer. Debian and RHEL are resolved by family first, so the
// order only matters on an unrecognised host.
var pkgPreference = []string{"apt-get", "dnf", "yum", "zypper", "pacman"}

// ResolvePackageManager returns the package manager binary for a distro family,
// or "" when none of the known managers is available.
//
// lookPath is injected so the resolution can be tested without the host's real
// PATH.
func ResolvePackageManager(family distro.Family, lookPath func(string) (string, error)) string {
	if lookPath == nil {
		lookPath = exec.LookPath
	}

	found := func(bin string) bool {
		_, err := lookPath(bin)
		return err == nil
	}

	switch family {
	case distro.FamilyDebian:
		if found("apt-get") {
			return "apt-get"
		}
	case distro.FamilyRHEL:
		// dnf replaced yum on RHEL 8+; Amazon Linux 2023 and Fedora ship dnf.
		for _, bin := range []string{"dnf", "yum"} {
			if found(bin) {
				return bin
			}
		}
	}

	for _, bin := range pkgPreference {
		if found(bin) {
			return bin
		}
	}
	return ""
}

// hostPackageManager resolves the manager for the running host. Detection is
// best effort: an unreadable /etc/os-release falls back to probing PATH, which
// is what makes this work in containers built from minimal images.
func hostPackageManager() string {
	family := distro.FamilyUnknown
	if info, err := distro.Detect(); err == nil && info != nil {
		family = info.Family
	}
	return ResolvePackageManager(family, exec.LookPath)
}

// HostPackageManager exposes the resolved binary for a host, or "" when none
// was found. Modules use it to decide whether they can remediate at all.
func HostPackageManager() string {
	return hostPackageManager()
}

// InstallPackages returns the command that installs pkgs with the host's
// package manager.
func InstallPackages(pkgs ...string) (PackageCommand, error) {
	return buildPackageCommand(pkgs, hostPackageManager(), false)
}

// RemovePackages returns the command that removes pkgs with the host's package
// manager.
func RemovePackages(pkgs ...string) (PackageCommand, error) {
	return buildPackageCommand(pkgs, hostPackageManager(), true)
}

// InstallPackagesWith is InstallPackages against an explicit manager, for
// modules that resolve the manager themselves (and for tests).
func InstallPackagesWith(bin string, pkgs ...string) (PackageCommand, error) {
	return buildPackageCommand(pkgs, bin, false)
}

// RemovePackagesWith is RemovePackages against an explicit manager.
func RemovePackagesWith(bin string, pkgs ...string) (PackageCommand, error) {
	return buildPackageCommand(pkgs, bin, true)
}

// HostFamily classifies the running host, falling back to unknown when
// /etc/os-release cannot be read.
func HostFamily() distro.Family {
	if info, err := distro.Detect(); err == nil && info != nil {
		return info.Family
	}
	return distro.FamilyUnknown
}

// PackageNameForFamily resolves a package whose name differs between Debian and
// RHEL family distributions, for example acct (Debian) versus psacct (RHEL).
func PackageNameForFamily(family distro.Family, debianName, rhelName string) string {
	if family == distro.FamilyRHEL {
		return rhelName
	}
	return debianName
}

// HostPackageName is PackageNameForFamily against the running host.
func HostPackageName(debianName, rhelName string) string {
	return PackageNameForFamily(HostFamily(), debianName, rhelName)
}

func buildPackageCommand(pkgs []string, bin string, remove bool) (PackageCommand, error) {
	mgr, ok := pkgManagers[bin]
	if !ok {
		return PackageCommand{}, ErrNoPackageManager
	}
	action := mgr.install
	if remove {
		action = mgr.remove
	}
	args := action(pkgs)
	return PackageCommand{
		Bin:    mgr.bin,
		Args:   args,
		DryRun: strings.TrimSpace(mgr.bin + " " + strings.Join(args, " ")),
	}, nil
}
