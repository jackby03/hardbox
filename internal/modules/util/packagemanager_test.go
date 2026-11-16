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

package util_test

import (
	"errors"
	"reflect"
	"testing"

	"github.com/hardbox-io/hardbox/internal/distro"
	"github.com/hardbox-io/hardbox/internal/modules/util"
)

// fakePath returns a lookPath implementation answering only for the given
// binaries.
func fakePath(present ...string) func(string) (string, error) {
	return func(name string) (string, error) {
		for _, p := range present {
			if p == name {
				return "/usr/bin/" + name, nil
			}
		}
		return "", errors.New("not found")
	}
}

func TestResolvePackageManager(t *testing.T) {
	cases := []struct {
		name    string
		family  distro.Family
		present []string
		want    string
	}{
		// The family decides, even when a manager from the other family exists
		// (a Debian host can have dnf installed for containers).
		{"debian prefers apt-get", distro.FamilyDebian, []string{"apt-get", "dnf"}, "apt-get"},
		{"rhel prefers dnf", distro.FamilyRHEL, []string{"apt-get", "dnf", "yum"}, "dnf"},
		{"rhel falls back to yum", distro.FamilyRHEL, []string{"yum"}, "yum"},
		{"debian without apt-get falls through", distro.FamilyDebian, []string{"dnf"}, "dnf"},
		{"unknown family probes", distro.FamilyUnknown, []string{"zypper"}, "zypper"},
		{"unknown family order", distro.FamilyUnknown, []string{"pacman", "apt-get"}, "apt-get"},
		{"no manager", distro.FamilyUnknown, nil, ""},
		{"rhel without dnf or yum", distro.FamilyRHEL, []string{"pacman"}, "pacman"},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := util.ResolvePackageManager(c.family, fakePath(c.present...))
			if got != c.want {
				t.Errorf("got %q, want %q", got, c.want)
			}
		})
	}
}

func TestInstallPackagesWith(t *testing.T) {
	cases := []struct {
		bin    string
		want   []string
		dryRun string
	}{
		{"apt-get", []string{"install", "-y", "aide"}, "apt-get install -y aide"},
		{"dnf", []string{"install", "-y", "aide"}, "dnf install -y aide"},
		{"yum", []string{"install", "-y", "aide"}, "yum install -y aide"},
		{"zypper", []string{"--non-interactive", "install", "aide"}, "zypper --non-interactive install aide"},
		{"pacman", []string{"-S", "--noconfirm", "aide"}, "pacman -S --noconfirm aide"},
	}

	for _, c := range cases {
		t.Run(c.bin, func(t *testing.T) {
			cmd, err := util.InstallPackagesWith(c.bin, "aide")
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if cmd.Bin != c.bin {
				t.Errorf("bin = %q, want %q", cmd.Bin, c.bin)
			}
			if !reflect.DeepEqual(cmd.Args, c.want) {
				t.Errorf("args = %v, want %v", cmd.Args, c.want)
			}
			if cmd.DryRun != c.dryRun {
				t.Errorf("dry run = %q, want %q", cmd.DryRun, c.dryRun)
			}
		})
	}
}

func TestRemovePackagesWith(t *testing.T) {
	cmd, err := util.RemovePackagesWith("apt-get", "aide")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !reflect.DeepEqual(cmd.Args, []string{"remove", "-y", "aide"}) {
		t.Errorf("args = %v", cmd.Args)
	}

	if _, err := util.RemovePackagesWith("no-such-manager", "aide"); !errors.Is(err, util.ErrNoPackageManager) {
		t.Errorf("expected ErrNoPackageManager, got %v", err)
	}
}

// TestInstallPackagesWith_UnknownManager guards the callers that must surface a
// host with no usable package manager instead of silently doing nothing.
func TestInstallPackagesWith_UnknownManager(t *testing.T) {
	if _, err := util.InstallPackagesWith("", "aide"); !errors.Is(err, util.ErrNoPackageManager) {
		t.Fatalf("expected ErrNoPackageManager, got %v", err)
	}
}

func TestPackageNameForFamily(t *testing.T) {
	if got := util.PackageNameForFamily(distro.FamilyDebian, "acct", "psacct"); got != "acct" {
		t.Errorf("debian: got %q", got)
	}
	if got := util.PackageNameForFamily(distro.FamilyRHEL, "acct", "psacct"); got != "psacct" {
		t.Errorf("rhel: got %q", got)
	}
	if got := util.PackageNameForFamily(distro.FamilyUnknown, "acct", "psacct"); got != "acct" {
		t.Errorf("unknown should use the Debian name, got %q", got)
	}
}
