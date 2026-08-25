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
package users

import (
	"context"
	"path/filepath"
	"testing"
)

func BenchmarkAudit(b *testing.B) {
	tdPath := func(elem ...string) string {
		return filepath.Join(append([]string{"testdata"}, elem...)...)
	}
	m := &Module{
		loginDefs:   tdPath("login_defs_hardened"),
		pamDir:      tdPath("pam_hardened"),
		passwdFile:  tdPath("passwd_clean"),
		sudoers:     tdPath("sudoers_compliant"),
		sudoersDir:  tdPath("nonexistent_sudoers_d"),
		useraddConf: tdPath("default_useradd_hardened"),
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = m.Audit(context.Background(), nil)
	}
}

func BenchmarkParsePasswdFile(b *testing.B) {
	path := filepath.Join("testdata", "passwd_clean")
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = parsePasswdFile(path)
	}
}
