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
package crypto

import (
	"testing"
)

func BenchmarkParseOpenSSLMinProtocol(b *testing.B) {
	content := `
# Some openssl conf
[system_default_sect]
MinProtocol = TLSv1.2
CipherString = DEFAULT@SECLEVEL=2
`
	for i := 0; i < b.N; i++ {
		parseOpenSSLMinProtocol(content)
	}
}

func BenchmarkParseOpenSSLSecLevel(b *testing.B) {
	content := `
# Some openssl conf
[system_default_sect]
MinProtocol = TLSv1.2
CipherString = DEFAULT@SECLEVEL=2
`
	for i := 0; i < b.N; i++ {
		parseOpenSSLSecLevel(content)
	}
}

func BenchmarkParseOpenSSLCipherString(b *testing.B) {
	content := `
# Some openssl conf
[system_default_sect]
MinProtocol = TLSv1.2
CipherString = DEFAULT@SECLEVEL=2
`
	for i := 0; i < b.N; i++ {
		parseOpenSSLCipherString(content)
	}
}

