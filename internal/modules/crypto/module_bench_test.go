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
