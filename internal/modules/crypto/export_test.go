package crypto

import "github.com/hardbox-io/hardbox/internal/distro"

// NewModuleForTest creates a module instance with injectable file paths and distro detector.
func NewModuleForTest(
	detect distroDetector,
	cryptoPolicyPath, opensslConfPath, fipsEnabledPath, systemGPGConf, userGPGConf, homeDir string,
) *Module {
	return &Module{
		detectDistro:     detect,
		cryptoPolicyPath: cryptoPolicyPath,
		opensslConfPath:  opensslConfPath,
		fipsEnabledPath:  fipsEnabledPath,
		systemGPGConf:    systemGPGConf,
		userGPGConf:      userGPGConf,
		homeDir:          homeDir,
	}
}

var (
	PolicyIsDefaultOrStronger = policyIsDefaultOrStronger
	ParseOpenSSLMinProtocol   = parseOpenSSLMinProtocol
	ParseOpenSSLCipherString  = parseOpenSSLCipherString
	GPGUsesLongKeyID          = gpgUsesLongKeyID
)

func FakeDistroDebian() (*distro.Info, error) {
	return &distro.Info{ID: "debian", Family: distro.FamilyDebian}, nil
}

func FakeDistroRHEL() (*distro.Info, error) {
	return &distro.Info{ID: "rhel", Family: distro.FamilyRHEL}, nil
}

var ParseOpenSSLSecLevel = parseOpenSSLSecLevel
