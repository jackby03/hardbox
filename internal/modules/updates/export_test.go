package updates

// TestOptions configures file paths and family override for tests.
type TestOptions struct {
	Family             string
	APTSourcesList     string
	APTSourcesListDir  string
	APTAutoUpgrades    string
	APTUnattended      string
	APTTrustedGPG      string
	APTTrustedGPGDir   string
	USRShareKeyrings   string
	DNFAutomaticConfig string
}

// NewModuleForTest creates a Module with test-specific paths.
func NewModuleForTest(o TestOptions) *Module {
	return &Module{
		familyOverride:         o.Family,
		aptSourcesListPath:     o.APTSourcesList,
		aptSourcesListDir:      o.APTSourcesListDir,
		aptAutoUpgradesPath:    o.APTAutoUpgrades,
		aptUnattendedPath:      o.APTUnattended,
		aptTrustedGPGPath:      o.APTTrustedGPG,
		aptTrustedGPGDir:       o.APTTrustedGPGDir,
		usrShareKeyringsDir:    o.USRShareKeyrings,
		dnfAutomaticConfigPath: o.DNFAutomaticConfig,
	}
}
