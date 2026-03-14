package network

// TestOptions configures module file paths for tests.
type TestOptions struct {
	IPv6DisablePath string
	ModprobeDir     string
	HostsAllowPath  string
	HostsDenyPath   string
	WirelessPath    string
	PasswdPath      string
}

// NewModuleForTest returns a module with test path overrides.
func NewModuleForTest(o TestOptions) *Module {
	return &Module{
		ipv6DisablePath: o.IPv6DisablePath,
		modprobeDir:     o.ModprobeDir,
		hostsAllowPath:  o.HostsAllowPath,
		hostsDenyPath:   o.HostsDenyPath,
		wirelessPath:    o.WirelessPath,
		passwdPath:      o.PasswdPath,
	}
}
