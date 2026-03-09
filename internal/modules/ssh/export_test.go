package ssh

// ParseSshdConfigForTest exposes parseSshdConfig for use in external test packages.
func ParseSshdConfigForTest(data []byte) map[string]string {
	return parseSshdConfig(data)
}

// NewModuleForTest creates a Module that reads from the given configPath instead of /etc/ssh/sshd_config.
func NewModuleForTest(configPath string) *Module {
	return &Module{configPath: configPath}
}
