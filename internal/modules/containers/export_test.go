package containers

// NewModuleForTest builds a containers module with injectable dependencies.
func NewModuleForTest(
	run commandRunner,
	hasBinary binaryChecker,
	daemonJSONPath string,
	auditRulesDir string,
) *Module {
	return &Module{
		run:            run,
		hasBinary:      hasBinary,
		daemonJSONPath: daemonJSONPath,
		auditRulesDir:  auditRulesDir,
	}
}

// Exported format strings so tests can build matching command keys.
var (
	SecurityOptsFmt = securityOptsFmt
	PrivilegedFmt   = privilegedFmt
	MountsFmt       = mountsFmt
)
