package logging

// NewModuleForTest creates a Module with injected paths and command runner for testing.
func NewModuleForTest(
	run commandRunner,
	rsyslogConf, rsyslogDir, journaldConf, logrotateConf, logrotateDir, varLog string,
) *Module {
	return &Module{
		run:           run,
		rsyslogConf:   rsyslogConf,
		rsyslogDir:    rsyslogDir,
		journaldConf:  journaldConf,
		logrotateConf: logrotateConf,
		logrotateDir:  logrotateDir,
		varLog:        varLog,
	}
}

// SetJournaldKey exposes the pure helper for unit tests.
var SetJournaldKey = setJournaldKey

// RsyslogHasRemoteForwarding exposes the pure helper for unit tests.
var RsyslogHasRemoteForwarding = rsyslogHasRemoteForwarding
