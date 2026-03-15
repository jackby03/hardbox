package users

// NewModuleForTest returns a Module with injected paths for white-box testing.
func NewModuleForTest(
	run commandRunner,
	loginDefs, pamDir, passwdFile, sudoers, sudoersDir, useraddConf string,
) *Module {
	return &Module{
		run:         run,
		loginDefs:   loginDefs,
		pamDir:      pamDir,
		passwdFile:  passwdFile,
		sudoers:     sudoers,
		sudoersDir:  sudoersDir,
		useraddConf: useraddConf,
	}
}

// ParseLoginDefsKey exposes the pure helper for unit tests.
var ParseLoginDefsKey = parseLoginDefsKey

// SetLoginDefsKey exposes the pure helper for unit tests.
var SetLoginDefsKey = setLoginDefsKey

// SetSimpleKey exposes the pure helper for unit tests.
var SetSimpleKey = setSimpleKey
