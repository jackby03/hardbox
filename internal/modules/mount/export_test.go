package mount

// Exported shims for white-box testing.

func NewModuleWithMounts(mountsPath string) *Module {
	return &Module{mountsPath: mountsPath}
}

func NewModuleWithModprobe(modprobeDir, lsmodOutput string) *Module {
	return &Module{modprobeDir: modprobeDir, lsmodOutput: lsmodOutput}
}

var (
	ParseMountPoints = parseMountPoints
	IsBlacklisted    = isBlacklisted
	HasInstallFalse  = hasInstallFalse
	NormaliseModName = normaliseModName
)
