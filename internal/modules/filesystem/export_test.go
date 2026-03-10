// export_test.go exposes internal constructor knobs for package-external tests.
package filesystem

// NewModuleForTest returns a Module with injected paths for unit testing.
//   - mountsPath: path to a fake /proc/mounts file
//   - fsRoot: root directory that replaces "/" for all file path lookups and scans
//   - fstabPath: path to a fake /etc/fstab file
func NewModuleForTest(mountsPath, fsRoot, fstabPath string) *Module {
	return &Module{
		mountsPath: mountsPath,
		fsRoot:     fsRoot,
		fstabPath:  fstabPath,
	}
}
