// Copyright (C) 2024 Jack (jackby03)
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published
// by the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU Affero General Public License for more details.
//
// You should have received a copy of the GNU Affero General Public License
// along with this program. If not, see <https://www.gnu.org/licenses/>.
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

