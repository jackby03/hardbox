//go:build !unix

package filesystem

import "os"

// statOwner is a no-op stub on non-Unix systems.
func statOwner(_ os.FileInfo) (uid, gid uint32, ok bool) {
	return 0, 0, false
}
