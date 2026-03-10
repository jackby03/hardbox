//go:build unix

package filesystem

import (
	"os"
	"syscall"
)

// statOwner extracts the UID and GID from a FileInfo on Unix systems.
func statOwner(info os.FileInfo) (uid, gid uint32, ok bool) {
	st, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return 0, 0, false
	}
	return st.Uid, st.Gid, true
}
