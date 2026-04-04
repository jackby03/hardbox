package fleet

import (
	"bytes"
	"context"
	"fmt"
	"os/exec"
	"strconv"
	"strings"
)

// sshClient wraps the system ssh(1) binary to run commands on a remote host.
// Using the system binary means host-key verification, SSH agent forwarding,
// and user SSH config (~/.ssh/config) all work without embedding a crypto lib.
type sshClient struct {
	host           Host
	identityFile   string // path to private key (empty = agent / SSH config)
	knownHostsFile string // path to known_hosts (empty = ~/.ssh/known_hosts)
}

// newSSHClient constructs an sshClient. No connection is opened at this point;
// connections are established per command by the ssh binary.
func newSSHClient(h Host, identityFile, knownHostsFile string) *sshClient {
	return &sshClient{
		host:           h,
		identityFile:   identityFile,
		knownHostsFile: knownHostsFile,
	}
}

// run executes cmd on the remote host and returns combined stdout+stderr.
// BatchMode=yes prevents interactive password prompts; host key verification
// is performed by the ssh binary using known_hosts (no InsecureIgnoreHostKey).
func (c *sshClient) run(ctx context.Context, cmd string) (string, error) {
	args := c.baseArgs()
	args = append(args, c.target(), cmd)

	var buf bytes.Buffer
	ex := exec.CommandContext(ctx, "ssh", args...)
	ex.Stdout = &buf
	ex.Stderr = &buf

	err := ex.Run()
	out := strings.TrimSpace(buf.String())
	if err != nil {
		return out, fmt.Errorf("ssh %s: %w\nOutput: %s", c.host, err, out)
	}
	return out, nil
}

// readFile reads the contents of a remote file.
func (c *sshClient) readFile(ctx context.Context, path string) (string, error) {
	return c.run(ctx, fmt.Sprintf("cat -- %s", shellQuote(path)))
}

// baseArgs returns common ssh flags shared across all invocations.
func (c *sshClient) baseArgs() []string {
	args := []string{
		"-o", "BatchMode=yes",
		"-o", "ConnectTimeout=30",
		"-o", "StrictHostKeyChecking=yes", // reject unknown host keys
	}
	if c.host.Port != 22 {
		args = append(args, "-p", strconv.Itoa(c.host.Port))
	}
	if c.identityFile != "" {
		args = append(args, "-i", c.identityFile)
	}
	if c.knownHostsFile != "" {
		args = append(args, "-o", "UserKnownHostsFile="+c.knownHostsFile)
	}
	return args
}

// target returns "user@host".
func (c *sshClient) target() string {
	return fmt.Sprintf("%s@%s", c.host.User, c.host.Addr)
}

// shellQuote wraps s in single quotes, escaping any embedded single quotes.
func shellQuote(s string) string {
	return "'" + strings.ReplaceAll(s, "'", "'\\''") + "'"
}
