// Package hardbox provides SSH utilities and hardbox CLI helpers
// used by the Terraform provider resource implementation.
package hardbox

import (
	"encoding/base64"
	"fmt"
	"net"
	"os"
	"strings"
	"time"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
	"golang.org/x/crypto/ssh/knownhosts"
)

// SSHConfig holds the connection parameters for a remote host.
type SSHConfig struct {
	Host        string
	Port        int
	User        string
	PrivateKey  string
	AgentSocket string

	// HostKey is the base64-encoded public host key of the target server
	// (the value from `ssh-keyscan` or `~/.ssh/known_hosts`).
	// When set, the connection is verified against this exact key.
	// When empty, the system known_hosts file (~/.ssh/known_hosts) is used.
	HostKey string
}

// SSHClient wraps an active SSH connection.
type SSHClient struct {
	client *ssh.Client
}

// NewSSHClient establishes an SSH connection using either a private key or
// the SSH agent identified by AgentSocket.
// Host key verification is performed against HostKey (if set) or the
// system known_hosts file. Connections with unknown host keys are rejected.
func NewSSHClient(cfg SSHConfig) (*SSHClient, error) {
	port := cfg.Port
	if port == 0 {
		port = 22
	}
	user := cfg.User
	if user == "" {
		user = "root"
	}

	// --- Authentication ---
	var authMethods []ssh.AuthMethod

	if cfg.PrivateKey != "" {
		signer, err := ssh.ParsePrivateKey([]byte(cfg.PrivateKey))
		if err != nil {
			return nil, fmt.Errorf("parse private key: %w", err)
		}
		authMethods = append(authMethods, ssh.PublicKeys(signer))
	}

	if cfg.AgentSocket != "" {
		sock, err := net.Dial("unix", cfg.AgentSocket)
		if err != nil {
			return nil, fmt.Errorf("connect to SSH agent socket %s: %w", cfg.AgentSocket, err)
		}
		authMethods = append(authMethods, ssh.PublicKeysCallback(agent.NewClient(sock).Signers))
	}

	if len(authMethods) == 0 {
		// Fall back to SSH_AUTH_SOCK environment variable.
		if sock := os.Getenv("SSH_AUTH_SOCK"); sock != "" {
			conn, err := net.Dial("unix", sock)
			if err == nil {
				authMethods = append(authMethods, ssh.PublicKeysCallback(agent.NewClient(conn).Signers))
			}
		}
	}

	if len(authMethods) == 0 {
		return nil, fmt.Errorf("no SSH authentication method available: set private_key or agent_socket")
	}

	// --- Host key verification ---
	hostKeyCallback, err := buildHostKeyCallback(cfg.Host, port, cfg.HostKey)
	if err != nil {
		return nil, err
	}

	clientCfg := &ssh.ClientConfig{
		User:            user,
		Auth:            authMethods,
		HostKeyCallback: hostKeyCallback,
		Timeout:         30 * time.Second,
	}

	addr := fmt.Sprintf("%s:%d", cfg.Host, port)
	client, err := ssh.Dial("tcp", addr, clientCfg)
	if err != nil {
		return nil, fmt.Errorf("ssh dial %s: %w", addr, err)
	}

	return &SSHClient{client: client}, nil
}

// buildHostKeyCallback returns the appropriate ssh.HostKeyCallback:
//   - If hostKey is provided: verify against that specific key only.
//   - Otherwise: verify against the system known_hosts file.
func buildHostKeyCallback(host string, port int, hostKey string) (ssh.HostKeyCallback, error) {
	if hostKey != "" {
		return fixedHostKeyCallback(hostKey)
	}
	return knownHostsCallback()
}

// fixedHostKeyCallback parses a base64-encoded public key and returns a
// callback that accepts only that exact key.
func fixedHostKeyCallback(hostKeyB64 string) (ssh.HostKeyCallback, error) {
	keyBytes, err := base64.StdEncoding.DecodeString(hostKeyB64)
	if err != nil {
		return nil, fmt.Errorf("decode host_key (expected base64): %w", err)
	}

	pubKey, err := ssh.ParsePublicKey(keyBytes)
	if err != nil {
		return nil, fmt.Errorf("parse host_key as SSH public key: %w", err)
	}

	return ssh.FixedHostKey(pubKey), nil
}

// knownHostsCallback returns a callback that verifies hosts against the
// system known_hosts file (~/.ssh/known_hosts).
// Returns an error if the file does not exist or cannot be parsed.
func knownHostsCallback() (ssh.HostKeyCallback, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return nil, fmt.Errorf("determine home directory for known_hosts lookup: %w", err)
	}

	knownHostsPath := fmt.Sprintf("%s/.ssh/known_hosts", home)
	if _, err := os.Stat(knownHostsPath); os.IsNotExist(err) {
		return nil, fmt.Errorf(
			"host_key is not set and %s does not exist: "+
				"provide the host's public key via the host_key argument "+
				"(obtain with: ssh-keyscan -t ed25519 <host> | awk '{print $3}')",
			knownHostsPath,
		)
	}

	cb, err := knownhosts.New(knownHostsPath)
	if err != nil {
		return nil, fmt.Errorf("parse known_hosts file %s: %w", knownHostsPath, err)
	}

	return cb, nil
}

// Run executes a command on the remote host and returns combined stdout+stderr.
func (c *SSHClient) Run(cmd string) (string, error) {
	sess, err := c.client.NewSession()
	if err != nil {
		return "", fmt.Errorf("new SSH session: %w", err)
	}
	defer sess.Close()

	out, err := sess.CombinedOutput(cmd)
	return strings.TrimSpace(string(out)), err
}

// ReadFile reads the contents of a remote file.
func (c *SSHClient) ReadFile(path string) (string, error) {
	out, err := c.Run(fmt.Sprintf("cat %s", path))
	if err != nil {
		return "", fmt.Errorf("read remote file %s: %w", path, err)
	}
	return out, nil
}

// Close closes the underlying SSH connection.
func (c *SSHClient) Close() error {
	return c.client.Close()
}
