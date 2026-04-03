// Package hardbox provides SSH utilities and hardbox CLI helpers
// used by the Terraform provider resource implementation.
package hardbox

import (
	"fmt"
	"net"
	"os"
	"strings"
	"time"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
)

// SSHConfig holds the connection parameters for a remote host.
type SSHConfig struct {
	Host        string
	Port        int
	User        string
	PrivateKey  string
	AgentSocket string
}

// SSHClient wraps an active SSH connection.
type SSHClient struct {
	client *ssh.Client
}

// NewSSHClient establishes an SSH connection using either a private key or
// the SSH agent identified by AgentSocket.
func NewSSHClient(cfg SSHConfig) (*SSHClient, error) {
	port := cfg.Port
	if port == 0 {
		port = 22
	}
	user := cfg.User
	if user == "" {
		user = "root"
	}

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

	clientCfg := &ssh.ClientConfig{
		User:            user,
		Auth:            authMethods,
		HostKeyCallback: ssh.InsecureIgnoreHostKey(), //nolint:gosec // users should configure known_hosts in production
		Timeout:         30 * time.Second,
	}

	addr := fmt.Sprintf("%s:%d", cfg.Host, port)
	client, err := ssh.Dial("tcp", addr, clientCfg)
	if err != nil {
		return nil, fmt.Errorf("ssh dial %s: %w", addr, err)
	}

	return &SSHClient{client: client}, nil
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
