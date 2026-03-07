# Security Policy

## Supported Versions

The following versions of hardbox are currently supported with security updates:

| Version | Supported |
|:-------:|:---------:|
| latest (main) | ✅ |
| v0.x (pre-release) | ✅ |
| older releases | ❌ |

Once v1.0 is released, only the two most recent minor versions will receive security patches.

---

## Reporting a Vulnerability

**Please do not report security vulnerabilities through public GitHub Issues.**

If you discover a security vulnerability in hardbox, we ask that you report it responsibly through one of the following channels:

### GitHub Private Security Advisory (preferred)

Use GitHub's built-in private disclosure mechanism:

1. Go to [Security Advisories](https://github.com/jackby03/hardbox/security/advisories/new)
2. Click **"Report a vulnerability"**
3. Fill out the form with as much detail as possible

### Email

If you prefer, you can reach the maintainer directly at:

**security@hardbox.jackby03.com**

Please encrypt sensitive reports using the maintainer's public GPG key if possible.

---

## What to Include

A good vulnerability report helps us triage and fix issues faster. Please include:

- A clear description of the vulnerability and its potential impact
- The affected version(s) or commit range
- Step-by-step reproduction instructions
- Any relevant logs, stack traces, or proof-of-concept code
- Your assessment of the severity (low / medium / high / critical)
- Any suggested mitigations or patches, if available

---

## Response Timeline

| Stage | Target |
|:------|:-------|
| Acknowledgement | Within **48 hours** |
| Initial assessment | Within **5 business days** |
| Fix or mitigation | Within **30 days** for critical/high, **90 days** for medium/low |
| Public disclosure | Coordinated with the reporter after fix is available |

We follow a **coordinated disclosure** model. We will work with you to agree on a disclosure timeline and will credit you in the release notes and advisory unless you prefer to remain anonymous.

---

## Scope

### In Scope

- Privilege escalation bugs in the hardbox engine or modules
- Vulnerabilities that allow bypassing intended hardening controls
- Issues in rollback or snapshot mechanisms that could expose sensitive system state
- Insecure defaults in bundled compliance profiles
- Command injection or unsafe shell execution within hardbox itself
- Path traversal or file permission issues in the hardbox binary

### Out of Scope

- Vulnerabilities in the underlying OS or third-party tools that hardbox invokes (report those to the respective upstream projects)
- Security issues in development dependencies not shipped in the final binary
- Findings from automated scanners without proof of exploitability
- Social engineering or phishing attacks
- Physical access attacks

---

## Disclosure Policy

We follow the principle of **responsible disclosure**:

1. Reporter submits a vulnerability privately
2. We acknowledge and investigate
3. We develop and test a fix
4. We coordinate a release and public advisory with the reporter
5. CVE is requested if applicable

We will not pursue legal action against researchers who disclose vulnerabilities in good faith and follow this policy.

---

## Security Considerations for Users

hardbox runs with elevated privileges (`sudo`) and makes direct changes to system configuration. To use it safely:

- Always run `hardbox audit` or use `--dry-run` before applying any profile
- Review the diff output before confirming changes
- Keep hardbox updated to the latest release
- Download binaries only from [official GitHub Releases](https://github.com/jackby03/hardbox/releases) or via the official installer at `https://hardbox.jackby03.com/install.sh`
- Verify binary checksums before installation (SHA256 checksums are published alongside each release)

---

## Acknowledgements

We are grateful to the security researchers and community members who help keep hardbox and its users safe. Confirmed vulnerability reporters will be listed here (with permission).

---

*This policy is inspired by best practices from the open-source security community and may be updated over time.*
