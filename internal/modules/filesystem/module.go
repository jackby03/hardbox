// Package filesystem implements filesystem security hardening checks.
// It covers mount options (fs-001..007), file permissions (fs-010..014),
// world-writable files (fs-015), unowned files (fs-016), SUID/SGID
// executables (fs-017), sticky bit on world-writable dirs (fs-018),
// and sticky bit on /tmp (fs-019).
package filesystem

import (
	"bufio"
	"context"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	"github.com/hardbox-io/hardbox/internal/modules"
	"github.com/hardbox-io/hardbox/internal/modules/util"
)

const (
	defaultMountsPath = "/proc/mounts"
	defaultFstabPath  = "/etc/fstab"
)

// Module implements filesystem security hardening.
type Module struct {
	mountsPath string // default: /proc/mounts; injectable for testing
	fstabPath  string // default: /etc/fstab; injectable for testing
	fsRoot     string // default: ""; prepended to all resolved paths for testing
}

func (m *Module) Name() string    { return "filesystem" }
func (m *Module) Version() string { return "1.0" }

func (m *Module) procMounts() string {
	if m.mountsPath != "" {
		return m.mountsPath
	}
	return defaultMountsPath
}

func (m *Module) fstab() string {
	if m.fstabPath != "" {
		return m.fstabPath
	}
	return defaultFstabPath
}

// resolvePath prepends fsRoot to abs when testing with a temp directory.
func (m *Module) resolvePath(abs string) string {
	if m.fsRoot != "" {
		return filepath.Join(m.fsRoot, filepath.FromSlash(abs))
	}
	return abs
}

// scanRoot returns the base directory for filesystem scans.
func (m *Module) scanRoot() string {
	if m.fsRoot != "" {
		return m.fsRoot
	}
	return "/"
}

// ── Audit ─────────────────────────────────────────────────────────────────────

// Audit inspects mount options from /proc/mounts, file permissions, and
// performs scans for world-writable files, unowned files, and SUID/SGID
// executables. It is read-only and has no side effects.
func (m *Module) Audit(_ context.Context, _ modules.ModuleConfig) ([]modules.Finding, error) {
	var findings []modules.Finding

	mountFindings, err := m.auditMounts()
	if err != nil {
		return nil, err
	}
	findings = append(findings, mountFindings...)
	findings = append(findings, m.auditFilePerms()...)
	findings = append(findings, m.auditStickyTmp()...)
	findings = append(findings, m.auditWorldWritable()...)
	findings = append(findings, m.auditSUIDSGID()...)
	findings = append(findings, m.auditUnowned()...)

	return findings, nil
}

// ── Mount option checks (fs-001..007) ─────────────────────────────────────────

func (m *Module) auditMounts() ([]modules.Finding, error) {
	content, err := os.ReadFile(m.procMounts())
	if err != nil {
		if os.IsNotExist(err) {
			var findings []modules.Finding
			for _, spec := range mountChecks() {
				findings = append(findings, modules.Finding{
					Check:  spec.check,
					Status: modules.StatusSkipped,
					Detail: "/proc/mounts not available",
				})
			}
			return findings, nil
		}
		return nil, fmt.Errorf("filesystem: read %s: %w", m.procMounts(), err)
	}

	mounts := parseMounts(content)
	var findings []modules.Finding

	for _, spec := range mountChecks() {
		opts, found := mounts[spec.mountPoint]
		if !found {
			findings = append(findings, modules.Finding{
				Check:  spec.check,
				Status: modules.StatusSkipped,
				Detail: fmt.Sprintf("%s is not a separate mountpoint", spec.mountPoint),
			})
			continue
		}

		missing := missingOptions(opts, spec.required)
		current := strings.Join(opts, ",")
		target := strings.Join(spec.required, ",")

		if len(missing) == 0 {
			findings = append(findings, modules.Finding{
				Check:   spec.check,
				Status:  modules.StatusCompliant,
				Current: current,
				Target:  target,
				Detail:  fmt.Sprintf("all required options present: %s", target),
			})
		} else {
			findings = append(findings, modules.Finding{
				Check:   spec.check,
				Status:  modules.StatusNonCompliant,
				Current: current,
				Target:  target,
				Detail:  fmt.Sprintf("missing options: %s", strings.Join(missing, ",")),
			})
		}
	}

	return findings, nil
}

// parseMounts returns mountpoint → options from /proc/mounts content.
func parseMounts(data []byte) map[string][]string {
	result := make(map[string][]string)
	scanner := bufio.NewScanner(strings.NewReader(string(data)))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		// Format: device mountpoint fstype options dump pass
		fields := strings.Fields(line)
		if len(fields) < 4 {
			continue
		}
		result[fields[1]] = strings.Split(fields[3], ",")
	}
	return result
}

// missingOptions returns required options not present in present.
func missingOptions(present, required []string) []string {
	have := make(map[string]bool, len(present))
	for _, o := range present {
		have[strings.TrimSpace(o)] = true
	}
	var missing []string
	for _, req := range required {
		if !have[req] {
			missing = append(missing, req)
		}
	}
	return missing
}

// ── File permission checks (fs-010..014) ──────────────────────────────────────

func (m *Module) auditFilePerms() []modules.Finding {
	findings := make([]modules.Finding, 0, len(filePermChecks()))
	for _, spec := range filePermChecks() {
		findings = append(findings, m.checkFilePerm(spec))
	}
	return findings
}

func (m *Module) checkFilePerm(spec filePermSpec) modules.Finding {
	path := m.resolvePath(spec.path)
	info, err := os.Lstat(path)
	if err != nil {
		if os.IsNotExist(err) {
			return modules.Finding{
				Check:  spec.check,
				Status: modules.StatusSkipped,
				Detail: fmt.Sprintf("%s does not exist", spec.path),
			}
		}
		return modules.Finding{
			Check:  spec.check,
			Status: modules.StatusError,
			Detail: fmt.Sprintf("stat %s: %v", spec.path, err),
		}
	}

	currentPerm := info.Mode().Perm()
	modeOK := currentPerm == spec.mode || (spec.modeAlt != 0 && currentPerm == spec.modeAlt)

	targetMode := fmt.Sprintf("%04o", spec.mode)
	if spec.modeAlt != 0 {
		targetMode += fmt.Sprintf("|%04o", spec.modeAlt)
	}

	uid, gid, haveOwner := statOwner(info)
	ownerOK := true
	var ownerIssue string
	if haveOwner {
		if uid != spec.wantUID {
			ownerOK = false
			ownerIssue += fmt.Sprintf("; uid %d != %d", uid, spec.wantUID)
		}
		if !spec.skipGID && gid != spec.wantGID {
			ownerOK = false
			ownerIssue += fmt.Sprintf("; gid %d != %d (%s)", gid, spec.wantGID, spec.gidLabel)
		}
	}

	var currentStr, targetStr string
	if haveOwner {
		currentStr = fmt.Sprintf("%04o uid=%d gid=%d", currentPerm, uid, gid)
	} else {
		currentStr = fmt.Sprintf("%04o", currentPerm)
	}
	targetStr = fmt.Sprintf("%s uid=%d gid=%s", targetMode, spec.wantUID, spec.gidLabel)

	if modeOK && ownerOK {
		return modules.Finding{
			Check:   spec.check,
			Status:  modules.StatusCompliant,
			Current: currentStr,
			Target:  targetStr,
			Detail:  "permissions and ownership are correct",
		}
	}

	return modules.Finding{
		Check:   spec.check,
		Status:  modules.StatusNonCompliant,
		Current: currentStr,
		Target:  targetStr,
		Detail:  fmt.Sprintf("mode: %04o (want %s)%s", currentPerm, targetMode, ownerIssue),
	}
}

// ── Sticky bit on /tmp (fs-019) ───────────────────────────────────────────────

var checkFS019 = modules.Check{
	ID:          "fs-019",
	Title:       "Sticky bit set on /tmp",
	Severity:    modules.SeverityHigh,
	Remediation: "Run: chmod +t /tmp",
	Compliance: []modules.ComplianceRef{
		{Framework: "CIS", Control: "1.1.1"},
		{Framework: "NIST", Control: "CM-7"},
	},
}

func (m *Module) auditStickyTmp() []modules.Finding {
	tmpPath := m.resolvePath("/tmp")
	info, err := os.Stat(tmpPath)
	if err != nil {
		status := modules.StatusError
		if os.IsNotExist(err) {
			status = modules.StatusSkipped
		}
		return []modules.Finding{{
			Check:  checkFS019,
			Status: status,
			Detail: fmt.Sprintf("stat /tmp: %v", err),
		}}
	}

	if info.Mode()&os.ModeSticky != 0 {
		return []modules.Finding{{
			Check:   checkFS019,
			Status:  modules.StatusCompliant,
			Current: "sticky bit set",
			Target:  "sticky bit set",
		}}
	}

	return []modules.Finding{{
		Check:   checkFS019,
		Status:  modules.StatusNonCompliant,
		Current: "sticky bit not set",
		Target:  "sticky bit set",
		Detail:  "run: chmod +t /tmp",
	}}
}

// ── World-writable files (fs-015) and sticky bit on dirs (fs-018) ─────────────

var checkFS015 = modules.Check{
	ID:          "fs-015",
	Title:       "No world-writable files",
	Severity:    modules.SeverityHigh,
	Remediation: "Remove world-write permission: chmod o-w <file>",
	Compliance: []modules.ComplianceRef{
		{Framework: "CIS", Control: "6.1.12"},
		{Framework: "NIST", Control: "AC-6"},
	},
}

var checkFS018 = modules.Check{
	ID:          "fs-018",
	Title:       "Sticky bit set on all world-writable directories",
	Severity:    modules.SeverityHigh,
	Remediation: "Run: chmod +t <directory> for each listed directory.",
	Compliance: []modules.ComplianceRef{
		{Framework: "CIS", Control: "6.1.11"},
		{Framework: "NIST", Control: "AC-6"},
	},
}

func (m *Module) auditWorldWritable() []modules.Finding {
	root := m.scanRoot()
	var wwFiles []string
	var wwDirsNoSticky []string

	_ = filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		// Skip virtual and noise-heavy directories.
		rel, _ := filepath.Rel(root, path)
		switch rel {
		case "proc", "sys", "dev":
			return fs.SkipDir
		}

		info, err := d.Info()
		if err != nil {
			return nil
		}
		mode := info.Mode()
		if mode.Perm()&0o002 == 0 {
			return nil
		}
		if mode.IsDir() {
			if mode&os.ModeSticky == 0 {
				wwDirsNoSticky = append(wwDirsNoSticky, path)
			}
		} else if mode.IsRegular() {
			wwFiles = append(wwFiles, path)
		}
		return nil
	})

	const maxList = 20
	var findings []modules.Finding

	if len(wwFiles) == 0 {
		findings = append(findings, modules.Finding{
			Check:   checkFS015,
			Status:  modules.StatusCompliant,
			Current: "0 world-writable files",
			Target:  "0 world-writable files",
		})
	} else {
		findings = append(findings, modules.Finding{
			Check:   checkFS015,
			Status:  modules.StatusNonCompliant,
			Current: fmt.Sprintf("%d world-writable file(s)", len(wwFiles)),
			Target:  "0 world-writable files",
			Detail:  strings.Join(wwFiles[:min(len(wwFiles), maxList)], "\n"),
		})
	}

	if len(wwDirsNoSticky) == 0 {
		findings = append(findings, modules.Finding{
			Check:   checkFS018,
			Status:  modules.StatusCompliant,
			Current: "all world-writable directories have sticky bit",
			Target:  "sticky bit on all world-writable directories",
		})
	} else {
		findings = append(findings, modules.Finding{
			Check:   checkFS018,
			Status:  modules.StatusNonCompliant,
			Current: fmt.Sprintf("%d world-writable dir(s) without sticky bit", len(wwDirsNoSticky)),
			Target:  "sticky bit on all world-writable directories",
			Detail:  strings.Join(wwDirsNoSticky[:min(len(wwDirsNoSticky), maxList)], "\n"),
		})
	}

	return findings
}

// ── SUID/SGID scan (fs-017) ───────────────────────────────────────────────────

var checkFS017 = modules.Check{
	ID:          "fs-017",
	Title:       "Audit SUID and SGID executables",
	Severity:    modules.SeverityMedium,
	Remediation: "Review listed SUID/SGID executables and remove the bit if not required: chmod u-s <file> or chmod g-s <file>",
	Compliance: []modules.ComplianceRef{
		{Framework: "CIS", Control: "6.1.14"},
		{Framework: "NIST", Control: "CM-7"},
	},
}

func (m *Module) auditSUIDSGID() []modules.Finding {
	root := m.scanRoot()
	var found []string

	_ = filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		rel, _ := filepath.Rel(root, path)
		switch rel {
		case "proc", "sys", "dev":
			return fs.SkipDir
		}
		info, err := d.Info()
		if err != nil {
			return nil
		}
		mode := info.Mode()
		if mode&os.ModeSetuid != 0 || mode&os.ModeSetgid != 0 {
			found = append(found, path)
		}
		return nil
	})

	const maxList = 30
	if len(found) == 0 {
		return []modules.Finding{{
			Check:   checkFS017,
			Status:  modules.StatusManual,
			Current: "0 SUID/SGID executables found",
			Target:  "review all SUID/SGID executables",
			Detail:  "no SUID/SGID executables detected in scan root",
		}}
	}
	return []modules.Finding{{
		Check:   checkFS017,
		Status:  modules.StatusManual,
		Current: fmt.Sprintf("%d SUID/SGID executable(s)", len(found)),
		Target:  "review all SUID/SGID executables",
		Detail:  strings.Join(found[:min(len(found), maxList)], "\n"),
	}}
}

// ── Unowned/ungrouped files (fs-016) ─────────────────────────────────────────

var checkFS016 = modules.Check{
	ID:          "fs-016",
	Title:       "No unowned or ungrouped files",
	Severity:    modules.SeverityMedium,
	Remediation: "Assign proper ownership: chown <user>:<group> <file>",
	Compliance: []modules.ComplianceRef{
		{Framework: "CIS", Control: "6.1.13"},
		{Framework: "NIST", Control: "AC-6"},
	},
}

func (m *Module) auditUnowned() []modules.Finding {
	knownUIDs := parseIDsFromPasswd(m.resolvePath("/etc/passwd"))
	knownGIDs := parseIDsFromGroup(m.resolvePath("/etc/group"))

	if len(knownUIDs) == 0 && len(knownGIDs) == 0 {
		return []modules.Finding{{
			Check:  checkFS016,
			Status: modules.StatusSkipped,
			Detail: "could not read /etc/passwd and /etc/group",
		}}
	}

	root := m.scanRoot()
	var unowned []string

	_ = filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		rel, _ := filepath.Rel(root, path)
		switch rel {
		case "proc", "sys", "dev":
			return fs.SkipDir
		}
		info, err := d.Info()
		if err != nil {
			return nil
		}
		uid, gid, haveOwner := statOwner(info)
		if !haveOwner {
			return nil
		}
		if !knownUIDs[uid] || !knownGIDs[gid] {
			unowned = append(unowned, path)
		}
		return nil
	})

	const maxList = 20
	if len(unowned) == 0 {
		return []modules.Finding{{
			Check:   checkFS016,
			Status:  modules.StatusCompliant,
			Current: "0 unowned/ungrouped files",
			Target:  "0 unowned/ungrouped files",
		}}
	}
	return []modules.Finding{{
		Check:   checkFS016,
		Status:  modules.StatusNonCompliant,
		Current: fmt.Sprintf("%d unowned/ungrouped file(s)", len(unowned)),
		Target:  "0 unowned/ungrouped files",
		Detail:  strings.Join(unowned[:min(len(unowned), maxList)], "\n"),
	}}
}

// parseIDsFromPasswd reads /etc/passwd and returns a set of known UIDs.
func parseIDsFromPasswd(path string) map[uint32]bool {
	data, err := os.ReadFile(path)
	if err != nil {
		return map[uint32]bool{}
	}
	ids := make(map[uint32]bool)
	for _, line := range strings.Split(string(data), "\n") {
		fields := strings.Split(line, ":")
		if len(fields) < 3 {
			continue
		}
		var uid uint32
		if _, err := fmt.Sscanf(fields[2], "%d", &uid); err == nil {
			ids[uid] = true
		}
	}
	return ids
}

// parseIDsFromGroup reads /etc/group and returns a set of known GIDs.
func parseIDsFromGroup(path string) map[uint32]bool {
	data, err := os.ReadFile(path)
	if err != nil {
		return map[uint32]bool{}
	}
	ids := make(map[uint32]bool)
	for _, line := range strings.Split(string(data), "\n") {
		fields := strings.Split(line, ":")
		if len(fields) < 3 {
			continue
		}
		var gid uint32
		if _, err := fmt.Sscanf(fields[2], "%d", &gid); err == nil {
			ids[gid] = true
		}
	}
	return ids
}

// ── Plan ─────────────────────────────────────────────────────────────────────

// Plan returns reversible Changes to remediate non-compliant file permissions,
// sticky bit on /tmp, and mount option entries in /etc/fstab.
// Scan-based findings (fs-015..018) require manual review and are not auto-remediated.
func (m *Module) Plan(ctx context.Context, _ modules.ModuleConfig) ([]modules.Change, error) {
	findings, err := m.Audit(ctx, nil)
	if err != nil {
		return nil, err
	}

	ncByID := make(map[string]modules.Finding)
	for _, f := range findings {
		if f.Status == modules.StatusNonCompliant {
			ncByID[f.Check.ID] = f
		}
	}

	var changes []modules.Change

	// File permission changes (fs-010..014).
	for _, spec := range filePermChecks() {
		if _, nc := ncByID[spec.check.ID]; !nc {
			continue
		}
		spec := spec
		path := m.resolvePath(spec.path)
		info, err := os.Lstat(path)
		if err != nil {
			continue
		}
		oldMode := info.Mode().Perm()
		changes = append(changes, modules.Change{
			Description:  fmt.Sprintf("filesystem: chmod %04o %s", spec.mode, spec.path),
			DryRunOutput: fmt.Sprintf("  chmod %04o %s", spec.mode, spec.path),
			Apply: func() error {
				return os.Chmod(path, spec.mode)
			},
			Revert: func() error {
				return os.Chmod(path, oldMode)
			},
		})
	}

	// Sticky bit on /tmp (fs-019).
	if _, nc := ncByID["fs-019"]; nc {
		tmpPath := m.resolvePath("/tmp")
		info, err := os.Stat(tmpPath)
		if err == nil {
			oldMode := info.Mode()
			changes = append(changes, modules.Change{
				Description:  "filesystem: set sticky bit on /tmp",
				DryRunOutput: fmt.Sprintf("  chmod +t /tmp  (current mode: %04o)", oldMode.Perm()),
				Apply: func() error {
					return os.Chmod(tmpPath, oldMode|os.ModeSticky)
				},
				Revert: func() error {
					return os.Chmod(tmpPath, oldMode&^os.ModeSticky)
				},
			})
		}
	}

	// Mount option changes via /etc/fstab.
	mountChanges, err := m.planMounts(findings)
	if err != nil {
		return nil, err
	}
	changes = append(changes, mountChanges...)

	return changes, nil
}

// planMounts builds a single atomic Change that updates /etc/fstab for all
// non-compliant mount options, with a single Revert that restores the original file.
func (m *Module) planMounts(findings []modules.Finding) ([]modules.Change, error) {
	type mountFix struct {
		mountPoint string
		missing    []string
	}
	var fixes []mountFix

	specByID := make(map[string]mountCheckSpec)
	for _, spec := range mountChecks() {
		specByID[spec.check.ID] = spec
	}

	for _, f := range findings {
		if f.Status != modules.StatusNonCompliant {
			continue
		}
		spec, ok := specByID[f.Check.ID]
		if !ok {
			continue
		}
		currentOpts := strings.Split(f.Current, ",")
		missing := missingOptions(currentOpts, spec.required)
		if len(missing) > 0 {
			fixes = append(fixes, mountFix{mountPoint: spec.mountPoint, missing: missing})
		}
	}

	if len(fixes) == 0 {
		return nil, nil
	}

	fstabPath := m.fstab()
	oldContent, readErr := os.ReadFile(fstabPath)
	if readErr != nil && !os.IsNotExist(readErr) {
		return nil, fmt.Errorf("filesystem: read %s: %w", fstabPath, readErr)
	}
	fileExisted := readErr == nil

	var dryRun strings.Builder
	newContent := string(oldContent)
	for _, fix := range fixes {
		fmt.Fprintf(&dryRun, "  %s: add mount options %s\n", fix.mountPoint, strings.Join(fix.missing, ","))
		newContent = addFstabOptions(newContent, fix.mountPoint, fix.missing)
	}

	return []modules.Change{{
		Description:  fmt.Sprintf("filesystem: update /etc/fstab mount options for %d mountpoint(s)", len(fixes)),
		DryRunOutput: strings.TrimRight(dryRun.String(), "\n"),
		Apply: func() error {
			return util.AtomicWrite(fstabPath, []byte(newContent), 0o644)
		},
		Revert: func() error {
			if !fileExisted {
				return os.Remove(fstabPath)
			}
			return util.AtomicWrite(fstabPath, oldContent, 0o644)
		},
	}}, nil
}

// addFstabOptions appends missing mount options to the entry for mountpoint in
// the fstab content. If the entry is absent, a new tmpfs line is appended.
func addFstabOptions(content, mountpoint string, addOpts []string) string {
	lines := strings.Split(content, "\n")
	updated := false

	for i, line := range lines {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			continue
		}
		fields := strings.Fields(trimmed)
		if len(fields) < 4 || fields[1] != mountpoint {
			continue
		}
		opts := strings.Split(fields[3], ",")
		opts = append(opts, addOpts...)
		fields[3] = strings.Join(opts, ",")
		lines[i] = strings.Join(fields, "\t")
		updated = true
		break
	}

	if !updated {
		lines = append(lines, fmt.Sprintf("tmpfs\t%s\ttmpfs\t%s\t0 0",
			mountpoint, strings.Join(addOpts, ",")))
	}

	return strings.Join(lines, "\n")
}
