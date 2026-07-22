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
// Package serve implements the hardbox web dashboard HTTP server.
package serve

import (
	"context"
	"embed"
	"encoding/json"
	"fmt"
	"html/template"
	"math"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/hardbox-io/hardbox/internal/report"
)

//go:embed templates/*.html
var templateFS embed.FS

// Config holds the server configuration.
type Config struct {
	Addr       string // e.g. "127.0.0.1:8080"
	ReportsDir string
	BasicAuth  string // "user:pass" or empty
}

// Server is the hardbox dashboard HTTP server.
type Server struct {
	cfg  Config
	tmpl *template.Template
	mux  *http.ServeMux
}

// New creates a Server and parses the embedded templates.
func New(cfg Config) (*Server, error) {
	funcMap := template.FuncMap{
		"sparklineSVG": sparklineSVG,
	}
	tmpl, err := template.New("").Funcs(funcMap).ParseFS(templateFS, "templates/*.html")
	if err != nil {
		return nil, fmt.Errorf("parsing templates: %w", err)
	}

	s := &Server{cfg: cfg, tmpl: tmpl, mux: http.NewServeMux()}
	s.routes()
	return s, nil
}

// Addr returns the resolved listen address (useful after Start returns it).
func (s *Server) Addr() string { return s.cfg.Addr }

// Start listens on the configured address and serves until ctx is cancelled.
func (s *Server) Start(ctx context.Context) error {
	ln, err := net.Listen("tcp", s.cfg.Addr)
	if err != nil {
		return fmt.Errorf("listen %s: %w", s.cfg.Addr, err)
	}
	s.cfg.Addr = ln.Addr().String()

	srv := &http.Server{
		Handler:      s.handler(),
		ReadTimeout:  10 * time.Second,
		WriteTimeout: 30 * time.Second,
		IdleTimeout:  60 * time.Second,
	}

	errCh := make(chan error, 1)
	go func() { errCh <- srv.Serve(ln) }()

	select {
	case <-ctx.Done():
		shutCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		return srv.Shutdown(shutCtx)
	case err := <-errCh:
		return err
	}
}

func (s *Server) handler() http.Handler {
	if s.cfg.BasicAuth == "" {
		return s.mux
	}
	user, pass, ok := strings.Cut(s.cfg.BasicAuth, ":")
	if !ok {
		return s.mux
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		u, p, ok := r.BasicAuth()
		if !ok || u != user || p != pass {
			w.Header().Set("WWW-Authenticate", `Basic realm="hardbox"`)
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		s.mux.ServeHTTP(w, r)
	})
}

func (s *Server) routes() {
	s.mux.HandleFunc("/", s.handleIndex)
	s.mux.HandleFunc("/report/", s.handleReport)
	s.mux.HandleFunc("/diff/", s.handleDiff)
	s.mux.HandleFunc("/fleet", s.handleFleet)
	s.mux.HandleFunc("/host/", s.handleHost)
	s.mux.HandleFunc("/api/reports", s.handleAPIReports)
}

// reportMeta is the report list entry returned by /api/reports.
type reportMeta struct {
	SessionID    string    `json:"session_id"`
	Timestamp    time.Time `json:"timestamp"`
	Profile      string    `json:"profile"`
	OverallScore int       `json:"overall_score"`
	Hostname     string    `json:"hostname,omitempty"`
	Modules      int       `json:"modules"`
	File         string    `json:"file"`
}

func (s *Server) loadReports() ([]*report.Report, error) {
	entries, err := os.ReadDir(s.cfg.ReportsDir)
	if err != nil {
		return nil, fmt.Errorf("reading reports dir %q: %w", s.cfg.ReportsDir, err)
	}

	var reports []*report.Report
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".json") {
			continue
		}
		path := filepath.Join(s.cfg.ReportsDir, e.Name())
		data, err := os.ReadFile(path)
		if err != nil {
			continue
		}
		var r report.Report
		if err := json.Unmarshal(data, &r); err != nil {
			continue
		}
		// Only include files that look like hardbox reports (have a session_id).
		if r.SessionID == "" {
			continue
		}
		reports = append(reports, &r)
	}

	sort.Slice(reports, func(i, j int) bool {
		return reports[i].Timestamp.After(reports[j].Timestamp)
	})
	return reports, nil
}

func (s *Server) findReport(sessionID string) (*report.Report, error) {
	reports, err := s.loadReports()
	if err != nil {
		return nil, err
	}
	for _, r := range reports {
		if r.SessionID == sessionID {
			return r, nil
		}
	}
	return nil, fmt.Errorf("report %q not found", sessionID)
}

// ── fleet detection & grouping ────────────────────────────────────────

type fleetHostRow struct {
	Hostname    string
	Score       int
	ScoreDelta  int
	HasDelta    bool
	LastAudit   time.Time
	Profile     string
	SessionID   string
	Reports     int
	IsRegressed bool
	Trend       trendSummary
}

// trendSummary carries score history data used to render SVG sparklines.
type trendSummary struct {
	Scores []int
	High   int
	Low    int
	Delta  int
	Count  int
}

func computeTrend(reports []*report.Report) trendSummary {
	if len(reports) == 0 {
		return trendSummary{}
	}
	sorted := make([]*report.Report, len(reports))
	copy(sorted, reports)
	sort.Slice(sorted, func(i, j int) bool {
		return sorted[i].Timestamp.Before(sorted[j].Timestamp)
	})
	scores := make([]int, len(sorted))
	high, low := -999, 999
	for i, r := range sorted {
		s := r.OverallScore
		if s < 0 {
			s = 0
		}
		scores[i] = s
		if s > high {
			high = s
		}
		if s < low {
			low = s
		}
	}
	if high < 0 {
		high = 0
	}
	if low > 100 {
		low = 0
	}
	delta := 0
	if len(scores) >= 2 {
		delta = scores[len(scores)-1] - scores[0]
	}
	return trendSummary{
		Scores: scores,
		High:   high,
		Low:    low,
		Delta:  delta,
		Count:  len(scores),
	}
}

func (s *Server) isFleet(reports []*report.Report) bool {
	if len(reports) < 2 {
		return false
	}
	hosts := make(map[string]bool)
	for _, r := range reports {
		if r.Hostname != "" {
			hosts[r.Hostname] = true
		}
	}
	return len(hosts) > 1
}

func (s *Server) buildFleetRows(reports []*report.Report) []fleetHostRow {
	byHost := make(map[string][]*report.Report)
	for _, r := range reports {
		h := r.Hostname
		if h == "" {
			continue
		}
		byHost[h] = append(byHost[h], r)
	}

	var rows []fleetHostRow
	for host, reps := range byHost {
		sort.Slice(reps, func(i, j int) bool {
			return reps[i].Timestamp.After(reps[j].Timestamp)
		})

		row := fleetHostRow{
			Hostname:  host,
			Score:     reps[0].OverallScore,
			LastAudit: reps[0].Timestamp,
			Profile:   reps[0].Profile,
			SessionID: reps[0].SessionID,
			Reports:   len(reps),
			Trend:     computeTrend(reps),
		}

		if len(reps) >= 2 {
			row.ScoreDelta = reps[0].OverallScore - reps[1].OverallScore
			row.HasDelta = true
			row.IsRegressed = row.ScoreDelta < 0
		}

		rows = append(rows, row)
	}

	sort.Slice(rows, func(i, j int) bool {
		return rows[i].LastAudit.After(rows[j].LastAudit)
	})

	return rows
}

func (s *Server) hostReports(hostname string, reports []*report.Report) []*report.Report {
	var result []*report.Report
	for _, r := range reports {
		h := r.Hostname
		if h == "" {
			h = "unknown"
		}
		if h == hostname {
			result = append(result, r)
		}
	}
	sort.Slice(result, func(i, j int) bool {
		return result[i].Timestamp.After(result[j].Timestamp)
	})
	return result
}

// ── handlers ──────────────────────────────────────────────────────────

// handleIndex renders the report list page, or shows fleet overview.
func (s *Server) handleIndex(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}
	reports, _ := s.loadReports()

	if s.isFleet(reports) {
		rows := s.buildFleetRows(reports)
		s.render(w, "fleet.html", map[string]any{
			"Hosts":      rows,
			"TotalHosts": len(rows),
			"ReportsDir": s.cfg.ReportsDir,
		})
		return
	}

	s.render(w, "index.html", map[string]any{
		"Reports":    reports,
		"ReportsDir": s.cfg.ReportsDir,
		"Trend":      computeTrend(reports),
	})
}

// handleFleet renders the fleet overview page.
func (s *Server) handleFleet(w http.ResponseWriter, r *http.Request) {
	reports, _ := s.loadReports()
	rows := s.buildFleetRows(reports)
	s.render(w, "fleet.html", map[string]any{
		"Hosts":      rows,
		"TotalHosts": len(rows),
		"ReportsDir": s.cfg.ReportsDir,
	})
}

// handleHost shows all reports for a single host with score history.
func (s *Server) handleHost(w http.ResponseWriter, r *http.Request) {
	hostname := strings.TrimPrefix(r.URL.Path, "/host/")
	if hostname == "" {
		http.Redirect(w, r, "/fleet", http.StatusFound)
		return
	}
	reports, _ := s.loadReports()
	hostReps := s.hostReports(hostname, reports)
	if len(hostReps) == 0 {
		http.Error(w, "host not found", http.StatusNotFound)
		return
	}

	latest := hostReps[0]
	delta := 0
	hasDelta := false
	if len(hostReps) >= 2 {
		delta = hostReps[0].OverallScore - hostReps[1].OverallScore
		hasDelta = true
	}

	var scores []int
	for i := len(hostReps) - 1; i >= 0; i-- {
		scores = append(scores, hostReps[i].OverallScore)
	}

	s.render(w, "host.html", map[string]any{
		"Hostname": hostname,
		"Reports":  hostReps,
		"Latest":   latest,
		"Delta":    delta,
		"HasDelta": hasDelta,
		"Scores":   scores,
		"Trend":    computeTrend(hostReps),
	})
}

// handleReport renders a single report page at /report/<session_id>.
func (s *Server) handleReport(w http.ResponseWriter, r *http.Request) {
	id := strings.TrimPrefix(r.URL.Path, "/report/")
	if id == "" {
		http.Redirect(w, r, "/", http.StatusFound)
		return
	}
	rep, err := s.findReport(id)
	if err != nil {
		http.Error(w, "report not found", http.StatusNotFound)
		return
	}
	reports, _ := s.loadReports()
	var hostReps []*report.Report
	if rep.Hostname != "" {
		hostReps = s.hostReports(rep.Hostname, reports)
	}
	s.render(w, "report.html", map[string]any{
		"Report": rep,
		"Trend":  computeTrend(hostReps),
	})
}

// handleDiff renders the diff page at /diff/<id1>/<id2>.
func (s *Server) handleDiff(w http.ResponseWriter, r *http.Request) {
	path := strings.TrimPrefix(r.URL.Path, "/diff/")
	parts := strings.SplitN(path, "/", 2)
	if len(parts) != 2 || parts[0] == "" || parts[1] == "" {
		http.Error(w, "usage: /diff/<before_id>/<after_id>", http.StatusBadRequest)
		return
	}

	before, err := s.findReport(parts[0])
	if err != nil {
		http.Error(w, fmt.Sprintf("before report: %v", err), http.StatusNotFound)
		return
	}
	after, err := s.findReport(parts[1])
	if err != nil {
		http.Error(w, fmt.Sprintf("after report: %v", err), http.StatusNotFound)
		return
	}

	d := report.Diff(before, after)
	s.render(w, "diff.html", map[string]any{"Diff": d})
}

// handleAPIReports returns JSON metadata for all reports.
func (s *Server) handleAPIReports(w http.ResponseWriter, r *http.Request) {
	reports, err := s.loadReports()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	meta := make([]reportMeta, 0, len(reports))
	for _, rep := range reports {
		meta = append(meta, reportMeta{
			SessionID:    rep.SessionID,
			Timestamp:    rep.Timestamp,
			Profile:      rep.Profile,
			OverallScore: rep.OverallScore,
			Hostname:     rep.Hostname,
			Modules:      len(rep.Modules),
		})
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(meta)
}

func (s *Server) render(w http.ResponseWriter, name string, data any) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := s.tmpl.ExecuteTemplate(w, name, data); err != nil {
		http.Error(w, "render error: "+err.Error(), http.StatusInternalServerError)
	}
}

// sparklineSVG returns an inline SVG sparkline for a trend summary.
// Width=120, Height=24, only rendered when 2+ data points exist.
func sparklineSVG(t trendSummary) template.HTML {
	if t.Count < 2 || len(t.Scores) == 0 {
		return ""
	}
	high, low := t.High, t.Low
	span := high - low
	if span == 0 {
		span = 1
	}

	w, h := 120.0, 24.0
	barW := w / float64(len(t.Scores))
	if barW < 2 {
		barW = 2
	}

	var sb strings.Builder
	sb.WriteString(fmt.Sprintf(`<svg width="%.0f" height="%.0f" style="vertical-align:middle;margin-left:4px">`, w, h))
	for i, score := range t.Scores {
		x := float64(i) * barW
		barH := math.Max(2, float64(score-low)/float64(span)*h)
		y := h - barH
		color := "#4ade80"
		if score < 50 {
			color = "#f87171"
		} else if score < 80 {
			color = "#facc15"
		}
		sb.WriteString(fmt.Sprintf(`<rect x="%.1f" y="%.1f" width="%.1f" height="%.1f" fill="%s" rx="1"/>`,
			x, y, barW-1, barH, color))
	}
	sb.WriteString("</svg>")
	return template.HTML(sb.String())
}
