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
	tmpl, err := template.New("").ParseFS(templateFS, "templates/*.html")
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
	s.mux.HandleFunc("/api/reports", s.handleAPIReports)
}

// reportMeta is the report list entry returned by /api/reports.
type reportMeta struct {
	SessionID    string    `json:"session_id"`
	Timestamp    time.Time `json:"timestamp"`
	Profile      string    `json:"profile"`
	OverallScore int       `json:"overall_score"`
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

// handleIndex renders the report list page.
func (s *Server) handleIndex(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}
	reports, _ := s.loadReports()
	s.render(w, "index.html", map[string]any{
		"Reports":    reports,
		"ReportsDir": s.cfg.ReportsDir,
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
	s.render(w, "report.html", map[string]any{"Report": rep})
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

