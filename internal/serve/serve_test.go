package serve

import (
	"strings"
	"testing"
	"time"

	"github.com/hardbox-io/hardbox/internal/report"
)

func makeTestReport(id, hostname string, score int, ts time.Time) *report.Report {
	return &report.Report{
		SessionID:    id,
		Timestamp:    ts,
		Profile:      "production",
		Hostname:     hostname,
		OverallScore: score,
	}
}

func TestIsFleet_DetectsMultiHost(t *testing.T) {
	reports := []*report.Report{
		makeTestReport("a", "web-01", 80, time.Now()),
		makeTestReport("b", "db-01", 70, time.Now()),
	}
	if !(&Server{}).isFleet(reports) {
		t.Error("should detect fleet with 2 different hostnames")
	}
}

func TestIsFleet_SingleHost(t *testing.T) {
	reports := []*report.Report{
		makeTestReport("a", "web-01", 80, time.Now()),
		makeTestReport("b", "web-01", 85, time.Now()),
	}
	if (&Server{}).isFleet(reports) {
		t.Error("should not detect fleet with same hostname")
	}
}

func TestIsFleet_NoHostname(t *testing.T) {
	reports := []*report.Report{
		{SessionID: "a", OverallScore: 80},
		{SessionID: "b", OverallScore: 85},
	}
	if (&Server{}).isFleet(reports) {
		t.Error("should not detect fleet without hostnames")
	}
}

func TestIsFleet_TooFew(t *testing.T) {
	reports := []*report.Report{
		makeTestReport("a", "web-01", 80, time.Now()),
	}
	if (&Server{}).isFleet(reports) {
		t.Error("should not detect fleet with only 1 report")
	}
}

func TestIsFleet_Mixed(t *testing.T) {
	reports := []*report.Report{
		makeTestReport("a", "web-01", 80, time.Now()),
		{SessionID: "b", OverallScore: 85},
		makeTestReport("c", "db-01", 70, time.Now()),
	}
	if !(&Server{}).isFleet(reports) {
		t.Error("should detect fleet when 2+ reports have hostnames")
	}
}

func TestBuildFleetRows_ScoreDelta(t *testing.T) {
	now := time.Now()
	reports := []*report.Report{
		makeTestReport("a1", "web-01", 82, now),
		makeTestReport("a2", "web-01", 75, now.Add(-1*time.Hour)),
		makeTestReport("b1", "db-01", 55, now),
	}

	rows := (&Server{}).buildFleetRows(reports)
	if len(rows) != 2 {
		t.Fatalf("expected 2 hosts, got %d", len(rows))
	}

	for _, row := range rows {
		switch row.Hostname {
		case "web-01":
			if row.Score != 82 {
				t.Errorf("web-01 score: got %d, want 82", row.Score)
			}
			if row.ScoreDelta != 7 {
				t.Errorf("web-01 delta: got %d, want +7", row.ScoreDelta)
			}
			if row.Reports != 2 {
				t.Errorf("web-01 reports: got %d, want 2", row.Reports)
			}
		case "db-01":
			if row.Score != 55 {
				t.Errorf("db-01 score: got %d, want 55", row.Score)
			}
			if row.HasDelta {
				t.Error("db-01 should not have delta (only 1 report)")
			}
		}
	}
}

func TestBuildFleetRows_RegressionFlag(t *testing.T) {
	now := time.Now()
	reports := []*report.Report{
		makeTestReport("a1", "web-01", 70, now),
		makeTestReport("a2", "web-01", 85, now.Add(-1*time.Hour)),
	}

	rows := (&Server{}).buildFleetRows(reports)
	if len(rows) != 1 {
		t.Fatalf("expected 1 host, got %d", len(rows))
	}
	if !rows[0].IsRegressed {
		t.Error("score dropped from 85 to 70 should be regression")
	}
	if rows[0].ScoreDelta != -15 {
		t.Errorf("delta: got %d, want -15", rows[0].ScoreDelta)
	}
}

func TestHostReports_FiltersCorrectly(t *testing.T) {
	now := time.Now()
	reports := []*report.Report{
		makeTestReport("a", "web-01", 80, now),
		makeTestReport("b", "db-01", 70, now),
		makeTestReport("c", "web-01", 85, now.Add(-1*time.Hour)),
	}

	hostReps := (&Server{}).hostReports("web-01", reports)
	if len(hostReps) != 2 {
		t.Fatalf("expected 2 reports for web-01, got %d", len(hostReps))
	}
	if hostReps[0].OverallScore != 80 {
		t.Error("most recent report should be first")
	}
}

func TestComputeTrend_Basic(t *testing.T) {
	now := time.Now()
	reports := []*report.Report{
		makeTestReport("a", "", 70, now.Add(-2*time.Hour)),
		makeTestReport("b", "", 75, now.Add(-1*time.Hour)),
		makeTestReport("c", "", 82, now),
	}
	tr := computeTrend(reports)
	if tr.Count != 3 {
		t.Errorf("count: got %d, want 3", tr.Count)
	}
	if tr.High != 82 {
		t.Errorf("high: got %d, want 82", tr.High)
	}
	if tr.Low != 70 {
		t.Errorf("low: got %d, want 70", tr.Low)
	}
	if tr.Delta != 12 {
		t.Errorf("delta: got %d, want 12", tr.Delta)
	}
	if len(tr.Scores) != 3 {
		t.Errorf("scores length: got %d, want 3", len(tr.Scores))
	}
}

func TestComputeTrend_SingleReport(t *testing.T) {
	reports := []*report.Report{
		makeTestReport("a", "", 80, time.Now()),
	}
	tr := computeTrend(reports)
	if tr.Count != 1 {
		t.Errorf("count: got %d, want 1", tr.Count)
	}
	if tr.Delta != 0 {
		t.Errorf("delta for single report: got %d, want 0", tr.Delta)
	}
}

func TestComputeTrend_Empty(t *testing.T) {
	tr := computeTrend(nil)
	if tr.Count != 0 {
		t.Errorf("count for nil: got %d, want 0", tr.Count)
	}
}

func TestComputeTrend_NegativeScores(t *testing.T) {
	now := time.Now()
	reports := []*report.Report{
		makeTestReport("a", "", -1, now.Add(-1*time.Hour)),
		makeTestReport("b", "", 75, now),
	}
	tr := computeTrend(reports)
	if tr.Scores[0] != 0 {
		t.Errorf("negative score should be 0, got %d", tr.Scores[0])
	}
}

func TestSparklineSVG_SinglePoint(t *testing.T) {
	tr := trendSummary{Scores: []int{80}, Count: 1}
	svg := sparklineSVG(tr)
	if svg != "" {
		t.Error("single point should produce empty SVG")
	}
}

func TestSparklineSVG_MultiPoint(t *testing.T) {
	tr := trendSummary{Scores: []int{50, 60, 70, 80}, Count: 4, High: 80, Low: 50}
	svg := string(sparklineSVG(tr))
	if !strings.Contains(svg, "<svg") || !strings.Contains(svg, "</svg>") {
		t.Error("SVG should have valid tags")
	}
	if !strings.Contains(svg, "<rect") {
		t.Error("SVG should contain rect elements")
	}
}

func TestSparklineSVG_Colors(t *testing.T) {
	tr := trendSummary{Scores: []int{30, 60, 90}, Count: 3, High: 90, Low: 30}
	svg := string(sparklineSVG(tr))
	if !strings.Contains(svg, "#4ade80") && !strings.Contains(svg, "#f87171") {
		t.Error("SVG should have color coding")
	}
}
