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
package report

import (
	"encoding/json"
	"fmt"
	"io"
	"strings"
)

const sarifVersion = "2.1.0"
const sarifSchema = "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json"

func renderSARIF(r *Report, w io.Writer) error {
	rules, ruleIdx := buildSARIFRules(r)
	results := buildSARIFResults(r, ruleIdx)

	doc := sarifRoot{
		Version: sarifVersion,
		Schema:  sarifSchema,
		Runs: []sarifRun{
			{
				Tool: sarifTool{
					Driver: sarifDriver{
						Name:           "hardbox",
						Version:        "0.5.0-dev",
						InformationURI: "https://github.com/jackby03/hardbox",
						Rules:          rules,
					},
				},
				Results: results,
			},
		},
	}

	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	if err := enc.Encode(doc); err != nil {
		return err
	}
	return nil
}

// renderDiffSARIF produces a SARIF document from a diff report, treating
// regressions as results and improvements as suppressed results.
func renderDiffSARIF(d *DiffReport, w io.Writer) error {
	var rules []sarifRule
	var results []sarifResult

	ruleIdx := make(map[string]int)
	addRule := func(id, title, severity string) int {
		if idx, ok := ruleIdx[id]; ok {
			return idx
		}
		idx := len(rules)
		rules = append(rules, sarifRule{
			ID:               id,
			ShortDescription: textMsg{Text: title},
			FullDescription:  textMsg{Text: fmt.Sprintf("Diff: %s", title)},
			Properties:       ruleProps{Tags: []string{"security", fmt.Sprintf("severity/%s", severity)}},
		})
		ruleIdx[id] = idx
		return idx
	}

	for _, reg := range d.Regressions {
		idx := addRule(reg.CheckID, reg.Title, reg.Severity)
		msg := fmt.Sprintf("REGRESSION: %s — was compliant, now non-compliant", reg.Title)
		if reg.Detail != "" {
			msg = fmt.Sprintf("%s: %s", msg, reg.Detail)
		}
		results = append(results, sarifResult{
			RuleID:    reg.CheckID,
			RuleIndex: idx,
			Level:     sarifLevel(reg.Severity),
			Message:   textMsg{Text: msg},
		})
	}

	for _, imp := range d.Improvements {
		idx := addRule(imp.CheckID, imp.Title, imp.Severity)
		msg := fmt.Sprintf("IMPROVEMENT: %s — was non-compliant, now compliant", imp.Title)
		results = append(results, sarifResult{
			RuleID:    imp.CheckID,
			RuleIndex: idx,
			Level:     "none",
			Message:   textMsg{Text: msg},
		})
	}

	doc := sarifRoot{
		Version: sarifVersion,
		Schema:  sarifSchema,
		Runs: []sarifRun{
			{
				Tool: sarifTool{
					Driver: sarifDriver{
						Name:           "hardbox",
						Version:        "0.5.0-dev",
						InformationURI: "https://github.com/jackby03/hardbox",
						Rules:          rules,
					},
				},
				Results: results,
			},
		},
	}

	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(doc)
}

// ── SARIF data model ─────────────────────────────────────────────────

type sarifRoot struct {
	Version string     `json:"version"`
	Schema  string     `json:"$schema"`
	Runs    []sarifRun `json:"runs"`
}

type sarifRun struct {
	Tool    sarifTool     `json:"tool"`
	Results []sarifResult `json:"results"`
}

type sarifTool struct {
	Driver sarifDriver `json:"driver"`
}

type sarifDriver struct {
	Name           string      `json:"name"`
	Version        string      `json:"version"`
	InformationURI string      `json:"informationUri"`
	Rules          []sarifRule `json:"rules"`
}

type sarifRule struct {
	ID               string   `json:"id"`
	ShortDescription textMsg  `json:"shortDescription"`
	FullDescription  textMsg  `json:"fullDescription"`
	Help             textMsg  `json:"help,omitempty"`
	Properties       ruleProps `json:"properties,omitempty"`
}

type textMsg struct {
	Text string `json:"text"`
}

type ruleProps struct {
	Tags []string `json:"tags,omitempty"`
}

type sarifResult struct {
	RuleID    string       `json:"ruleId"`
	RuleIndex int          `json:"ruleIndex"`
	Level     string       `json:"level"`
	Message   textMsg      `json:"message"`
	Locations []sarifLoc   `json:"locations,omitempty"`
}

type sarifLoc struct {
	PhysicalLocation sarifPhysicalLoc `json:"physicalLocation"`
}

type sarifPhysicalLoc struct {
	ArtifactLocation artifactLoc `json:"artifactLocation"`
}

type artifactLoc struct {
	URI string `json:"uri"`
}

// ── builders ─────────────────────────────────────────────────────────

func sarifLevel(severity string) string {
	switch strings.ToLower(severity) {
	case "critical", "high":
		return "error"
	case "medium":
		return "warning"
	case "low", "info":
		return "note"
	default:
		return "warning"
	}
}

func buildSARIFRules(r *Report) ([]sarifRule, map[string]int) {
	seen := make(map[string]bool)
	var rules []sarifRule
	idx := make(map[string]int)

	for _, mod := range r.Modules {
		for _, f := range mod.Findings {
			if seen[f.CheckID] {
				continue
			}
			seen[f.CheckID] = true

			help := ""
			if f.Target != "" {
				help = fmt.Sprintf("Expected: %s", f.Target)
			}

			rule := sarifRule{
				ID: f.CheckID,
				ShortDescription: textMsg{Text: f.Title},
				FullDescription:  textMsg{Text: fmt.Sprintf("%s — Current: %s, Target: %s", f.Title, f.Current, f.Target)},
				Help:             textMsg{Text: help},
				Properties: ruleProps{
					Tags: []string{"security", fmt.Sprintf("severity/%s", f.Severity)},
				},
			}
			idx[f.CheckID] = len(rules)
			rules = append(rules, rule)
		}
	}
	return rules, idx
}

func buildSARIFResults(r *Report, ruleIdx map[string]int) []sarifResult {
	var results []sarifResult
	for _, mod := range r.Modules {
		for _, f := range mod.Findings {
			if f.Status == "compliant" || f.Status == "skipped" {
				continue
			}

			msg := f.Title
			if f.Detail != "" {
				msg = fmt.Sprintf("%s: %s", f.Title, f.Detail)
			} else if f.Current != "" && f.Target != "" {
				msg = fmt.Sprintf("%s — Current: %s, Expected: %s", f.Title, f.Current, f.Target)
			}

			results = append(results, sarifResult{
				RuleID:    f.CheckID,
				RuleIndex: ruleIdx[f.CheckID],
				Level:     sarifLevel(f.Severity),
				Message:   textMsg{Text: msg},
			})
		}
	}
	return results
}
