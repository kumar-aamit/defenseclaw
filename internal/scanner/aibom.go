package scanner

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"time"
)

type AIBOMScanner struct {
	BinaryPath string
}

func NewAIBOMScanner(binaryPath string) *AIBOMScanner {
	if binaryPath == "" {
		binaryPath = "cisco-aibom"
	}
	return &AIBOMScanner{BinaryPath: binaryPath}
}

func (s *AIBOMScanner) Name() string              { return "aibom" }
func (s *AIBOMScanner) Version() string            { return "1.0.0" }
func (s *AIBOMScanner) SupportedTargets() []string { return []string{"skill", "mcp", "code"} }

func (s *AIBOMScanner) Scan(ctx context.Context, target string) (*ScanResult, error) {
	start := time.Now()

	tmpFile, err := os.CreateTemp("", "defenseclaw-aibom-*.json")
	if err != nil {
		return nil, fmt.Errorf("scanner: %s: create temp file: %w", s.Name(), err)
	}
	tmpPath := tmpFile.Name()
	tmpFile.Close()
	defer os.Remove(tmpPath)

	cmd := exec.CommandContext(ctx, s.BinaryPath, "analyze", target, "--output-format", "json", "--output-file", tmpPath)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr

	err = cmd.Run()
	duration := time.Since(start)

	result := &ScanResult{
		Scanner:   s.Name(),
		Target:    target,
		Timestamp: start,
		Duration:  duration,
	}

	if err != nil {
		if errors.Is(err, exec.ErrNotFound) {
			return nil, fmt.Errorf("scanner: %s not found at %q — install with: uv tool install cisco-aibom", s.Name(), s.BinaryPath)
		}
		stderrStr := stderr.String()
		if _, statErr := os.Stat(tmpPath); statErr != nil {
			return nil, fmt.Errorf("scanner: %s failed: %s", s.Name(), stderrStr)
		}
	}

	data, readErr := os.ReadFile(tmpPath)
	if readErr == nil && len(data) > 0 {
		findings, parseErr := parseAIBOMOutput(data)
		if parseErr != nil {
			return nil, fmt.Errorf("scanner: failed to parse %s output: %w", s.Name(), parseErr)
		}
		result.Findings = findings
	}

	return result, nil
}

type aibomOutput struct {
	Analysis *aibomAnalysis `json:"aibom_analysis"`
}

type aibomAnalysis struct {
	Sources map[string]aibomSource `json:"sources"`
	Summary aibomSummary           `json:"summary"`
}

type aibomSource struct {
	Components      map[string][]aibomComponent `json:"components"`
	TotalComponents int                         `json:"total_components"`
}

type aibomSummary struct {
	TotalComponents int            `json:"total_components"`
	Categories      map[string]int `json:"categories"`
}

type aibomComponent struct {
	Name     string `json:"name"`
	FilePath string `json:"file_path"`
	Category string `json:"category"`
}

func parseAIBOMOutput(data []byte) ([]Finding, error) {
	var out aibomOutput
	if err := json.Unmarshal(data, &out); err != nil {
		return nil, err
	}

	var findings []Finding

	if out.Analysis != nil {
		for source, s := range out.Analysis.Sources {
			for category, components := range s.Components {
				for _, c := range components {
					findings = append(findings, Finding{
						ID:          fmt.Sprintf("AIBOM-%s-%s", category, c.Name),
						Severity:    SeverityInfo,
						Title:       fmt.Sprintf("[%s] %s", category, c.Name),
						Description: fmt.Sprintf("Source: %s, File: %s", source, c.FilePath),
						Location:    c.FilePath,
						Scanner:     "aibom",
						Tags:        []string{category},
					})
				}
			}
		}
	}

	return findings, nil
}
