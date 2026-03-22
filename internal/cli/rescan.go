package cli

import (
	"context"
	"fmt"
	"time"

	"github.com/spf13/cobra"

	"github.com/defenseclaw/defenseclaw/internal/enforce"
	"github.com/defenseclaw/defenseclaw/internal/scanner"
)

var rescanCmd = &cobra.Command{
	Use:   "rescan",
	Short: "Re-scan all known skills and MCP servers",
	Long: `Re-scans all items on block and allow lists.
Auto-blocks targets with HIGH/CRITICAL findings.
Items that are now clean are moved to the allow list.`,
	RunE: runRescan,
}

func init() {
	rootCmd.AddCommand(rescanCmd)
}

func runRescan(cmd *cobra.Command, _ []string) error {
	pe := enforce.NewPolicyEngine(auditStore)
	ctx, cancel := context.WithTimeout(cmd.Context(), 10*time.Minute)
	defer cancel()

	fmt.Println("Re-scanning all known targets...")
	fmt.Println()

	blocked, _ := pe.ListBlocked()
	allowed, _ := pe.ListAllowed()

	type target struct {
		name       string
		targetType string
	}

	seen := make(map[string]bool)
	var targets []target
	for _, b := range blocked {
		key := b.TargetType + ":" + b.TargetName
		if !seen[key] {
			seen[key] = true
			targets = append(targets, target{name: b.TargetName, targetType: b.TargetType})
		}
	}
	for _, a := range allowed {
		key := a.TargetType + ":" + a.TargetName
		if !seen[key] {
			seen[key] = true
			targets = append(targets, target{name: a.TargetName, targetType: a.TargetType})
		}
	}

	if len(targets) == 0 {
		fmt.Println("No targets to re-scan. Block or allow some items first.")
		return nil
	}

	var newBlocks, newAllows int

	for _, t := range targets {
		var s scanner.Scanner
		switch t.targetType {
		case "skill":
			s = scanner.NewSkillScanner(cfg.Scanners.SkillScanner)
		case "mcp":
			s = scanner.NewMCPScanner(cfg.Scanners.MCPScanner)
		case "code":
			s = scanner.NewCodeGuardScanner(cfg.Scanners.CodeGuard)
		default:
			continue
		}

		fmt.Printf("  [rescan] %s %q\n", t.targetType, t.name)
		result, err := s.Scan(ctx, t.name)
		if err != nil {
			fmt.Printf("    Error: %v\n", err)
			continue
		}

		if auditLog != nil {
			_ = auditLog.LogScan(result)
		}

		if result.HasSeverity(scanner.SeverityHigh) || result.HasSeverity(scanner.SeverityCritical) {
			wasBlocked, _ := pe.IsBlocked(t.targetType, t.name)
			if !wasBlocked {
				reason := fmt.Sprintf("rescan: %d findings, max_severity=%s", len(result.Findings), result.MaxSeverity())
				_ = pe.Block(t.targetType, t.name, reason)
				newBlocks++
				fmt.Printf("    BLOCKED — %s (%d findings)\n", result.MaxSeverity(), len(result.Findings))
			} else {
				fmt.Printf("    Still blocked — %s (%d findings)\n", result.MaxSeverity(), len(result.Findings))
			}
		} else {
			wasBlocked, _ := pe.IsBlocked(t.targetType, t.name)
			if wasBlocked {
				reason := fmt.Sprintf("rescan: now clean (max_severity=%s)", result.MaxSeverity())
				_ = pe.Allow(t.targetType, t.name, reason)
				newAllows++
				fmt.Printf("    UNBLOCKED — now clean (%s)\n", result.MaxSeverity())
			} else {
				fmt.Printf("    Clean (%s)\n", result.MaxSeverity())
			}
		}

		if auditLog != nil {
			_ = auditLog.LogAction("rescan", t.name,
				fmt.Sprintf("type=%s findings=%d max_severity=%s", t.targetType, len(result.Findings), result.MaxSeverity()))
		}
	}

	fmt.Println()
	fmt.Printf("Re-scan complete: %d targets scanned, %d newly blocked, %d unblocked\n",
		len(targets), newBlocks, newAllows)
	return nil
}
