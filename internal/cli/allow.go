package cli

import (
	"context"
	"fmt"
	"path/filepath"
	"time"

	"github.com/spf13/cobra"

	"github.com/defenseclaw/defenseclaw/internal/enforce"
	"github.com/defenseclaw/defenseclaw/internal/sandbox"
	"github.com/defenseclaw/defenseclaw/internal/scanner"
)

var allowReason string
var skipRescan bool

var allowCmd = &cobra.Command{
	Use:   "allow",
	Short: "Allow a previously blocked skill or MCP server",
}

var allowSkillCmd = &cobra.Command{
	Use:   "skill <name-or-path>",
	Short: "Allow a skill — re-scan and restore if clean",
	Args:  cobra.ExactArgs(1),
	RunE:  runAllowSkill,
}

var allowMCPCmd = &cobra.Command{
	Use:   "mcp <url>",
	Short: "Allow an MCP server — re-scan and add to allow-list if clean",
	Args:  cobra.ExactArgs(1),
	RunE:  runAllowMCP,
}

func init() {
	allowSkillCmd.Flags().StringVar(&allowReason, "reason", "", "Reason for allowing")
	allowSkillCmd.Flags().BoolVar(&skipRescan, "skip-rescan", false, "Skip re-scan before allowing")
	allowMCPCmd.Flags().StringVar(&allowReason, "reason", "", "Reason for allowing")
	allowMCPCmd.Flags().BoolVar(&skipRescan, "skip-rescan", false, "Skip re-scan before allowing")
	rootCmd.AddCommand(allowCmd)
	allowCmd.AddCommand(allowSkillCmd)
	allowCmd.AddCommand(allowMCPCmd)
}

func runAllowSkill(_ *cobra.Command, args []string) error {
	skillArg := args[0]
	skillName := filepath.Base(skillArg)

	pe := enforce.NewPolicyEngine(auditStore)
	shell := sandbox.NewWithFallback(cfg.OpenShell.Binary, cfg.OpenShell.PolicyDir, cfg.PolicyDir)
	se := enforce.NewSkillEnforcer(cfg.QuarantineDir, shell)

	if !skipRescan {
		scanTarget := skillArg
		if se.IsQuarantined(skillName) {
			scanTarget = cfg.QuarantineDir + "/skills/" + skillName
		} else if !filepath.IsAbs(scanTarget) {
			if resolved := resolveInstalledSkillPath(skillName); resolved != "" {
				scanTarget = resolved
			}
		}

		fmt.Printf("[allow] Re-scanning %q before allowing...\n", scanTarget)
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
		defer cancel()

		s := scanner.NewSkillScanner(cfg.Scanners.SkillScanner)
		result, err := s.Scan(ctx, scanTarget)
		if err != nil {
			return fmt.Errorf("allow: re-scan failed: %w", err)
		}

		if result.HasSeverity(scanner.SeverityHigh) || result.HasSeverity(scanner.SeverityCritical) {
			fmt.Printf("[allow] REJECTED — skill still has %s findings\n", result.MaxSeverity())
			fmt.Printf("  Findings: %d (HIGH: %d, CRITICAL: %d)\n",
				len(result.Findings),
				result.CountBySeverity(scanner.SeverityHigh),
				result.CountBySeverity(scanner.SeverityCritical))
			_ = auditLog.LogAction("allow-skill-rejected", skillName,
				fmt.Sprintf("max_severity=%s findings=%d", result.MaxSeverity(), len(result.Findings)))
			return fmt.Errorf("skill %q has HIGH/CRITICAL findings — cannot allow", skillName)
		}

		if auditLog != nil {
			_ = auditLog.LogScan(result)
		}
		fmt.Printf("[allow] Re-scan clean (max severity: %s)\n", result.MaxSeverity())
	}

	reason := allowReason
	if reason == "" {
		reason = "manual allow"
	}

	if err := pe.Allow("skill", skillName, reason); err != nil {
		return fmt.Errorf("allow skill: %w", err)
	}
	_ = pe.ClearQuarantine("skill", skillName)
	_ = pe.Enable("skill", skillName)
	if resolved := resolveInstalledSkillPath(skillName); resolved != "" {
		pe.SetSourcePath("skill", skillName, resolved)
	}
	fmt.Printf("[allow] Skill %q added to allow list\n", skillName)

	if se.IsQuarantined(skillName) {
		if err := se.Restore(skillName, skillName); err != nil {
			fmt.Printf("[allow] Warning: could not restore from quarantine: %v\n", err)
		} else {
			fmt.Printf("[allow] Skill restored from quarantine\n")
		}
	}

	pErr := se.UpdateSandboxPolicy(skillName, false)
	if pErr != nil {
		if !shell.IsAvailable() {
			fmt.Println("[allow] OpenShell not detected — policy written but not enforced")
		} else {
			fmt.Printf("[allow] Warning: could not update sandbox policy: %v\n", pErr)
		}
	} else {
		if shell.IsAvailable() {
			fmt.Println("[allow] Sandbox policy updated and reloaded")
		} else {
			fmt.Println("[allow] Sandbox policy written (OpenShell not available — not enforced)")
		}
	}

	_ = auditLog.LogAction("allow-skill", skillName, fmt.Sprintf("reason=%s", reason))
	fmt.Printf("[allow] Audit event recorded\n")
	return nil
}

func runAllowMCP(_ *cobra.Command, args []string) error {
	url := args[0]

	pe := enforce.NewPolicyEngine(auditStore)
	shell := sandbox.NewWithFallback(cfg.OpenShell.Binary, cfg.OpenShell.PolicyDir, cfg.PolicyDir)
	me := enforce.NewMCPEnforcer(shell)

	if !skipRescan {
		fmt.Printf("[allow] Re-scanning %q before allowing...\n", url)
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
		defer cancel()

		s := scanner.NewMCPScanner(cfg.Scanners.MCPScanner)
		result, err := s.Scan(ctx, url)
		if err != nil {
			return fmt.Errorf("allow: re-scan failed: %w", err)
		}

		if result.HasSeverity(scanner.SeverityHigh) || result.HasSeverity(scanner.SeverityCritical) {
			fmt.Printf("[allow] REJECTED — MCP server still has %s findings\n", result.MaxSeverity())
			_ = auditLog.LogAction("allow-mcp-rejected", url,
				fmt.Sprintf("max_severity=%s findings=%d", result.MaxSeverity(), len(result.Findings)))
			return fmt.Errorf("MCP server %q has HIGH/CRITICAL findings — cannot allow", url)
		}

		if auditLog != nil {
			_ = auditLog.LogScan(result)
		}
		fmt.Printf("[allow] Re-scan clean (max severity: %s)\n", result.MaxSeverity())
	}

	reason := allowReason
	if reason == "" {
		reason = "manual allow"
	}

	if err := pe.Allow("mcp", url, reason); err != nil {
		return fmt.Errorf("allow mcp: %w", err)
	}
	fmt.Printf("[allow] MCP server %q added to allow list\n", url)

	if err := me.AllowEndpoint(url); err != nil {
		if !shell.IsAvailable() {
			fmt.Println("[allow] OpenShell not detected — policy written but not enforced")
		} else {
			fmt.Printf("[allow] Warning: could not update sandbox policy: %v\n", err)
		}
	} else {
		if shell.IsAvailable() {
			fmt.Println("[allow] Network allow-list updated and sandbox policy reloaded")
		} else {
			fmt.Println("[allow] Network allow-list written (OpenShell not available — not enforced)")
		}
	}

	_ = auditLog.LogAction("allow-mcp", url, fmt.Sprintf("reason=%s", reason))
	fmt.Printf("[allow] Audit event recorded\n")
	return nil
}
