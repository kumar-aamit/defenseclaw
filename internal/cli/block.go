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

var blockReason string

var blockCmd = &cobra.Command{
	Use:   "block",
	Short: "Block a skill or MCP server",
}

var blockSkillCmd = &cobra.Command{
	Use:   "skill <name-or-path>",
	Short: "Block a skill — quarantine files and update sandbox policy",
	Args:  cobra.ExactArgs(1),
	RunE:  runBlockSkill,
}

var blockMCPCmd = &cobra.Command{
	Use:   "mcp <url>",
	Short: "Block an MCP server — add to network deny-list",
	Args:  cobra.ExactArgs(1),
	RunE:  runBlockMCP,
}

func init() {
	blockSkillCmd.Flags().StringVar(&blockReason, "reason", "", "Reason for blocking")
	blockMCPCmd.Flags().StringVar(&blockReason, "reason", "", "Reason for blocking")
	rootCmd.AddCommand(blockCmd)
	blockCmd.AddCommand(blockSkillCmd)
	blockCmd.AddCommand(blockMCPCmd)
}

func runBlockSkill(_ *cobra.Command, args []string) error {
	skillArg := args[0]
	skillName := filepath.Base(skillArg)
	skillPath := skillArg
	if !filepath.IsAbs(skillPath) {
		if resolved := resolveInstalledSkillPath(skillName); resolved != "" {
			skillPath = resolved
		}
	}

	pe := enforce.NewPolicyEngine(auditStore)
	blocked, err := pe.IsBlocked("skill", skillName)
	if err != nil {
		return err
	}
	if blocked {
		fmt.Printf("Skill %q is already blocked.\n", skillName)
		return nil
	}

	shell := sandbox.NewWithFallback(cfg.OpenShell.Binary, cfg.OpenShell.PolicyDir, cfg.PolicyDir)
	se := enforce.NewSkillEnforcer(cfg.QuarantineDir, shell)

	reason := blockReason
	if reason == "" {
		reason = "manual block"
	}

	if err := pe.Block("skill", skillName, reason); err != nil {
		return fmt.Errorf("block skill: %w", err)
	}
	if filepath.IsAbs(skillPath) {
		pe.SetSourcePath("skill", skillName, skillPath)
	}
	fmt.Printf("[block] Skill %q added to block list\n", skillName)

	dest, qErr := se.Quarantine(skillPath)
	if qErr != nil {
		fmt.Printf("[block] Warning: could not quarantine skill files: %v\n", qErr)
		fmt.Printf("        Skill is blocked in the database but files were not moved.\n")
	} else {
		fmt.Printf("[block] Skill quarantined to %s\n", dest)
		_ = pe.Quarantine("skill", skillName, reason)
	}

	pErr := se.UpdateSandboxPolicy(skillName, true)
	if pErr != nil {
		if !shell.IsAvailable() {
			fmt.Println("[block] OpenShell not detected — policy written but not enforced")
		} else {
			fmt.Printf("[block] Warning: could not update sandbox policy: %v\n", pErr)
		}
	} else {
		if shell.IsAvailable() {
			fmt.Println("[block] Sandbox policy updated and reloaded")
		} else {
			fmt.Println("[block] Sandbox policy written (OpenShell not available — not enforced)")
		}
	}

	_ = auditLog.LogAction("block-skill", skillName, fmt.Sprintf("reason=%s", reason))
	fmt.Printf("[block] Audit event recorded\n")
	return nil
}

func runBlockMCP(_ *cobra.Command, args []string) error {
	url := args[0]

	pe := enforce.NewPolicyEngine(auditStore)
	blocked, err := pe.IsBlocked("mcp", url)
	if err != nil {
		return err
	}
	if blocked {
		fmt.Printf("MCP server %q is already blocked.\n", url)
		return nil
	}

	shell := sandbox.NewWithFallback(cfg.OpenShell.Binary, cfg.OpenShell.PolicyDir, cfg.PolicyDir)
	me := enforce.NewMCPEnforcer(shell)

	reason := blockReason
	if reason == "" {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
		defer cancel()
		s := scanner.NewMCPScanner(cfg.Scanners.MCPScanner)
		result, scanErr := s.Scan(ctx, url)
		if scanErr == nil && !result.IsClean() {
			reason = fmt.Sprintf("scan: %d findings, max_severity=%s", len(result.Findings), result.MaxSeverity())
		} else {
			reason = "manual block"
		}
	}

	if err := pe.Block("mcp", url, reason); err != nil {
		return fmt.Errorf("block mcp: %w", err)
	}
	fmt.Printf("[block] MCP server %q added to block list\n", url)

	if err := me.BlockEndpoint(url); err != nil {
		if !shell.IsAvailable() {
			fmt.Println("[block] OpenShell not detected — policy written but not enforced")
		} else {
			fmt.Printf("[block] Warning: could not update sandbox policy: %v\n", err)
		}
	} else {
		if shell.IsAvailable() {
			fmt.Println("[block] Network deny-list updated and sandbox policy reloaded")
		} else {
			fmt.Println("[block] Network deny-list written (OpenShell not available — not enforced)")
		}
	}

	_ = auditLog.LogAction("block-mcp", url, fmt.Sprintf("reason=%s", reason))
	fmt.Printf("[block] Audit event recorded\n")
	return nil
}
