package cli

import (
	"context"
	"fmt"
	"os"
	"time"

	"github.com/spf13/cobra"

	"github.com/defenseclaw/defenseclaw/internal/audit"
	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/enforce"
	"github.com/defenseclaw/defenseclaw/internal/sandbox"
	"github.com/defenseclaw/defenseclaw/internal/scanner"
)

var deploySkipInit bool

var deployCmd = &cobra.Command{
	Use:   "deploy [path]",
	Short: "Deploy OpenClaw in a secured sandbox",
	Long: `Full orchestrated deployment:
  1. Initialize if needed
  2. Run all scanners (skills + MCP + AIBOM + CodeGuard)
  3. Auto-block anything HIGH/CRITICAL
  4. Generate OpenShell sandbox policy
  5. Start OpenClaw in sandbox
  6. Print summary`,
	Args: cobra.MaximumNArgs(1),
	RunE: runDeploy,
}

func init() {
	deployCmd.Flags().BoolVar(&deploySkipInit, "skip-init", false, "Skip initialization step")
	rootCmd.AddCommand(deployCmd)
}

func runDeploy(cmd *cobra.Command, args []string) error {
	target := "."
	if len(args) > 0 {
		target = args[0]
	}
	start := time.Now()

	fmt.Println("╔══════════════════════════════════════════════╗")
	fmt.Println("║         DefenseClaw Deploy                   ║")
	fmt.Println("╚══════════════════════════════════════════════╝")
	fmt.Println()

	// Step 1: Init
	if !deploySkipInit {
		fmt.Println("Step 1/5: Initializing...")
		if err := ensureInit(); err != nil {
			return fmt.Errorf("deploy: init failed: %w", err)
		}
		fmt.Println("  Done.")
	} else {
		fmt.Println("Step 1/5: Init skipped (--skip-init)")
	}
	fmt.Println()

	// Step 2: Full scan
	fmt.Println("Step 2/5: Running all scanners...")
	results := runAllScanners(cmd.Context(), target)
	fmt.Println()

	// Step 3: Auto-block HIGH/CRITICAL
	fmt.Println("Step 3/5: Enforcing policy (auto-blocking HIGH/CRITICAL)...")
	blocked := autoBlockFindings(results)
	if blocked > 0 {
		fmt.Printf("  Auto-blocked %d targets\n", blocked)
	} else {
		fmt.Println("  No targets blocked")
	}
	fmt.Println()

	// Step 4: Generate sandbox policy
	fmt.Println("Step 4/5: Generating sandbox policy...")
	shell := sandbox.NewWithFallback(cfg.OpenShell.Binary, cfg.OpenShell.PolicyDir, cfg.PolicyDir)
	if err := generateSandboxPolicy(shell); err != nil {
		fmt.Printf("  Warning: %v\n", err)
	} else {
		fmt.Println("  Policy written")
	}
	fmt.Println()

	// Step 5: Start sandbox
	fmt.Println("Step 5/5: Starting sandbox...")
	if shell.IsAvailable() {
		policyPath := shell.PolicyPath()
		if _, err := os.Stat(policyPath); err != nil {
			pp := cfg.PolicyDir + "/defenseclaw-policy.yaml"
			if _, e2 := os.Stat(pp); e2 == nil {
				policyPath = pp
			}
		}
		if err := shell.Start(policyPath); err != nil {
			fmt.Printf("  Warning: could not start sandbox: %v\n", err)
		} else {
			fmt.Println("  OpenShell sandbox started")
		}
	} else {
		env := config.Environment(cfg.Environment)
		switch env {
		case config.EnvMacOS:
			fmt.Println("  OpenShell not available on macOS — sandbox enforcement skipped")
		default:
			fmt.Println("  OpenShell not found — sandbox enforcement will not be active")
			fmt.Println("  Install OpenShell for full sandbox enforcement")
		}
	}
	fmt.Println()

	// Summary
	elapsed := time.Since(start)
	printDeploySummary(results, blocked, elapsed)

	if auditLog != nil {
		_ = auditLog.LogAction("deploy", target, fmt.Sprintf("duration=%s blocked=%d", elapsed.Round(time.Millisecond), blocked))
	}

	return nil
}

func ensureInit() error {
	if _, err := os.Stat(config.ConfigPath()); err == nil {
		return nil
	}

	defaults := config.DefaultConfig()
	dirs := []string{defaults.DataDir, defaults.QuarantineDir, defaults.PluginDir, defaults.PolicyDir}
	for _, dir := range dirs {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			return err
		}
	}
	if err := defaults.Save(); err != nil {
		return err
	}

	store, err := audit.NewStore(defaults.AuditDB)
	if err != nil {
		return err
	}
	defer store.Close()
	if err := store.Init(); err != nil {
		return err
	}

	cfg = defaults
	auditStore, err = audit.NewStore(cfg.AuditDB)
	if err != nil {
		return err
	}
	auditLog = audit.NewLogger(auditStore)
	return nil
}

type scanRun struct {
	scanner string
	target  string
	result  *scanner.ScanResult
	err     error
}

func runAllScanners(ctx context.Context, target string) []scanRun {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Minute)
	defer cancel()

	scanners := []scanner.Scanner{
		scanner.NewSkillScanner(cfg.Scanners.SkillScanner),
		scanner.NewMCPScanner(cfg.Scanners.MCPScanner),
		scanner.NewAIBOMScanner(cfg.Scanners.AIBOM),
		scanner.NewCodeGuardScanner(cfg.Scanners.CodeGuard),
	}

	var runs []scanRun
	for _, s := range scanners {
		fmt.Printf("  [scan] %s -> %s\n", s.Name(), target)
		result, err := s.Scan(ctx, target)

		run := scanRun{scanner: s.Name(), target: target, result: result, err: err}
		runs = append(runs, run)

		if err != nil {
			fmt.Printf("    Error: %v\n", err)
			continue
		}
		if result.IsClean() {
			fmt.Printf("    Clean (%s)\n", result.Duration.Round(time.Millisecond))
		} else {
			fmt.Printf("    Findings: %d (max: %s, %s)\n",
				len(result.Findings), result.MaxSeverity(), result.Duration.Round(time.Millisecond))
		}
		if auditLog != nil {
			_ = auditLog.LogScan(result)
		}
	}
	return runs
}

func autoBlockFindings(runs []scanRun) int {
	if auditStore == nil {
		return 0
	}

	pe := enforce.NewPolicyEngine(auditStore)
	blocked := 0

	for _, run := range runs {
		if run.err != nil || run.result == nil {
			continue
		}
		r := run.result
		if !r.HasSeverity(scanner.SeverityHigh) && !r.HasSeverity(scanner.SeverityCritical) {
			continue
		}

		targetType := "skill"
		if run.scanner == "mcp-scanner" {
			targetType = "mcp"
		} else if run.scanner == "codeguard" {
			targetType = "code"
		}

		already, _ := pe.IsBlocked(targetType, r.Target)
		if already {
			continue
		}

		reason := fmt.Sprintf("auto-block: %d findings, max_severity=%s (scanner=%s)",
			len(r.Findings), r.MaxSeverity(), run.scanner)
		if err := pe.Block(targetType, r.Target, reason); err == nil {
			blocked++
			fmt.Printf("  Blocked: %s %q (%s)\n", targetType, r.Target, r.MaxSeverity())
			if auditLog != nil {
				_ = auditLog.LogAction("auto-block", r.Target,
					fmt.Sprintf("type=%s severity=%s scanner=%s", targetType, r.MaxSeverity(), run.scanner))
			}
		}
	}
	return blocked
}

func generateSandboxPolicy(shell *sandbox.OpenShell) error {
	policy, err := shell.LoadPolicy()
	if err != nil {
		return err
	}

	if auditStore != nil {
		blockedMCPs, _ := auditStore.ListByActionAndType("install", "block", "mcp")
		for _, b := range blockedMCPs {
			policy.DenyEndpoint(b.TargetName)
		}
		blockedSkills, _ := auditStore.ListByActionAndType("install", "block", "skill")
		for _, b := range blockedSkills {
			policy.DenySkill(b.TargetName)
		}
		allowedSkills, _ := auditStore.ListByActionAndType("install", "allow", "skill")
		for _, a := range allowedSkills {
			policy.AllowSkill(a.TargetName)
		}
	}

	return shell.SavePolicy(policy)
}

func printDeploySummary(runs []scanRun, blocked int, elapsed time.Duration) {
	fmt.Println("════════════════════════════════════════════════")
	fmt.Println("  Deploy Summary")
	fmt.Println("════════════════════════════════════════════════")

	totalFindings := 0
	maxSev := scanner.SeverityInfo
	for _, run := range runs {
		if run.result != nil {
			totalFindings += len(run.result.Findings)
			if scanner.CompareSeverity(run.result.MaxSeverity(), maxSev) > 0 {
				maxSev = run.result.MaxSeverity()
			}
		}
	}

	fmt.Printf("  Scanners run:     %d\n", len(runs))
	fmt.Printf("  Total findings:   %d\n", totalFindings)
	fmt.Printf("  Max severity:     %s\n", maxSev)
	fmt.Printf("  Auto-blocked:     %d\n", blocked)
	fmt.Printf("  Duration:         %s\n", elapsed.Round(time.Millisecond))
	fmt.Println()
	fmt.Println("  Run 'defenseclaw tui' for the live dashboard.")
	fmt.Println("  Run 'defenseclaw status' to check deployment health.")
}
