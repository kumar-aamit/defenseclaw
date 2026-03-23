package cli

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	runewidth "github.com/mattn/go-runewidth"
	"github.com/spf13/cobra"

	"github.com/defenseclaw/defenseclaw/internal/audit"
	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/enforce"
	"github.com/defenseclaw/defenseclaw/internal/gateway"
	"github.com/defenseclaw/defenseclaw/internal/sandbox"
	"github.com/defenseclaw/defenseclaw/internal/scanner"
)

var skillCmd = &cobra.Command{
	Use:   "skill",
	Short: "Manage OpenClaw skills — install, scan, block, allow, disable, enable, quarantine, restore",
}

var skillDisableCmd = &cobra.Command{
	Use:   "disable <skill>",
	Short: "Disable a skill at runtime via the OpenClaw gateway",
	Long: `Send a skills.update RPC to the OpenClaw gateway to disable a skill in the
running session. This prevents the agent from using the skill's tools until
it is re-enabled.

This is a runtime-only action — it does not affect the install block list or
quarantine the skill's files. Use 'skill block' or 'skill quarantine' for those.

Requires the gateway to be running.`,
	Args: cobra.ExactArgs(1),
	RunE: runSkillDisable,
}

var skillEnableCmd = &cobra.Command{
	Use:   "enable <skill>",
	Short: "Enable a previously disabled skill via the OpenClaw gateway",
	Long: `Send a skills.update RPC to the OpenClaw gateway to re-enable a skill.

This is a runtime-only action.`,
	Args: cobra.ExactArgs(1),
	RunE: runSkillEnable,
}

var skillBlockCmd = &cobra.Command{
	Use:   "block <skill>",
	Short: "Add a skill to the install block list",
	Long: `Block a skill from being installed in the future. Blocked skills are rejected
by 'skill install' before any scan is performed.

This does not affect a skill that is already installed or running — use
'skill disable' or 'skill quarantine' for that.`,
	Args: cobra.ExactArgs(1),
	RunE: runSkillBlock,
}

var skillAllowCmd = &cobra.Command{
	Use:   "allow <skill>",
	Short: "Add a skill to the install allow list",
	Long: `Allow-list a skill so that 'skill install' skips the scan gate.
Adding a skill to the allow list also removes it from the block list.`,
	Args: cobra.ExactArgs(1),
	RunE: runSkillAllow,
}

var skillQuarantineCmd = &cobra.Command{
	Use:   "quarantine <skill>",
	Short: "Quarantine a skill's files and deny it in the sandbox policy",
	Long: `Move a skill's directory to the quarantine area and update the OpenShell
sandbox policy to deny it. The skill's files are preserved and can be
restored with 'skill restore'.`,
	Args: cobra.ExactArgs(1),
	RunE: runSkillQuarantine,
}

var skillRestoreCmd = &cobra.Command{
	Use:   "restore <skill>",
	Short: "Restore a quarantined skill",
	Long: `Move a previously quarantined skill back to its original location and
re-allow it in the OpenShell sandbox policy.

By default, restores to the original path recorded during quarantine.
Use --path to override the restore destination.`,
	Args: cobra.ExactArgs(1),
	RunE: runSkillRestore,
}

var skillScanCmd = &cobra.Command{
	Use:   "scan <skill-name|all>",
	Short: "Scan a skill by name or all configured skills",
	Long: `Run skill-scanner against a skill and report a pass/fail verdict.

The skill path is resolved automatically via 'openclaw skills info'.
Use --path to override with an explicit directory.
Use 'all' to scan all skills in the configured skill directories.`,
	Args: cobra.ExactArgs(1),
	RunE: runSkillScan,
}

var skillInfoCmd = &cobra.Command{
	Use:   "info <skill-name>",
	Short: "Show detailed information about a skill",
	Long: `Display merged skill metadata from OpenClaw, latest scan results from the
DefenseClaw audit database, and enforcement actions (block/allow/quarantine/disable).`,
	Args: cobra.ExactArgs(1),
	RunE: runSkillInfo,
}

var skillListCmd = &cobra.Command{
	Use:   "list",
	Short: "List all OpenClaw skills with their latest scan severity",
	Long: `List all skills from 'openclaw skills list' merged with the latest
scan results from the DefenseClaw audit database.

Shows skill name, status, description, source, and the severity from
the most recent skill-scanner run (if any).`,
	RunE: runSkillList,
}

var skillInstallCmd = &cobra.Command{
	Use:   "install <skill>",
	Short: "Install and scan an OpenClaw skill via clawhub",
	Long: `Install a skill from ClawHub using 'npx @clawhub install', then scan it.

By default, install only runs the scan and reports findings — no enforcement
actions are taken. Pass --action to apply the configured skill_actions policy
(quarantine, disable, block) based on scan severity.

Use --force to pass the --force flag to clawhub (overwrites existing).`,
	Args: cobra.ExactArgs(1),
	RunE: runSkillInstall,
}

var (
	skillActionReason   string
	skillScanJSON       bool
	skillScanPath       string
	skillInfoJSON       bool
	skillInstallForce   bool
	skillInstallJSON    bool
	skillInstallAction  bool
	skillListJSON       bool
	skillRestorePath    string
)

func init() {
	skillDisableCmd.Flags().StringVar(&skillActionReason, "reason", "", "Reason for the action")
	skillBlockCmd.Flags().StringVar(&skillActionReason, "reason", "", "Reason for blocking")
	skillAllowCmd.Flags().StringVar(&skillActionReason, "reason", "", "Reason for allowing")
	skillQuarantineCmd.Flags().StringVar(&skillActionReason, "reason", "", "Reason for quarantine")
	skillRestoreCmd.Flags().StringVar(&skillRestorePath, "path", "", "Override restore destination (defaults to original path)")
	skillScanCmd.Flags().BoolVar(&skillScanJSON, "json", false, "Output scan results as JSON")
	skillScanCmd.Flags().StringVar(&skillScanPath, "path", "", "Override skill directory path")
	skillInfoCmd.Flags().BoolVar(&skillInfoJSON, "json", false, "Output skill info as JSON")
	skillInstallCmd.Flags().BoolVar(&skillInstallForce, "force", false, "Force install (overwrites existing)")
	skillInstallCmd.Flags().BoolVar(&skillInstallJSON, "json", false, "Output results as JSON")
	skillInstallCmd.Flags().BoolVar(&skillInstallAction, "action", false, "Apply skill_actions policy based on scan severity")
	skillListCmd.Flags().BoolVar(&skillListJSON, "json", false, "Output merged skill list as JSON")

	skillCmd.AddCommand(skillDisableCmd)
	skillCmd.AddCommand(skillEnableCmd)
	skillCmd.AddCommand(skillBlockCmd)
	skillCmd.AddCommand(skillAllowCmd)
	skillCmd.AddCommand(skillQuarantineCmd)
	skillCmd.AddCommand(skillRestoreCmd)
	skillCmd.AddCommand(skillScanCmd)
	skillCmd.AddCommand(skillInfoCmd)
	skillCmd.AddCommand(skillInstallCmd)
	skillCmd.AddCommand(skillListCmd)
	rootCmd.AddCommand(skillCmd)
}

// --- Runtime actions (gateway RPC) ---

func runSkillDisable(_ *cobra.Command, args []string) error {
	skillName := filepath.Base(args[0])

	if err := disableViaGateway(skillName); err != nil {
		return fmt.Errorf("skill disable: %w", err)
	}
	fmt.Printf("[skill] %q disabled via gateway RPC\n", skillName)

	reason := skillActionReason
	if reason == "" {
		reason = "manual disable via CLI"
	}

	pe := enforce.NewPolicyEngine(auditStore)
	_ = pe.Disable("skill", skillName, reason)

	_ = auditLog.LogAction("skill-disable", skillName, fmt.Sprintf("reason=%s", reason))
	return nil
}

func runSkillEnable(_ *cobra.Command, args []string) error {
	skillName := filepath.Base(args[0])

	if err := enableViaGateway(skillName); err != nil {
		return fmt.Errorf("skill enable: %w", err)
	}
	fmt.Printf("[skill] %q enabled via gateway RPC\n", skillName)

	pe := enforce.NewPolicyEngine(auditStore)
	_ = pe.Enable("skill", skillName)

	_ = auditLog.LogAction("skill-enable", skillName, "re-enabled via CLI")
	return nil
}

// --- Install-level actions (block/allow list in SQLite) ---

func runSkillBlock(_ *cobra.Command, args []string) error {
	skillName := filepath.Base(args[0])
	pe := enforce.NewPolicyEngine(auditStore)

	reason := skillActionReason
	if reason == "" {
		reason = "manual block via CLI"
	}

	if err := pe.Block("skill", skillName, reason); err != nil {
		return fmt.Errorf("skill block: %w", err)
	}
	if skillPath := resolveInstalledSkillPath(skillName); skillPath != "" {
		pe.SetSourcePath("skill", skillName, skillPath)
	}
	fmt.Printf("[skill] %q added to block list\n", skillName)

	_ = auditLog.LogAction("skill-block", skillName, fmt.Sprintf("reason=%s", reason))
	return nil
}

func runSkillAllow(_ *cobra.Command, args []string) error {
	skillName := filepath.Base(args[0])
	pe := enforce.NewPolicyEngine(auditStore)

	reason := skillActionReason
	if reason == "" {
		reason = "manual allow via CLI"
	}

	if err := pe.Allow("skill", skillName, reason); err != nil {
		return fmt.Errorf("skill allow: %w", err)
	}
	if skillPath := resolveInstalledSkillPath(skillName); skillPath != "" {
		pe.SetSourcePath("skill", skillName, skillPath)
	}
	fmt.Printf("[skill] %q added to allow list\n", skillName)

	_ = auditLog.LogAction("skill-allow", skillName, fmt.Sprintf("reason=%s", reason))
	return nil
}

// --- File-level actions (quarantine / restore) ---

func runSkillQuarantine(_ *cobra.Command, args []string) error {
	skillArg := args[0]
	skillName := filepath.Base(skillArg)

	skillPath := skillArg
	if !filepath.IsAbs(skillPath) {
		resolved := resolveInstalledSkillPath(skillName)
		if resolved == "" {
			return fmt.Errorf("skill quarantine: could not locate skill %q — provide an absolute path", skillName)
		}
		skillPath = resolved
	}

	shell := sandbox.NewWithFallback(cfg.OpenShell.Binary, cfg.OpenShell.PolicyDir, cfg.PolicyDir)
	se := enforce.NewSkillEnforcer(cfg.QuarantineDir, shell)

	dest, err := se.Quarantine(skillPath)
	if err != nil {
		return fmt.Errorf("skill quarantine: %w", err)
	}
	fmt.Printf("[skill] %q quarantined to %s\n", skillName, dest)

	if err := se.UpdateSandboxPolicy(skillName, true); err != nil {
		fmt.Fprintf(os.Stderr, "[skill] sandbox policy update failed: %v\n", err)
	}

	reason := skillActionReason
	if reason == "" {
		reason = "manual quarantine via CLI"
	}

	pe := enforce.NewPolicyEngine(auditStore)
	_ = pe.Quarantine("skill", skillName, reason)
	pe.SetSourcePath("skill", skillName, skillPath)

	_ = auditLog.LogAction("skill-quarantine", skillName, fmt.Sprintf("reason=%s, dest=%s", reason, dest))
	return nil
}

func runSkillRestore(_ *cobra.Command, args []string) error {
	skillName := filepath.Base(args[0])

	shell := sandbox.NewWithFallback(cfg.OpenShell.Binary, cfg.OpenShell.PolicyDir, cfg.PolicyDir)
	se := enforce.NewSkillEnforcer(cfg.QuarantineDir, shell)

	if !se.IsQuarantined(skillName) {
		return fmt.Errorf("skill restore: %q is not quarantined", skillName)
	}

	pe := enforce.NewPolicyEngine(auditStore)

	restorePath := skillRestorePath
	if restorePath == "" {
		entry, err := pe.GetAction("skill", skillName)
		if err != nil {
			return fmt.Errorf("skill restore: failed to lookup original path: %w", err)
		}
		if entry == nil || entry.SourcePath == "" {
			return fmt.Errorf("skill restore: no stored path for %q — use --path to specify restore destination", skillName)
		}
		restorePath = entry.SourcePath
	}

	if err := se.Restore(skillName, restorePath); err != nil {
		return fmt.Errorf("skill restore: %w", err)
	}
	fmt.Printf("[skill] %q restored to %s\n", skillName, restorePath)

	if err := se.UpdateSandboxPolicy(skillName, false); err != nil {
		fmt.Fprintf(os.Stderr, "[skill] sandbox policy update failed: %v\n", err)
	}

	_ = pe.ClearQuarantine("skill", skillName)
	pe.SetSourcePath("skill", skillName, restorePath)

	_ = auditLog.LogAction("skill-restore", skillName, fmt.Sprintf("restored to %s", restorePath))
	return nil
}

// skillVerdict holds the result of scanning a skill directory.
type skillVerdict struct {
	Target        string                `json:"target"`
	Clean         bool                  `json:"clean"`
	MaxSeverity   scanner.Severity      `json:"max_severity"`
	TotalFindings int                   `json:"total_findings"`
	Results       []*scanner.ScanResult `json:"results,omitempty"`
}

// scanSkillPath runs the skill scanner against the given path and returns a verdict.
// If verbose is true, it prints progress to stdout.
func scanSkillPath(ctx context.Context, path string, verbose bool) (*skillVerdict, error) {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Minute)
	defer cancel()

	s := scanner.NewSkillScanner(cfg.Scanners.SkillScanner)
	v := &skillVerdict{Target: path, Clean: true, MaxSeverity: scanner.SeverityInfo}

	if verbose {
		fmt.Printf("[scan] %s -> %s\n", s.Name(), path)
	}

	result, err := s.Scan(ctx, path)
	if err != nil {
		return nil, fmt.Errorf("skill scan: %w", err)
	}

	if auditLog != nil {
		_ = auditLog.LogScan(result)
	}

	if !result.IsClean() {
		v.Clean = false
		v.TotalFindings = len(result.Findings)
		v.MaxSeverity = result.MaxSeverity()
	}
	v.Results = append(v.Results, result)

	return v, nil
}

func runSkillScan(cmd *cobra.Command, args []string) error {
	target := args[0]

	if target == "all" {
		return runSkillScanAll(cmd)
	}

	scanDir := skillScanPath
	if scanDir == "" {
		info, err := getOpenclawSkillInfo(target)
		if err != nil {
			return fmt.Errorf("skill scan: could not resolve %q: %w", target, err)
		}
		if info.BaseDir == "" {
			return fmt.Errorf("skill scan: no baseDir for %q — use --path to specify manually", target)
		}
		scanDir = info.BaseDir
	}

	verdict, err := scanSkillPath(cmd.Context(), scanDir, !skillScanJSON)
	if err != nil {
		return err
	}

	printSkillVerdict(verdict)
	return nil
}

// getOpenclawSkillInfoRaw returns the raw JSON map from 'openclaw skills info <name> --json'.
func getOpenclawSkillInfoRaw(name string) (map[string]interface{}, error) {
	out, err := exec.Command("openclaw", "skills", "info", name, "--json").Output()
	if err != nil {
		return nil, fmt.Errorf("openclaw skills info %s: %w", name, err)
	}

	var m map[string]interface{}
	if err := json.Unmarshal(out, &m); err != nil {
		return nil, fmt.Errorf("parse skill info: %w", err)
	}
	return m, nil
}

func runSkillInfo(_ *cobra.Command, args []string) error {
	skillName := args[0]

	infoMap, err := getOpenclawSkillInfoRaw(skillName)
	if err != nil {
		return fmt.Errorf("skill info: %w", err)
	}

	scanMap := buildSkillScanMap()
	if scan, ok := scanMap[skillName]; ok {
		infoMap["scan"] = scan
	}

	actionsMap := buildSkillActionsMap()
	if ae, ok := actionsMap[skillName]; ok {
		if !ae.Actions.IsEmpty() {
			infoMap["actions"] = &ae.Actions
		}
	}

	if skillInfoJSON {
		data, err := json.MarshalIndent(infoMap, "", "  ")
		if err != nil {
			return fmt.Errorf("skill info: json marshal: %w", err)
		}
		fmt.Println(string(data))
		return nil
	}

	return printSkillInfoText(infoMap)
}

func skillInfoStr(m map[string]interface{}, key string) string {
	if v, ok := m[key]; ok {
		if s, ok := v.(string); ok {
			return s
		}
	}
	return ""
}

func skillInfoBool(m map[string]interface{}, key string) bool {
	if v, ok := m[key]; ok {
		if b, ok := v.(bool); ok {
			return b
		}
	}
	return false
}

func printSkillInfoText(m map[string]interface{}) error {
	fmt.Printf("Skill:       %s\n", skillInfoStr(m, "name"))
	if desc := skillInfoStr(m, "description"); desc != "" {
		fmt.Printf("Description: %s\n", desc)
	}
	fmt.Printf("Source:      %s\n", skillInfoStr(m, "source"))
	if baseDir := skillInfoStr(m, "baseDir"); baseDir != "" {
		fmt.Printf("Path:        %s\n", baseDir)
	}
	if filePath := skillInfoStr(m, "filePath"); filePath != "" {
		fmt.Printf("File:        %s\n", filePath)
	}
	fmt.Printf("Eligible:    %v\n", skillInfoBool(m, "eligible"))
	fmt.Printf("Bundled:     %v\n", skillInfoBool(m, "bundled"))
	if hp := skillInfoStr(m, "homepage"); hp != "" {
		fmt.Printf("Homepage:    %s\n", hp)
	}

	if v, ok := m["scan"]; ok {
		if scan, ok := v.(*skillScanEntry); ok {
			fmt.Println()
			fmt.Println("Last Scan:")
			if scan.Clean {
				fmt.Println("  Verdict:  CLEAN")
			} else {
				fmt.Printf("  Verdict:  %d %s findings\n", scan.TotalFindings, scan.MaxSeverity)
			}
			fmt.Printf("  Target:   %s\n", scan.Target)
		}
	}

	if v, ok := m["actions"]; ok {
		if actions, ok := v.(*audit.ActionState); ok && !actions.IsEmpty() {
			fmt.Println()
			fmt.Printf("Actions:     %s\n", actions.Summary())
		}
	}

	return nil
}

// openclawSkillInfo represents the output of 'openclaw skills info <skill> --json'
type openclawSkillInfo struct {
	Name    string `json:"name"`
	BaseDir string `json:"baseDir"`
	Bundled bool   `json:"bundled"`
	Source  string `json:"source"`
}

// openclawSkill represents a single skill entry from 'openclaw skills list --json'.
type openclawSkill struct {
	Name               string `json:"name"`
	Description        string `json:"description"`
	Emoji              string `json:"emoji"`
	Eligible           bool   `json:"eligible"`
	Disabled           bool   `json:"disabled"`
	BlockedByAllowlist bool   `json:"blockedByAllowlist"`
	Source             string `json:"source"`
	Bundled            bool   `json:"bundled"`
	Homepage           string `json:"homepage"`
}

// openclawSkillsList represents the full output of 'openclaw skills list --json'.
type openclawSkillsList struct {
	WorkspaceDir     string          `json:"workspaceDir"`
	ManagedSkillsDir string          `json:"managedSkillsDir"`
	Skills           []openclawSkill `json:"skills"`
}

// skillListItem is the merged representation of an openclaw skill + latest scan data.
type skillListItem struct {
	Name        string            `json:"name"`
	Description string            `json:"description"`
	Source      string            `json:"source"`
	Status      string            `json:"status"`
	Eligible    bool              `json:"eligible"`
	Disabled    bool              `json:"disabled"`
	Bundled     bool              `json:"bundled"`
	Homepage    string            `json:"homepage,omitempty"`
	Scan        *skillScanEntry   `json:"scan,omitempty"`
	Actions     *audit.ActionState `json:"actions,omitempty"`
}

// skillScanEntry holds the latest scan result for a skill, shaped like skill scan --json output.
type skillScanEntry struct {
	Target        string                `json:"target"`
	Clean         bool                  `json:"clean"`
	MaxSeverity   scanner.Severity      `json:"max_severity"`
	TotalFindings int                   `json:"total_findings"`
	Results       []*scanner.ScanResult `json:"results,omitempty"`
}

func runSkillScanAll(cmd *cobra.Command) error {
	// Get all skills from openclaw (includes workspace, global, and bundled)
	skillNames, err := listOpenclawSkills()
	if err != nil {
		return fmt.Errorf("failed to list skills: %w", err)
	}

	if len(skillNames) == 0 {
		fmt.Println("[scan] no skills found")
		return nil
	}

	fmt.Printf("[scan] found %d skills to scan\n\n", len(skillNames))

	var allVerdicts []*skillVerdict

	for _, name := range skillNames {
		// Get skill info to find the baseDir
		info, err := getOpenclawSkillInfo(name)
		if err != nil {
			fmt.Fprintf(os.Stderr, "[scan] warning: cannot get info for %s: %v\n", name, err)
			continue
		}

		if info.BaseDir == "" {
			fmt.Fprintf(os.Stderr, "[scan] warning: no baseDir for %s\n", name)
			continue
		}

		verdict, err := scanSkillPath(cmd.Context(), info.BaseDir, !skillScanJSON)
		if err != nil {
			fmt.Fprintf(os.Stderr, "[scan] error scanning %s: %v\n", name, err)
			continue
		}
		allVerdicts = append(allVerdicts, verdict)

		if !skillScanJSON {
			printSkillVerdict(verdict)
			fmt.Println()
		}
	}

	if skillScanJSON {
		data, _ := json.MarshalIndent(allVerdicts, "", "  ")
		fmt.Println(string(data))
	} else {
		// Print summary
		clean, warnings, rejects := 0, 0, 0
		for _, v := range allVerdicts {
			if v.Clean {
				clean++
			} else if cfg.SkillActions.ShouldDisable(string(v.MaxSeverity)) || cfg.SkillActions.ShouldQuarantine(string(v.MaxSeverity)) {
				rejects++
			} else {
				warnings++
			}
		}
		fmt.Printf("Summary: %d clean, %d warnings, %d rejected\n", clean, warnings, rejects)
	}

	return nil
}

// listOpenclawSkillsFull returns the full parsed output of 'openclaw skills list --json'.
func listOpenclawSkillsFull() (*openclawSkillsList, error) {
	out, err := exec.Command("openclaw", "skills", "list", "--json").Output()
	if err != nil {
		return nil, fmt.Errorf("openclaw skills list: %w", err)
	}

	var list openclawSkillsList
	if err := json.Unmarshal(out, &list); err != nil {
		return nil, fmt.Errorf("parse skills list: %w", err)
	}
	return &list, nil
}

// listOpenclawSkills returns all skill names from 'openclaw skills list --json'.
func listOpenclawSkills() ([]string, error) {
	list, err := listOpenclawSkillsFull()
	if err != nil {
		return nil, err
	}

	names := make([]string, len(list.Skills))
	for i, s := range list.Skills {
		names[i] = s.Name
	}
	return names, nil
}

// getOpenclawSkillInfo returns skill info from 'openclaw skills info <name> --json'
func getOpenclawSkillInfo(name string) (*openclawSkillInfo, error) {
	out, err := exec.Command("openclaw", "skills", "info", name, "--json").Output()
	if err != nil {
		return nil, fmt.Errorf("openclaw skills info %s: %w", name, err)
	}

	var info openclawSkillInfo
	if err := json.Unmarshal(out, &info); err != nil {
		return nil, fmt.Errorf("parse skill info: %w", err)
	}
	return &info, nil
}

func printSkillVerdict(verdict *skillVerdict) {
	if skillScanJSON {
		data, _ := json.MarshalIndent(verdict, "", "  ")
		fmt.Println(string(data))
		return
	}

	for _, r := range verdict.Results {
		printScanResult(r)
	}
	if verdict.Clean {
		fmt.Println("  Verdict: CLEAN")
	} else if cfg.SkillActions.ShouldDisable(string(verdict.MaxSeverity)) || cfg.SkillActions.ShouldQuarantine(string(verdict.MaxSeverity)) {
		fmt.Printf("  Verdict: REJECT (%d %s findings)\n", verdict.TotalFindings, verdict.MaxSeverity)
	} else {
		fmt.Printf("  Verdict: WARNING (%d %s findings)\n", verdict.TotalFindings, verdict.MaxSeverity)
	}
}

func skillStatus(s openclawSkill) string {
	if s.Disabled {
		return "disabled"
	}
	if s.BlockedByAllowlist {
		return "blocked"
	}
	if s.Eligible {
		return "active"
	}
	return "inactive"
}

func skillStatusDisplay(s openclawSkill) string {
	if s.Disabled {
		return "✗ disabled"
	}
	if s.BlockedByAllowlist {
		return "✗ blocked"
	}
	if s.Eligible {
		return "✓ ready"
	}
	return "✗ missing"
}

func runSkillList(_ *cobra.Command, _ []string) error {
	list, err := listOpenclawSkillsFull()
	if err != nil {
		return err
	}

	if len(list.Skills) == 0 {
		fmt.Println("No skills found.")
		return nil
	}

	scanMap := buildSkillScanMap()
	actionsMap := buildSkillActionsMap()

	if skillListJSON {
		return printSkillListJSON(list.Skills, scanMap, actionsMap)
	}
	return printSkillListTable(list.Skills, scanMap, actionsMap)
}

func buildSkillScanMap() map[string]*skillScanEntry {
	scanMap := make(map[string]*skillScanEntry)
	if auditStore == nil {
		return scanMap
	}
	latestScans, err := auditStore.LatestScansByScanner("skill-scanner")
	if err != nil {
		return scanMap
	}
	for _, ls := range latestScans {
		name := filepath.Base(ls.Target)
		severity := scanner.Severity(ls.MaxSeverity)
		if severity == "" {
			severity = scanner.SeverityInfo
		}
		entry := &skillScanEntry{
			Target:        ls.Target,
			Clean:         ls.FindingCount == 0,
			MaxSeverity:   severity,
			TotalFindings: ls.FindingCount,
		}
		if skillListJSON && ls.RawJSON != "" {
			var sr scanner.ScanResult
			if json.Unmarshal([]byte(ls.RawJSON), &sr) == nil {
				entry.Results = []*scanner.ScanResult{&sr}
			}
		}
		scanMap[name] = entry
	}
	return scanMap
}

func buildSkillActionsMap() map[string]*audit.ActionEntry {
	m := make(map[string]*audit.ActionEntry)
	if auditStore == nil {
		return m
	}
	entries, err := auditStore.ListActionsByType("skill")
	if err != nil {
		return m
	}
	for i, e := range entries {
		m[e.TargetName] = &entries[i]
	}
	return m
}

// --- bordered table helpers ---

func strDisplayWidth(s string) int { return runewidth.StringWidth(s) }

func strPadRight(s string, width int) string {
	gap := width - strDisplayWidth(s)
	if gap <= 0 {
		return s
	}
	return s + strings.Repeat(" ", gap)
}

func wrapText(s string, width int) []string {
	if width <= 0 || strDisplayWidth(s) <= width {
		return []string{s}
	}
	words := strings.Fields(s)
	if len(words) == 0 {
		return []string{""}
	}
	var lines []string
	cur := words[0]
	for _, w := range words[1:] {
		test := cur + " " + w
		if strDisplayWidth(test) <= width {
			cur = test
		} else {
			lines = append(lines, cur)
			cur = w
		}
	}
	lines = append(lines, cur)
	return lines
}

func tableHLine(widths []int, left, mid, right, fill string) string {
	parts := make([]string, len(widths))
	for i, w := range widths {
		parts[i] = strings.Repeat(fill, w+2) // +2 for cell padding
	}
	return left + strings.Join(parts, mid) + right
}

func tableCell(s string, width int) string {
	return " " + strPadRight(s, width) + " "
}

func printSkillListTable(skills []openclawSkill, scanMap map[string]*skillScanEntry, actionsMap map[string]*audit.ActionEntry) error {
	readyCount := 0
	for _, s := range skills {
		if s.Eligible && !s.Disabled {
			readyCount++
		}
	}

	type rowData struct {
		status, skill, desc, source, severity, actions string
	}

	rows := make([]rowData, len(skills))
	headers := [6]string{"Status", "Skill", "Description", "Source", "Severity", "Actions"}
	colW := [6]int{
		strDisplayWidth(headers[0]),
		strDisplayWidth(headers[1]),
		0,
		strDisplayWidth(headers[3]),
		strDisplayWidth(headers[4]),
		strDisplayWidth(headers[5]),
	}

	for i, s := range skills {
		rows[i] = rowData{
			status:   skillStatusDisplay(s),
			skill:    s.Emoji + " " + s.Name,
			desc:     s.Description,
			source:   s.Source,
			severity: "-",
			actions:  "-",
		}
		if scan, ok := scanMap[s.Name]; ok {
			rows[i].severity = string(scan.MaxSeverity)
		}
		if ae, ok := actionsMap[s.Name]; ok {
			rows[i].actions = ae.Actions.Summary()
		}
		if w := strDisplayWidth(rows[i].status); w > colW[0] {
			colW[0] = w
		}
		if w := strDisplayWidth(rows[i].skill); w > colW[1] {
			colW[1] = w
		}
		if w := strDisplayWidth(rows[i].source); w > colW[3] {
			colW[3] = w
		}
		if w := strDisplayWidth(rows[i].severity); w > colW[4] {
			colW[4] = w
		}
		if w := strDisplayWidth(rows[i].actions); w > colW[5] {
			colW[5] = w
		}
	}

	fixedUsed := colW[0] + colW[1] + colW[3] + colW[4] + colW[5]
	chrome := 7 + 6*2 // 6 columns → 7 borders, each cell has 2-char padding
	descW := 130 - fixedUsed - chrome
	if descW < 30 {
		descW = 30
	}
	colW[2] = descW

	widths := colW[:]

	fmt.Printf("\nSkills (%d/%d ready)\n", readyCount, len(skills))
	fmt.Println(tableHLine(widths, "┌", "┬", "┐", "─"))
	fmt.Printf("│%s│%s│%s│%s│%s│%s│\n",
		tableCell(headers[0], colW[0]),
		tableCell(headers[1], colW[1]),
		tableCell(headers[2], colW[2]),
		tableCell(headers[3], colW[3]),
		tableCell(headers[4], colW[4]),
		tableCell(headers[5], colW[5]),
	)
	fmt.Println(tableHLine(widths, "├", "┼", "┤", "─"))

	for _, r := range rows {
		descLines := wrapText(r.desc, colW[2])
		if len(descLines) == 0 {
			descLines = []string{""}
		}
		fmt.Printf("│%s│%s│%s│%s│%s│%s│\n",
			tableCell(r.status, colW[0]),
			tableCell(r.skill, colW[1]),
			tableCell(descLines[0], colW[2]),
			tableCell(r.source, colW[3]),
			tableCell(r.severity, colW[4]),
			tableCell(r.actions, colW[5]),
		)
		for _, line := range descLines[1:] {
			fmt.Printf("│%s│%s│%s│%s│%s│%s│\n",
				tableCell("", colW[0]),
				tableCell("", colW[1]),
				tableCell(line, colW[2]),
				tableCell("", colW[3]),
				tableCell("", colW[4]),
				tableCell("", colW[5]),
			)
		}
	}

	fmt.Println(tableHLine(widths, "└", "┴", "┘", "─"))
	return nil
}

func printSkillListJSON(skills []openclawSkill, scanMap map[string]*skillScanEntry, actionsMap map[string]*audit.ActionEntry) error {
	items := make([]skillListItem, 0, len(skills))
	for _, s := range skills {
		item := skillListItem{
			Name:        s.Name,
			Description: s.Description,
			Source:      s.Source,
			Status:      skillStatus(s),
			Eligible:    s.Eligible,
			Disabled:    s.Disabled,
			Bundled:     s.Bundled,
			Homepage:    s.Homepage,
		}
		if scan, ok := scanMap[s.Name]; ok {
			item.Scan = scan
		}
		if ae, ok := actionsMap[s.Name]; ok {
			item.Actions = &ae.Actions
		}
		items = append(items, item)
	}
	data, err := json.MarshalIndent(items, "", "  ")
	if err != nil {
		return fmt.Errorf("skill list: json marshal: %w", err)
	}
	fmt.Println(string(data))
	return nil
}

func runSkillInstall(cmd *cobra.Command, args []string) error {
	skillName := args[0]

	pe := enforce.NewPolicyEngine(auditStore)

	// Block list check always applies
	blocked, err := pe.IsBlocked("skill", skillName)
	if err == nil && blocked {
		_ = auditLog.LogAction("install-rejected", skillName, "reason=blocked")
		return fmt.Errorf("skill %q is on the block list — run 'defenseclaw skill allow %s' to unblock", skillName, skillName)
	}

	// Allow list check — skip scan
	allowed, err := pe.IsAllowed("skill", skillName)
	if err == nil && allowed {
		fmt.Printf("[install] %q is on the allow list — skipping scan\n", skillName)
		_ = auditLog.LogAction("install-allowed", skillName, "reason=allow-listed")
		return runClawHubInstall(skillName, skillInstallForce)
	}

	// Install via clawhub
	fmt.Printf("[install] installing %q via clawhub...\n", skillName)
	if err := runClawHubInstall(skillName, skillInstallForce); err != nil {
		return err
	}

	// Locate and scan the installed skill
	skillPath := resolveInstalledSkillPath(skillName)
	if skillPath == "" {
		fmt.Fprintf(os.Stderr, "[install] warning: could not locate installed skill for scan\n")
		return nil
	}

	fmt.Printf("[install] scanning %s...\n", skillPath)
	verdict, err := scanSkillPath(cmd.Context(), skillPath, !skillInstallJSON)
	if err != nil {
		return fmt.Errorf("install: scan error: %w", err)
	}

	if !skillInstallJSON && len(verdict.Results) > 0 {
		for _, r := range verdict.Results {
			printScanResult(r)
		}
	}

	if verdict.Clean {
		fmt.Printf("[install] %q installed and clean\n", skillName)
		_ = auditLog.LogAction("install-clean", skillName, "verdict=clean")
		return nil
	}

	detail := fmt.Sprintf("severity=%s findings=%d", verdict.MaxSeverity, verdict.TotalFindings)

	if !skillInstallAction {
		fmt.Printf("[install] %d %s findings in %q (no action taken — pass --action to enforce)\n",
			verdict.TotalFindings, verdict.MaxSeverity, skillName)
		_ = auditLog.LogAction("install-warning", skillName, detail)
		return nil
	}

	// --action: apply configured skill_actions policy
	action := cfg.SkillActions.ForSeverity(string(verdict.MaxSeverity))
	shouldQuarantine := action.File == config.FileActionQuarantine
	shouldDisable := action.Runtime == config.RuntimeDisable
	shouldBlock := action.Install == config.InstallBlock
	shouldAllow := action.Install == config.InstallAllow

	shell := sandbox.NewWithFallback(cfg.OpenShell.Binary, cfg.OpenShell.PolicyDir, cfg.PolicyDir)
	se := enforce.NewSkillEnforcer(cfg.QuarantineDir, shell)

	enforcementReason := fmt.Sprintf("post-install scan: %d findings, max=%s", verdict.TotalFindings, verdict.MaxSeverity)
	var actions []string

	if shouldQuarantine {
		if dest, qErr := se.Quarantine(skillPath); qErr != nil {
			fmt.Fprintf(os.Stderr, "[install] quarantine failed: %v\n", qErr)
		} else {
			actions = append(actions, fmt.Sprintf("quarantined to %s", dest))
			_ = pe.Quarantine("skill", skillName, enforcementReason)
		}
	}
	if shouldDisable {
		if dErr := disableViaGateway(skillName); dErr != nil {
			fmt.Fprintf(os.Stderr, "[install] gateway disable failed: %v\n", dErr)
		} else {
			actions = append(actions, "disabled via gateway")
			_ = pe.Disable("skill", skillName, enforcementReason)
		}
	}
	if shouldBlock {
		_ = pe.Block("skill", skillName, enforcementReason)
		actions = append(actions, "added to block list")
	}
	if shouldAllow {
		_ = pe.Allow("skill", skillName, enforcementReason)
		actions = append(actions, "added to allow list")
	}

	pe.SetSourcePath("skill", skillName, skillPath)

	if len(actions) > 0 {
		fmt.Printf("[install] %q: %s (%s)\n", skillName, strings.Join(actions, ", "), detail)
		_ = auditLog.LogAction("install-enforced", skillName, detail+"; "+strings.Join(actions, ", "))
		return fmt.Errorf("skill %q had %s findings — actions applied: %s",
			skillName, verdict.MaxSeverity, strings.Join(actions, ", "))
	}

	fmt.Printf("[install] warning: %d %s findings in %q\n", verdict.TotalFindings, verdict.MaxSeverity, skillName)
	_ = auditLog.LogAction("install-warning", skillName, detail)
	return nil
}

func runClawHubInstall(skillName string, force bool) error {
	args := []string{"clawhub", "install", skillName}
	if force {
		args = append(args, "--force")
	}
	cmd := exec.Command("npx", args...)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("clawhub install: %w", err)
	}
	return nil
}

func resolveInstalledSkillPath(skillName string) string {
	for _, c := range cfg.InstalledSkillCandidates(skillName) {
		if _, err := os.Stat(c); err == nil {
			return c
		}
	}
	return ""
}

func disableViaGateway(skillKey string) error {
	gwClient, err := gateway.NewClient(&cfg.Gateway)
	if err != nil {
		return err
	}
	defer gwClient.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	if err := gwClient.Connect(ctx); err != nil {
		return err
	}

	return gwClient.DisableSkill(ctx, skillKey)
}

func enableViaGateway(skillKey string) error {
	gwClient, err := gateway.NewClient(&cfg.Gateway)
	if err != nil {
		return err
	}
	defer gwClient.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	if err := gwClient.Connect(ctx); err != nil {
		return err
	}

	return gwClient.EnableSkill(ctx, skillKey)
}
