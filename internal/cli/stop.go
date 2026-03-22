package cli

import (
	"fmt"

	"github.com/spf13/cobra"

	"github.com/defenseclaw/defenseclaw/internal/sandbox"
)

var stopCmd = &cobra.Command{
	Use:   "stop",
	Short: "Stop the OpenShell sandbox",
	Long:  "Gracefully stop the OpenShell sandbox process started by 'defenseclaw deploy'.",
	RunE:  runStop,
}

func init() {
	rootCmd.AddCommand(stopCmd)
}

func runStop(_ *cobra.Command, _ []string) error {
	shell := sandbox.NewWithFallback(cfg.OpenShell.Binary, cfg.OpenShell.PolicyDir, cfg.PolicyDir)

	if !shell.IsAvailable() {
		fmt.Println("OpenShell is not installed — nothing to stop.")
		return nil
	}

	if !shell.IsRunning() {
		fmt.Println("No running sandbox process found.")
		return nil
	}

	fmt.Print("Stopping sandbox... ")
	if err := shell.Stop(); err != nil {
		return fmt.Errorf("stop: %w", err)
	}
	fmt.Println("done.")

	if auditLog != nil {
		_ = auditLog.LogAction("sandbox-stop", "", "graceful shutdown")
	}
	return nil
}
