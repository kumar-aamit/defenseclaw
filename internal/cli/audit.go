package cli

import (
	"fmt"
	"os"
	"text/tabwriter"

	"github.com/spf13/cobra"

	"github.com/defenseclaw/defenseclaw/internal/audit"
)

var (
	auditLimit  int
	auditFormat string
	auditOutput string
)

var auditCmd = &cobra.Command{
	Use:   "audit",
	Short: "View audit log",
	Long:  "Display recent audit events from the SQLite event store.",
	RunE:  runAudit,
}

var auditExportCmd = &cobra.Command{
	Use:   "export",
	Short: "Export audit events",
	Long: `Export audit events in different formats.

Formats:
  table    Print to terminal (default)
  json     JSON array
  csv      CSV with headers
  splunk   Send to Splunk via HEC (requires splunk config in config.yaml)`,
	RunE: runAuditExport,
}

func init() {
	auditCmd.Flags().IntVarP(&auditLimit, "limit", "n", 25, "Number of events to show")

	auditExportCmd.Flags().IntVarP(&auditLimit, "limit", "n", 100, "Number of events to export")
	auditExportCmd.Flags().StringVarP(&auditFormat, "format", "f", "json", "Export format: json, csv, splunk")
	auditExportCmd.Flags().StringVarP(&auditOutput, "output", "o", "-", "Output file (- for stdout, ignored for splunk)")

	auditCmd.AddCommand(auditExportCmd)
	rootCmd.AddCommand(auditCmd)
}

func runAudit(_ *cobra.Command, _ []string) error {
	events, err := auditStore.ListEvents(auditLimit)
	if err != nil {
		return fmt.Errorf("audit: %w", err)
	}

	if len(events) == 0 {
		fmt.Println("No audit events.")
		return nil
	}

	w := tabwriter.NewWriter(os.Stdout, 0, 4, 2, ' ', 0)
	fmt.Fprintln(w, "TIMESTAMP\tACTION\tTARGET\tSEVERITY\tDETAILS")
	for _, e := range events {
		details := e.Details
		if len(details) > 60 {
			details = details[:57] + "..."
		}
		fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\n",
			e.Timestamp.Format("2006-01-02 15:04:05"),
			e.Action,
			e.Target,
			e.Severity,
			details,
		)
	}
	return w.Flush()
}

func runAuditExport(_ *cobra.Command, _ []string) error {
	switch auditFormat {
	case "json":
		return auditStore.ExportJSON(auditOutput, auditLimit)
	case "csv":
		return auditStore.ExportCSV(auditOutput, auditLimit)
	case "splunk":
		return exportToSplunk()
	default:
		return fmt.Errorf("audit: unknown format %q (use json, csv, or splunk)", auditFormat)
	}
}

func exportToSplunk() error {
	splunkCfg := audit.SplunkConfig{
		HECEndpoint:   cfg.Splunk.HECEndpoint,
		HECToken:      resolveSplunkToken(),
		Index:         cfg.Splunk.Index,
		Source:        cfg.Splunk.Source,
		SourceType:    cfg.Splunk.SourceType,
		VerifyTLS:     cfg.Splunk.VerifyTLS,
		Enabled:       true,
		BatchSize:     cfg.Splunk.BatchSize,
		FlushInterval: cfg.Splunk.FlushInterval,
	}

	if splunkCfg.HECToken == "" {
		return fmt.Errorf("splunk: HEC token not configured — set splunk.hec_token in config.yaml or DEFENSECLAW_SPLUNK_HEC_TOKEN env var")
	}

	fmt.Printf("[splunk] Sending %d events to %s (index=%s)\n", auditLimit, splunkCfg.HECEndpoint, splunkCfg.Index)

	if err := auditStore.ExportSplunk(splunkCfg, auditLimit); err != nil {
		return err
	}

	fmt.Println("[splunk] Export complete.")
	return nil
}

func resolveSplunkToken() string {
	if token := cfg.Splunk.HECToken; token != "" {
		return token
	}
	return os.Getenv("DEFENSECLAW_SPLUNK_HEC_TOKEN")
}
