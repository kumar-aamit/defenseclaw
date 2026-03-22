package cli

import (
	"fmt"
	"os"
	"text/tabwriter"

	"github.com/spf13/cobra"
)

var alertsLimit int

var alertsCmd = &cobra.Command{
	Use:   "alerts",
	Short: "View security alerts",
	Long:  "Display recent security alerts (events with CRITICAL, HIGH, MEDIUM, or LOW severity).",
	RunE:  runAlerts,
}

func init() {
	alertsCmd.Flags().IntVarP(&alertsLimit, "limit", "n", 25, "Number of alerts to show")
	rootCmd.AddCommand(alertsCmd)
}

func runAlerts(_ *cobra.Command, _ []string) error {
	alerts, err := auditStore.ListAlerts(alertsLimit)
	if err != nil {
		return fmt.Errorf("alerts: %w", err)
	}

	if len(alerts) == 0 {
		fmt.Println("No alerts. All clear.")
		return nil
	}

	w := tabwriter.NewWriter(os.Stdout, 0, 4, 2, ' ', 0)
	fmt.Fprintln(w, "SEVERITY\tTIMESTAMP\tACTION\tTARGET\tDETAILS")
	for _, e := range alerts {
		details := e.Details
		if len(details) > 55 {
			details = details[:52] + "..."
		}
		fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\n",
			e.Severity,
			e.Timestamp.Format("2006-01-02 15:04:05"),
			e.Action,
			e.Target,
			details,
		)
	}
	return w.Flush()
}
