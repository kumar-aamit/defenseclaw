package audit

import (
	"encoding/json"
	"fmt"
	"os"
	"time"

	"github.com/google/uuid"

	"github.com/defenseclaw/defenseclaw/internal/scanner"
)

type Logger struct {
	store    *Store
	splunk   *SplunkForwarder
}

func NewLogger(store *Store) *Logger {
	return &Logger{store: store}
}

func (l *Logger) SetSplunkForwarder(sf *SplunkForwarder) {
	l.splunk = sf
}

func (l *Logger) LogScan(result *scanner.ScanResult) error {
	scanID := uuid.New().String()
	raw, _ := result.JSON()

	if err := l.store.InsertScanResult(
		scanID, result.Scanner, result.Target, result.Timestamp,
		result.Duration.Milliseconds(), len(result.Findings),
		string(result.MaxSeverity()), string(raw),
	); err != nil {
		return err
	}

	for _, f := range result.Findings {
		tagsJSON, _ := json.Marshal(f.Tags)
		findingID := uuid.New().String()
		if err := l.store.InsertFinding(
			findingID, scanID, string(f.Severity), f.Title,
			f.Description, f.Location, f.Remediation, f.Scanner,
			string(tagsJSON),
		); err != nil {
			return err
		}
	}

	event := Event{
		Timestamp: time.Now().UTC(),
		Action:    "scan",
		Target:    result.Target,
		Details: fmt.Sprintf("scanner=%s findings=%d max_severity=%s duration=%s",
			result.Scanner, len(result.Findings), result.MaxSeverity(), result.Duration),
		Severity: string(result.MaxSeverity()),
	}

	if err := l.store.LogEvent(event); err != nil {
		return err
	}
	l.forwardToSplunk(event)
	return nil
}

func (l *Logger) LogAction(action, target, details string) error {
	event := Event{
		Timestamp: time.Now().UTC(),
		Action:    action,
		Target:    target,
		Details:   details,
		Severity:  "INFO",
	}
	if err := l.store.LogEvent(event); err != nil {
		return err
	}
	l.forwardToSplunk(event)
	return nil
}

func (l *Logger) forwardToSplunk(e Event) {
	if l.splunk == nil {
		return
	}
	if err := l.splunk.ForwardEvent(e); err != nil {
		fmt.Fprintf(os.Stderr, "warning: splunk forward: %v\n", err)
	}
}

func (l *Logger) Close() {
	if l.splunk != nil {
		if err := l.splunk.Close(); err != nil {
			fmt.Fprintf(os.Stderr, "warning: splunk flush on close: %v\n", err)
		}
	}
}
