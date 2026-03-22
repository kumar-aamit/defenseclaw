package audit

import (
	"encoding/csv"
	"encoding/json"
	"fmt"
	"os"
)

func (s *Store) ExportJSON(path string, limit int) error {
	events, err := s.ListEvents(limit)
	if err != nil {
		return fmt.Errorf("audit: export json: %w", err)
	}

	data, err := json.MarshalIndent(events, "", "  ")
	if err != nil {
		return fmt.Errorf("audit: marshal json: %w", err)
	}

	if path == "-" || path == "" {
		_, err = os.Stdout.Write(data)
		fmt.Println()
		return err
	}
	return os.WriteFile(path, data, 0o600)
}

func (s *Store) ExportCSV(path string, limit int) error {
	events, err := s.ListEvents(limit)
	if err != nil {
		return fmt.Errorf("audit: export csv: %w", err)
	}

	var f *os.File
	if path == "-" || path == "" {
		f = os.Stdout
	} else {
		var err error
		f, err = os.Create(path)
		if err != nil {
			return fmt.Errorf("audit: create csv: %w", err)
		}
		defer f.Close()
		if err := os.Chmod(path, 0o600); err != nil {
			return fmt.Errorf("audit: chmod csv: %w", err)
		}
	}

	w := csv.NewWriter(f)
	if err := w.Write([]string{"id", "timestamp", "action", "target", "actor", "details", "severity"}); err != nil {
		return err
	}
	for _, e := range events {
		if err := w.Write([]string{
			e.ID,
			e.Timestamp.Format("2006-01-02T15:04:05Z"),
			e.Action,
			e.Target,
			e.Actor,
			e.Details,
			e.Severity,
		}); err != nil {
			return err
		}
	}
	w.Flush()
	return w.Error()
}

func (s *Store) ExportSplunk(cfg SplunkConfig, limit int) error {
	events, err := s.ListEvents(limit)
	if err != nil {
		return fmt.Errorf("audit: export splunk: %w", err)
	}

	fwd, err := NewSplunkForwarder(cfg)
	if err != nil {
		return err
	}
	defer fwd.Close()

	return fwd.ExportEvents(events)
}
