package tui

import (
	"fmt"
	"strings"

	"github.com/charmbracelet/lipgloss"

	"github.com/defenseclaw/defenseclaw/internal/audit"
)

type skillItem struct {
	Name   string
	Status string
	Reason string
	Time   string
}

type SkillsPanel struct {
	items   []skillItem
	cursor  int
	width   int
	height  int
	store   *audit.Store
	message string
}

func NewSkillsPanel(store *audit.Store) SkillsPanel {
	return SkillsPanel{store: store}
}

func (p *SkillsPanel) Refresh() {
	if p.store == nil {
		return
	}

	p.items = nil

	blocked, err := p.store.ListBlockedByType("skill")
	if err != nil {
		p.message = fmt.Sprintf("Error: %v", err)
		return
	}
	for _, b := range blocked {
		p.items = append(p.items, skillItem{
			Name:   b.TargetName,
			Status: "blocked",
			Reason: b.Reason,
			Time:   b.CreatedAt.Format("2006-01-02 15:04"),
		})
	}

	allowed, err := p.store.ListAllowedByType("skill")
	if err != nil {
		p.message = fmt.Sprintf("Error: %v", err)
		return
	}
	for _, a := range allowed {
		p.items = append(p.items, skillItem{
			Name:   a.TargetName,
			Status: "allowed",
			Reason: a.Reason,
			Time:   a.CreatedAt.Format("2006-01-02 15:04"),
		})
	}

	if p.cursor >= len(p.items) && len(p.items) > 0 {
		p.cursor = len(p.items) - 1
	}
	p.message = ""
}

func (p *SkillsPanel) SetSize(w, h int) {
	p.width = w
	p.height = h
}

func (p *SkillsPanel) CursorUp()   { if p.cursor > 0 { p.cursor-- } }
func (p *SkillsPanel) CursorDown() { if p.cursor < len(p.items)-1 { p.cursor++ } }

func (p *SkillsPanel) Selected() *skillItem {
	if p.cursor >= 0 && p.cursor < len(p.items) {
		return &p.items[p.cursor]
	}
	return nil
}

func (p *SkillsPanel) ToggleBlock() string {
	sel := p.Selected()
	if sel == nil {
		return ""
	}
	if sel.Status == "blocked" {
		_ = p.store.RemoveBlock("skill", sel.Name)
		_ = p.store.AddAllow("skill", sel.Name, "unblocked from TUI")
		p.Refresh()
		return fmt.Sprintf("Allowed skill: %s", sel.Name)
	}
	_ = p.store.RemoveAllow("skill", sel.Name)
	_ = p.store.AddBlock("skill", sel.Name, "blocked from TUI")
	p.Refresh()
	return fmt.Sprintf("Blocked skill: %s", sel.Name)
}

func (p *SkillsPanel) Count() int                 { return len(p.items) }
func (p *SkillsPanel) BlockedCount() int {
	n := 0
	for _, i := range p.items {
		if i.Status == "blocked" {
			n++
		}
	}
	return n
}

func (p *SkillsPanel) View() string {
	if p.message != "" {
		return p.message
	}
	if len(p.items) == 0 {
		return StyleInfo.Render("  No skills in block/allow lists. Use 'defenseclaw block skill' or 'defenseclaw allow skill' to add.")
	}

	var b strings.Builder
	header := fmt.Sprintf("  %-10s %-40s %-25s %-16s", "STATUS", "NAME", "REASON", "SINCE")
	b.WriteString(HeaderStyle.Render(header))
	b.WriteString("\n")

	maxVisible := p.height - 4
	if maxVisible < 1 {
		maxVisible = 10
	}

	start := 0
	if p.cursor >= maxVisible {
		start = p.cursor - maxVisible + 1
	}
	end := start + maxVisible
	if end > len(p.items) {
		end = len(p.items)
	}

	for i := start; i < end; i++ {
		item := p.items[i]
		status := StatusStyle(item.Status).Render(fmt.Sprintf("%-10s", strings.ToUpper(item.Status)))
		name := item.Name
		if len(name) > 40 {
			name = name[:37] + "..."
		}
		reason := item.Reason
		if len(reason) > 25 {
			reason = reason[:22] + "..."
		}

		line := fmt.Sprintf("  %s %-40s %-25s %-16s", status, name, reason, item.Time)

		if i == p.cursor {
			line = SelectedStyle.Width(p.width).Render(line)
		}
		b.WriteString(line)
		if i < end-1 {
			b.WriteString("\n")
		}
	}

	if len(p.items) > maxVisible {
		b.WriteString("\n")
		b.WriteString(lipgloss.NewStyle().Foreground(lipgloss.Color("241")).Render(
			fmt.Sprintf("  showing %d-%d of %d", start+1, end, len(p.items)),
		))
	}

	return b.String()
}
