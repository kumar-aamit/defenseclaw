package tui

import (
	"fmt"
	"strings"

	"github.com/charmbracelet/lipgloss"

	"github.com/defenseclaw/defenseclaw/internal/audit"
)

type mcpItem struct {
	URL    string
	Status string
	Reason string
	Time   string
}

type MCPsPanel struct {
	items   []mcpItem
	cursor  int
	width   int
	height  int
	store   *audit.Store
	message string
}

func NewMCPsPanel(store *audit.Store) MCPsPanel {
	return MCPsPanel{store: store}
}

func (p *MCPsPanel) Refresh() {
	if p.store == nil {
		return
	}

	p.items = nil

	blocked, err := p.store.ListBlockedByType("mcp")
	if err != nil {
		p.message = fmt.Sprintf("Error: %v", err)
		return
	}
	for _, b := range blocked {
		p.items = append(p.items, mcpItem{
			URL:    b.TargetName,
			Status: "blocked",
			Reason: b.Reason,
			Time:   b.CreatedAt.Format("2006-01-02 15:04"),
		})
	}

	allowed, err := p.store.ListAllowedByType("mcp")
	if err != nil {
		p.message = fmt.Sprintf("Error: %v", err)
		return
	}
	for _, a := range allowed {
		p.items = append(p.items, mcpItem{
			URL:    a.TargetName,
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

func (p *MCPsPanel) SetSize(w, h int) {
	p.width = w
	p.height = h
}

func (p *MCPsPanel) CursorUp()   { if p.cursor > 0 { p.cursor-- } }
func (p *MCPsPanel) CursorDown() { if p.cursor < len(p.items)-1 { p.cursor++ } }

func (p *MCPsPanel) Selected() *mcpItem {
	if p.cursor >= 0 && p.cursor < len(p.items) {
		return &p.items[p.cursor]
	}
	return nil
}

func (p *MCPsPanel) ToggleBlock() string {
	sel := p.Selected()
	if sel == nil {
		return ""
	}
	if sel.Status == "blocked" {
		_ = p.store.RemoveBlock("mcp", sel.URL)
		_ = p.store.AddAllow("mcp", sel.URL, "unblocked from TUI")
		p.Refresh()
		return fmt.Sprintf("Allowed MCP: %s", sel.URL)
	}
	_ = p.store.RemoveAllow("mcp", sel.URL)
	_ = p.store.AddBlock("mcp", sel.URL, "blocked from TUI")
	p.Refresh()
	return fmt.Sprintf("Blocked MCP: %s", sel.URL)
}

func (p *MCPsPanel) Count() int { return len(p.items) }
func (p *MCPsPanel) BlockedCount() int {
	n := 0
	for _, i := range p.items {
		if i.Status == "blocked" {
			n++
		}
	}
	return n
}

func (p *MCPsPanel) View() string {
	if p.message != "" {
		return p.message
	}
	if len(p.items) == 0 {
		return StyleInfo.Render("  No MCP servers in block/allow lists. Use 'defenseclaw block mcp' or 'defenseclaw allow mcp' to add.")
	}

	var b strings.Builder
	header := fmt.Sprintf("  %-10s %-50s %-25s %-16s", "STATUS", "URL", "REASON", "SINCE")
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
		url := item.URL
		if len(url) > 50 {
			url = url[:47] + "..."
		}
		reason := item.Reason
		if len(reason) > 25 {
			reason = reason[:22] + "..."
		}

		line := fmt.Sprintf("  %s %-50s %-25s %-16s", status, url, reason, item.Time)

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
