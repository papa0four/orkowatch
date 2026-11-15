// internal/tui/tabs.go

package tui

import (
	"fmt"
	"strings"

	"charm.land/bubbles/v2/key"
	"charm.land/bubbles/v2/viewport"
	tea "charm.land/bubbletea/v2"
	"charm.land/lipgloss/v2"
)

// Tab identifiers. A tab's identifier fixes the key that jumps to it, so a
// source has the same letter in every run. The identifiers after software
// are reserved for the sources that arrive with the enrichment work.
const (
	TabFindings = "findings"
	TabSystem   = "system"
	TabSoftware = "software"

	// tabBarLines is the line the tab bar takes when there is more than one
	// tab to choose between.
	tabBarLines = 1
)

type (
	// Tab is one source's view in the browser beyond the findings list: a
	// list of records with a detail pane, in that source's own terms. A tab
	// with no records shows Note instead, which is how a module that was
	// skipped or failed says so.
	Tab struct {
		ID      string
		Name    string
		Note    string
		Records []Record
	}

	// Record is one row of a tab. Its fields are shown in the detail pane in
	// the order given.
	Record struct {
		Title    string
		Subtitle string
		Fields   []SummaryLine
	}

	// tabDef is a tab as the tab bar knows it.
	tabDef struct {
		id     string
		name   string
		letter string
	}

	// recordPane is the list and detail of one record tab. Its state is
	// reached through a pointer, so it survives the value copies the Bubble
	// Tea model goes through.
	recordPane struct {
		tab     Tab
		index   []string
		visible []int
		cursor  int
		listTop int
		shown   int
		detail  viewport.Model
	}
)

var (
	// tabLetters is the single key that jumps to each tab.
	tabLetters = map[string]string{
		TabFindings: "f",
		TabSystem:   "o",
		TabSoftware: "s",
		"attack":    "m",
		"nvd":       "n",
		"kev":       "k",
		"epss":      "e",
		"ghsa":      "g",
	}

	// detailKeys is the viewport's key map. Its defaults bind j, k, h, l, f,
	// b, u, d and space, which would scroll a pane when a tab letter or a
	// search character was meant; only arrows and page keys scroll here.
	detailKeys = viewport.KeyMap{
		PageDown: key.NewBinding(key.WithKeys("pgdown")),
		PageUp:   key.NewBinding(key.WithKeys("pgup")),
		Down:     key.NewBinding(key.WithKeys("down")),
		Up:       key.NewBinding(key.WithKeys("up")),
		Left:     key.NewBinding(key.WithKeys("left")),
		Right:    key.NewBinding(key.WithKeys("right")),
	}
)

// buildTabs lists the tabs a report offers, findings first. The findings tab
// is there when there are rules to list or a note to give in their place.
func buildTabs(report Report) []tabDef {
	var tabs []tabDef
	if len(report.Items) > 0 || report.FindingsNote != "" {
		tabs = append(tabs, tabDef{id: TabFindings, name: "Findings", letter: tabLetters[TabFindings]})
	}
	for _, t := range report.Tabs {
		tabs = append(tabs, tabDef{id: t.ID, name: t.Name, letter: tabLetters[t.ID]})
	}
	return tabs
}

// buildPanes returns one pane per tab, parallel to tabs: nil for the
// findings tab, which the browser draws itself.
func buildPanes(report Report, tabs []tabDef) []*recordPane {
	panes := make([]*recordPane, len(tabs))
	sources := make(map[string]Tab, len(report.Tabs))
	for _, t := range report.Tabs {
		sources[t.ID] = t
	}
	for i, t := range tabs {
		if t.id != TabFindings {
			panes[i] = newRecordPane(sources[t.id])
		}
	}
	return panes
}

func newRecordPane(tab Tab) *recordPane {
	p := &recordPane{tab: tab, shown: -1, detail: viewport.New()}
	p.detail.KeyMap = detailKeys
	p.detail.SetHorizontalStep(sideScroll)
	p.index = make([]string, len(tab.Records))
	for i, r := range tab.Records {
		var text strings.Builder
		text.WriteString(r.Title + "\n" + r.Subtitle)
		for _, f := range r.Fields {
			text.WriteString("\n" + f.Label + " " + f.Value)
		}
		p.index[i] = strings.ToLower(text.String())
	}
	return p
}

// listless reports whether the pane has nothing to choose between: a note, or
// a single record, which is shown whole with no list above it.
func (p *recordPane) listless() bool {
	return len(p.tab.Records) <= 1
}

// refilter keeps the records that contain needle, already lower-case, and
// selects the first.
func (p *recordPane) refilter(needle string) {
	p.visible = p.visible[:0]
	for i, text := range p.index {
		if needle == "" || strings.Contains(text, needle) {
			p.visible = append(p.visible, i)
		}
	}
	p.cursor = 0
	p.listTop = 0
	p.shown = -1
}

// show keeps the selection inside the list's rows and loads it into the
// detail pane, which keeps its place when the same record is redrawn.
func (p *recordPane) show(rows, width int) {
	switch {
	case p.cursor < p.listTop:
		p.listTop = p.cursor
	case p.cursor >= p.listTop+rows:
		p.listTop = p.cursor - rows + 1
	}

	if len(p.visible) == 0 {
		p.shown = -1
		message := p.tab.Note
		if message == "" {
			message = "nothing matches the search"
		}
		p.detail.SetContent(styleMuted.Render(message))
		return
	}
	index := p.visible[p.cursor]
	var offset int
	if index == p.shown {
		offset = p.detail.YOffset()
	}
	p.detail.SetContent(recordText(p.tab.Records[index], width))
	p.detail.SetYOffset(offset)
	p.shown = index
}

// onListKey moves the selection through the visible records.
func (p *recordPane) onListKey(key string, rows int) bool {
	page := max(rows-1, 1)
	switch key {
	case "up":
		p.cursor--
	case "down":
		p.cursor++
	case "pgup":
		p.cursor -= page
	case "pgdown":
		p.cursor += page
	case "home":
		p.cursor = 0
	case "end":
		p.cursor = len(p.visible) - 1
	case "enter":
		return true
	default:
		return false
	}
	p.cursor = min(max(p.cursor, 0), max(len(p.visible)-1, 0))
	return false
}

// listView renders the rows of the list that fall inside its window.
func (p *recordPane) listView(rows, width int, selected bool) string {
	lines := make([]string, 0, rows)
	for row := p.listTop; row < min(p.listTop+rows, len(p.visible)); row++ {
		record := p.tab.Records[p.visible[row]]
		text := record.Title
		if record.Subtitle != "" {
			text += "  " + record.Subtitle
		}
		line := truncate(text, width)
		if row == p.cursor && selected {
			line = styleSelected.Render(fmt.Sprintf("%-*s", width, line))
		} else {
			line = styleText.Render(line)
		}
		lines = append(lines, line)
	}
	for len(lines) < rows {
		lines = append(lines, "")
	}
	return strings.Join(lines, "\n")
}

// recordText renders one record for the detail pane: its title, its
// subtitle, and each field under its label.
func recordText(r Record, width int) string {
	wrap := lipgloss.NewStyle().Width(max(width-1, minWidth))
	var out strings.Builder
	out.WriteString(styleText.Bold(true).Render(wrap.Render(r.Title)) + "\n")
	if r.Subtitle != "" {
		out.WriteString(styleMuted.Render(wrap.Render(r.Subtitle)) + "\n")
	}
	for _, f := range r.Fields {
		out.WriteString("\n" + styleMuted.Render(f.Label) + "\n" + wrap.Render(f.Value) + "\n")
	}
	return out.String()
}

// layout sizes the pane's detail to the browser's main pane: the whole body
// when there is no list above it, the part below the list otherwise.
func (p *recordPane) layout(b browser) {
	height := b.bodyHeight()
	if !p.listless() {
		height = max(height-b.listHeight()-searchLines-ruleLines, 1)
	}
	p.detail.SetWidth(b.mainWidth())
	p.detail.SetHeight(height)
}

// isFindings reports whether the findings tab, or no tab at all, is showing.
func (b browser) isFindings() bool {
	return len(b.tabs) == 0 || b.tabs[b.active].id == TabFindings
}

// activePane returns the record pane of the active tab, nil on the findings
// tab.
func (b browser) activePane() *recordPane {
	if len(b.panes) == 0 {
		return nil
	}
	return b.panes[b.active]
}

// tabBarHeight is the lines the tab bar takes: one when there is more than
// one tab to choose between, none otherwise.
func (b browser) tabBarHeight() int {
	if len(b.tabs) > 1 {
		return tabBarLines
	}
	return 0
}

// tabBar renders the tabs with the key that selects each, the active one lit.
func (b browser) tabBar() string {
	parts := make([]string, 0, len(b.tabs))
	for i, t := range b.tabs {
		label := t.name
		if t.letter != "" {
			label = t.letter + " " + t.name
		}
		style := styleMuted
		if i == b.active {
			style = styleSelected
		}
		parts = append(parts, style.Render(" "+label+" "))
	}
	return fitPane(strings.Join(parts, " "), b.width, tabBarLines)
}

// tabForKey returns the tab a key selects: a tab's letter, a digit counting
// from one, or -1. The brackets step through the tabs and are handled by the
// caller.
func (b browser) tabForKey(k string) int {
	for i, t := range b.tabs {
		if t.letter != "" && t.letter == k {
			return i
		}
	}
	if len(k) == 1 && k[0] >= '1' && k[0] <= '9' {
		if i := int(k[0] - '1'); i < len(b.tabs) {
			return i
		}
	}
	return -1
}

// selectTab makes tab i the active one. Each tab keeps its own search, and
// the panes are sized again because the filter pane is shown only beside the
// findings.
func (b *browser) selectTab(i int) {
	if i == b.active || i < 0 || i >= len(b.tabs) {
		return
	}
	b.queries[b.active] = b.query
	b.active = i
	b.query = b.queries[i]
	b.searching = false
	b.focus = focusList
	b.layout()
	b.showSelected()
}

// recordBody draws the active record tab: the search line, list and detail
// when there are records to choose between, the detail alone otherwise.
func (b browser) recordBody(p *recordPane) string {
	if p.listless() {
		return fitPane(p.detail.View(), b.mainWidth(), b.bodyHeight())
	}
	status := fmt.Sprintf("%d of %d %s", len(p.visible), len(p.tab.Records), strings.ToLower(p.tab.Name))
	main := lipgloss.JoinVertical(lipgloss.Left,
		b.queryLine(status),
		p.listView(b.listHeight(), b.mainWidth(), true),
		styleMuted.Render(strings.Repeat("─", b.mainWidth())),
		p.detail.View(),
	)
	return fitPane(main, b.mainWidth(), b.bodyHeight())
}

// onRecordKey drives a record tab: the list, or the detail pane when it has
// the keyboard or there is no list.
func (b browser) onRecordKey(msg tea.KeyPressMsg) (tea.Model, tea.Cmd) {
	p := b.activePane()
	k := msg.String()
	if p.listless() {
		return b, scroll(&p.detail, msg)
	}
	if b.focus == focusDetail {
		if k == "esc" {
			b.focus = focusList
			return b, nil
		}
		return b, scroll(&p.detail, msg)
	}
	if p.onListKey(k, b.listHeight()) {
		b.focus = focusDetail
		return b, nil
	}
	p.show(b.listHeight(), b.mainWidth())
	return b, nil
}
