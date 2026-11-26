// internal/tui/tabs.go

package tui

import (
	"fmt"
	"slices"
	"strings"

	"charm.land/bubbles/v2/key"
	"charm.land/bubbles/v2/viewport"
	tea "charm.land/bubbletea/v2"
	"charm.land/lipgloss/v2"

	"github.com/papa0four/orkowatch/internal/tone"
)

// Tab identifiers. A tab's identifier fixes the key that jumps to it, so a
// source has the same letter in every run.
const (
	TabFindings        = "findings"
	TabSystem          = "system"
	TabSoftware        = "software"
	TabVulnerabilities = "vulnerabilities"
	TabSockets         = "sockets"
	TabAttack          = "attack"
	TabDatasets        = "datasets"

	// The headings of the source table in the left pane, and the gap between
	// its two columns.
	keyHeading    = "key"
	sourceHeading = "source"
	sourceGap     = "  "

	// tabBarLines is the line the tab bar takes when there is more than one
	// tab to choose between.
	tabBarLines = 1

	// ruleChar draws every rule in the browser, and ruleLead is the stretch
	// of a band's rule ahead of the band's name.
	ruleChar = "─"
	ruleLead = ruleChar + ruleChar
)

type (
	// Tab is one source's view in the browser beyond the findings list: a
	// list of records with a detail pane, in that source's own terms. A tab
	// with no records shows Note instead, which is how a module that was
	// skipped or failed says so.
	Tab struct {
		ID   string
		Name string

		// Noun is what the tab's records are called in its status line, in
		// lower case. Empty, the lower-cased Name is used, which would write
		// a trademarked name in lower case.
		Noun    string
		Note    string
		Records []Record

		// Filters are the groups the left pane narrows the records by, each
		// record falling under one or more options of each.
		Filters []Filter

		// Switch, when it names a key, is a key that moves one of the
		// filters between two of its options from the list.
		Switch Switch

		// Alert names the band whose heading and records are drawn whole in
		// the known-exploited tone, so the records of confirmed exploitation
		// stand apart from the rest.

		Alert string

		// Attention marks a tab holding what the operator must act on, so its
		// name stands out as a notice wherever the sources are listed,
		// whichever tab is open.
		Attention bool
	}

	// Switch is a key that moves the filter named Filter between its
	// options A and B: to B from A, and to A from any other. Hint says what
	// the key does, for the key hints.
	Switch struct {
		Key    string
		Filter string
		A, B   string
		Hint   string
	}

	// Filter is a group of options the left pane narrows a tab's records
	// by: its name, its options in the order shown, and the option the tab
	// opens on. An option named All admits every record. Spares names a band
	// whose records the filter does not narrow, so they stay listed
	// whichever option is chosen. Tones gives the options that carry a
	// meaning, such as a severity, the tone the option's first word is drawn
	// in.
	Filter struct {
		Name    string
		Options []string
		Start   string
		Spares  string
		Tones   map[string]tone.Tone
	}

	// Record is one row of a tab. Its fields are shown in the detail pane in
	// the order given. Filters is the options of each of the tab's filters
	// the record falls under, in the tab's order. Band is the part of the
	// list the record is in, which the list heads with the band's name where
	// it changes, so a tab gives the records of one band together; a tab
	// whose records have none has no headings.
	Record struct {
		Title    string
		Subtitle Line
		Fields   []SummaryLine
		Filters  [][]string
		Band     string
	}

	// Line is text in runs, each drawn in its tone, so only the words that
	// carry a meaning are colored and the rest keeps the terminal's own
	// color.
	Line []Span

	// Span is a run of a Line's text and the tone it is drawn in.
	Span struct {
		Text string
		Tone tone.Tone
	}

	// listLine is one line of a record tab's list: the heading of a band with
	// how many of the visible records are in it, or the visible record at
	// row.
	listLine struct {
		heading string
		count   int
		row     int
	}

	// tabDef is a tab as the tab bar knows it.
	tabDef struct {
		id        string
		name      string
		letter    string
		attention bool
	}

	// recordPane is the list and detail of one record tab. Its state is
	// reached through a pointer, so it survives the value copies the Bubble
	// Tea model goes through. groups are the tab's filters as the left pane
	// walks them. lines are the visible records with the headings of their
	// bands, and lineOf the line of each visible record; listTop counts
	// lines, and cursor visible records.
	recordPane struct {
		tab     Tab
		index   []string
		groups  []*filterGroup
		visible []int
		lines   []listLine
		lineOf  []int
		cursor  int
		listTop int
		shown   int
		detail  viewport.Model
	}

	// filterGroup is a group of filter options as the left pane draws and
	// walks it: its name, its options and the label each is shown with,
	// which is chosen, how many records of the whole tab fall under each
	// option, or none where the tab does not count them, and the band whose
	// records it does not narrow.
	filterGroup struct {
		name    string
		options []string
		labels  []string
		chosen  int
		counts  []int
		spares  string
		tones   map[string]tone.Tone
	}
)

// All is the option of a filter that admits every record.
const All = allFilter

// option is the option chosen in g, or the empty string for one that admits
// everything.
func (g *filterGroup) option() string {
	if g.options[g.chosen] == allFilter {
		return ""
	}
	return g.options[g.chosen]
}

var (
	// tabLetters is the single key that jumps to each tab.
	tabLetters = map[string]string{
		TabFindings:        "f",
		TabSystem:          "o",
		TabSoftware:        "s",
		TabVulnerabilities: "v",
		TabSockets:         "l",
		TabAttack:          "m",
		TabDatasets:        "d",
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
		tabs = append(tabs, tabDef{id: t.ID, name: t.Name, letter: tabLetters[t.ID], attention: t.Attention})
	}
	return tabs
}

// nameStyle is how the source list and the tab bar draw t's name where the
// keyboard is not on it: as a notice when the operator has something to do
// there, in plain otherwise.
func (t tabDef) nameStyle(plain lipgloss.Style) lipgloss.Style {
	if t.attention {
		return styleNotice
	}
	return plain
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
		text.WriteString(r.Title + "\n" + r.Subtitle.String())
		for _, f := range r.Fields {
			text.WriteString("\n" + f.Label + " " + f.Value)
		}
		p.index[i] = strings.ToLower(text.String())
	}
	for at, f := range tab.Filters {
		g := &filterGroup{name: f.Name, options: f.Options, labels: f.Options, counts: make([]int, len(f.Options)), spares: f.Spares, tones: f.Tones}
		g.chosen = max(slices.Index(f.Options, f.Start), 0)
		for i, option := range f.Options {
			for _, r := range tab.Records {
				if option == allFilter || (at < len(r.Filters) && slices.Contains(r.Filters[at], option)) {
					g.counts[i]++
				}
			}
		}
		p.groups = append(p.groups, g)
	}
	return p
}

// admits reports whether record i falls under the option chosen in each of
// the pane's filters that narrows its band.
func (p *recordPane) admits(i int) bool {
	record := p.tab.Records[i]
	for at, g := range p.groups {
		if g.spares != "" && record.Band == g.spares {
			continue
		}
		if option := g.option(); option != "" && (at >= len(record.Filters) || !slices.Contains(record.Filters[at], option)) {
			return false
		}
	}
	return true
}

// listless reports whether the pane has nothing to choose between: a note, or
// a single record, which is shown whole with no list above it.
func (p *recordPane) listless() bool {
	return len(p.tab.Records) <= 1
}

// refilter keeps the records the chosen filters admit that contain needle,
// already lower-case, heads each band among them where it changes, and
// selects the first.
func (p *recordPane) refilter(needle string) {
	p.visible = p.visible[:0]
	for i, text := range p.index {
		if p.admits(i) && (needle == "" || strings.Contains(text, needle)) {
			p.visible = append(p.visible, i)
		}
	}
	p.lines, p.lineOf = p.lines[:0], p.lineOf[:0]
	band, heading := "", -1
	for row, i := range p.visible {
		if b := p.tab.Records[i].Band; b != "" && b != band {
			heading = len(p.lines)
			p.lines = append(p.lines, listLine{heading: b, row: -1})
		}
		band = p.tab.Records[i].Band
		if band != "" && heading >= 0 {
			p.lines[heading].count++
		}
		p.lineOf = append(p.lineOf, len(p.lines))
		p.lines = append(p.lines, listLine{row: row})
	}
	p.cursor = 0
	p.listTop = 0
	p.shown = -1
}

// show keeps the selection inside the list's rows, with the heading of its
// band when it is the band's first, and loads it into the detail pane, which
// keeps its place when the same record is redrawn.
func (p *recordPane) show(rows, width int) {
	if len(p.visible) > 0 {
		line := p.lineOf[p.cursor]
		switch {
		case line < p.listTop:
			p.listTop = line
			if line > 0 && p.lines[line-1].row < 0 {
				p.listTop--
			}
		case line >= p.listTop+rows:
			p.listTop = line - rows + 1
		}
	}

	if len(p.visible) == 0 {
		p.shown = -1
		message := p.tab.Note
		if message == "" {
			message = "nothing matches the search"
		}
		p.detail.SetContent(styleMuted.Render(detailWrap(width).Render(message)))
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

// switchFilter moves the filter the tab's switch names between its two
// options, and reports whether key is the switch's.
func (p *recordPane) switchFilter(key string) bool {
	sw := p.tab.Switch
	if sw.Key == "" || key != sw.Key {
		return false
	}
	for _, g := range p.groups {
		if g.name != sw.Filter {
			continue
		}
		to := sw.A
		if g.options[g.chosen] == sw.A {
			to = sw.B
		}
		g.chosen = max(slices.Index(g.options, to), 0)
	}
	return true
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

// listView renders the lines of the list that fall inside its window.
func (p *recordPane) listView(rows, width int, selected bool) string {
	lines := make([]string, 0, rows)
	for _, at := range p.lines[min(p.listTop, len(p.lines)):min(p.listTop+rows, len(p.lines))] {
		band := at.heading
		if at.row >= 0 {
			band = p.tab.Records[p.visible[at.row]].Band
		}
		style := p.bandStyle(band)
		if at.row < 0 {
			lines = append(lines, style.Bold(true).Render(bandRule(at.heading, at.count, width)))
			continue
		}
		row := at.row
		record := p.tab.Records[p.visible[row]]
		text, toned := record.Title, style.Render(record.Title)
		if len(record.Subtitle) > 0 {
			text += "  " + record.Subtitle.String()
			toned += style.Render("  ") + record.Subtitle.render(style)
		}
		if row == p.cursor && selected {
			lines = append(lines, styleSelected.Render(fmt.Sprintf("%-*s", width, truncate(text, width))))
			continue
		}
		lines = append(lines, truncate(toned, width))
	}
	for len(lines) < rows {
		lines = append(lines, "")
	}
	return strings.Join(lines, "\n")
}

// bandStyle is how the list draws the words of a line of band that carry no
// tone of their own: in the known-exploited tone when it is the tab's alert
// band, and in the terminal's own color otherwise. A word that carries a tone,
// such as a severity, keeps it in every band.
func (p *recordPane) bandStyle(band string) lipgloss.Style {
	if band != "" && band == p.tab.Alert {
		return tone.KnownExploited.Style()
	}
	return lipgloss.NewStyle()
}

// Plain is text as a Line in no tone, or no Line for no text.
func Plain(text string) Line {
	if text == "" {
		return nil
	}
	return Line{{Text: text}}
}

// String is the Line's text without its tones.
func (l Line) String() string {
	var b strings.Builder
	for _, s := range l {
		b.WriteString(s.Text)
	}
	return b.String()
}

// render draws the Line: each run in its tone, and a run in no tone in plain.
func (l Line) render(plain lipgloss.Style) string {
	var b strings.Builder
	for _, s := range l {
		if s.Tone == tone.Plain {
			b.WriteString(plain.Render(s.Text))
		} else {
			b.WriteString(s.Tone.Render(s.Text))
		}
	}
	return b.String()
}

// bandRule is the heading of a band as a rule across the list: the band's
// name and how many records are in it, between lines drawn to width.
func bandRule(name string, count, width int) string {
	label := truncate(fmt.Sprintf("%s %s (%d) ", ruleLead, name, count), width)
	return label + strings.Repeat(ruleChar, max(width-lipgloss.Width(label), 0))
}

// detailWrap wraps text to a detail pane width columns wide: one column
// narrower than the pane, and never narrower than minWidth, so no line of a
// detail is cut off at the pane's edge.
func detailWrap(width int) lipgloss.Style {
	return lipgloss.NewStyle().Width(max(width-1, minWidth))
}

// recordText renders one record for the detail pane: its title, its
// subtitle, and each field under its label.
func recordText(r Record, width int) string {
	wrap := detailWrap(width)
	var out strings.Builder
	out.WriteString(styleText.Bold(true).Render(wrap.Render(r.Title)) + "\n")
	if len(r.Subtitle) > 0 {
		out.WriteString(wrap.Render(r.Subtitle.render(styleMuted)) + "\n")
	}
	for _, f := range r.Fields {
		out.WriteString("\n" + styleMuted.Render(f.Label) + "\n" + wrap.Render(f.Tone.Render(f.Value)) + "\n")
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

// tabBarHeight is the lines the tab bar takes: one when the window is too
// narrow for the left pane, which otherwise lists the sources, and there is
// more than one to choose between.
func (b browser) tabBarHeight() int {
	if len(b.tabs) > 1 && !b.sidebarShown() {
		return tabBarLines
	}
	return 0
}

// tabBar renders the tabs with the key that selects each, the active one lit.
// It stands in for the left pane's source list in a window too narrow for it.
func (b browser) tabBar() string {
	parts := make([]string, 0, len(b.tabs))
	for i, t := range b.tabs {
		label := t.name
		if t.letter != "" {
			label = t.letter + " " + t.name
		}
		style := t.nameStyle(styleMuted)
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

// selectTab makes tab i the active one. Each tab keeps its own search. The
// keyboard stays in the left pane when the source was chosen there, so the
// next source is one key away, and goes to the list otherwise.
func (b *browser) selectTab(i int) {
	if i == b.active || i < 0 || i >= len(b.tabs) {
		return
	}
	b.queries[b.active] = b.query
	b.active = i
	b.query = b.queries[i]
	b.searching = false
	if b.focus != focusFilters {
		b.focus = focusList
	}
	b.filterCursor = i
	b.layout()
	b.showSelected()
}

// recordBody draws the active record tab: the search line, list and detail
// when there are records to choose between, the detail alone otherwise.
func (b browser) recordBody(p *recordPane) string {
	if p.listless() {
		return fitPane(p.detail.View(), b.mainWidth(), b.bodyHeight())
	}
	noun := p.tab.Noun
	if noun == "" {
		noun = strings.ToLower(p.tab.Name)
	}
	status := fmt.Sprintf("%s: %d of %d", noun, len(p.visible), len(p.tab.Records))
	main := lipgloss.JoinVertical(lipgloss.Left,
		b.queryLine(status),
		p.listView(b.listHeight(), b.mainWidth(), true),
		styleMuted.Render(strings.Repeat(ruleChar, b.mainWidth())),
		p.detail.View(),
	)
	return fitPane(main, b.mainWidth(), b.bodyHeight())
}

// onRecordKey drives a record tab: the list, or the detail pane when it has
// the keyboard or there is no list.
func (b browser) onRecordKey(msg tea.KeyPressMsg) (tea.Model, tea.Cmd) {
	p := b.activePane()
	k := msg.String()
	if b.focus == focusFilters {
		b.onFilterKey(k)
		return b, nil
	}
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
	if p.switchFilter(k) {
		b.refilter()
		return b, nil
	}
	if p.onListKey(k, b.listHeight()) {
		b.focus = focusDetail
		return b, nil
	}
	p.show(b.listHeight(), b.mainWidth())
	return b, nil
}
