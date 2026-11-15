// internal/tui/browser.go

package tui

import (
	"errors"
	"fmt"
	"strings"

	"charm.land/bubbles/v2/viewport"
	tea "charm.land/bubbletea/v2"
	"charm.land/lipgloss/v2"

	"github.com/papa0four/orkowatch/internal/security/finding"
)

const (
	// Pane geometry. The filter pane has a fixed width and is left out of a
	// window too narrow to also give the main pane minWidth columns. The
	// list takes a share of the height that remains and the detail pane the
	// rest.
	filterWidth   = 26
	paneRule      = 1
	headerLines   = 1
	footerLines   = 1
	defaultHeight = 24
	minListHeight = 4
	listShareNum  = 2
	listShareDen  = 5

	// searchLines and ruleLines are what the main pane spends above and
	// between its list and detail: the search line, and the rule that
	// separates the two.
	searchLines = 1
	ruleLines   = 1

	// resultColumn is the width the severity or result label is padded to
	// in a list row.
	resultColumn = 13

	// summaryLabelWidth is the column the summary's figures line up at.
	summaryLabelWidth = 14

	// evidencePreview is how many evidence lines the detail pane loads until
	// the operator asks for the rest. A whole-filesystem scan can attach
	// tens of thousands to one finding, and loading them all on every
	// cursor move makes the list lag.
	evidencePreview = 500

	// sideScroll is how many columns one left or right key press moves a
	// pane whose lines are wider than it is.
	sideScroll = 8

	// allFilter is the first option of each filter group.
	allFilter = "all"
)

// focus is which pane the keyboard is driving.
type focus uint8

const (
	focusFilters focus = iota
	focusList
	focusDetail
	focusCount
)

type (
	// Report is a finished run as the browser shows it. Text is the complete
	// plain report, which the browser can page through in full.
	Report struct {
		Title   string
		Host    string
		When    string
		Summary []SummaryLine
		Items   []Item
		Text    string
	}

	// SummaryLine is one labelled figure in the browser's summary.
	SummaryLine struct {
		Label string
		Value string
	}

	// Item is one evaluated rule. A finding carries the registry's text and
	// the evidence that caused it, each piece of evidence already rendered
	// as one line. Every other rule carries its result and, where it has
	// one, the reason.
	Item struct {
		Check       string
		Key         string
		Result      finding.Result
		Reason      string
		Severity    string
		Title       string
		Categories  []string
		Description string
		Impact      string
		Resolution  string
		References  []string
		Evidence    []string
	}

	// browser is the results browser's state.
	browser struct {
		report Report

		width  int
		height int
		focus  focus

		severities   []string
		checks       []string
		severity     int
		check        int
		filterCursor int
		findingsOnly bool

		// query is the search text. It is a plain string edited here rather
		// than a text input component, which would bring clipboard access
		// into the binary for the sake of one line of typing.
		query     string
		searching bool

		visible []int
		cursor  int
		listTop int

		// shown is the item the detail pane holds, or -1, so the pane keeps
		// its scroll position when it is redrawn for the same item.
		// fullEvidence is whether the operator asked for all of that item's
		// evidence rather than the first evidencePreview lines.
		shown        int
		fullEvidence bool

		detail   viewport.Model
		text     viewport.Model
		showText bool
	}
)

// Browse opens the results browser on report and returns when the operator
// leaves it.
func Browse(report Report) error {
	_, err := tea.NewProgram(newBrowser(report)).Run()
	if errors.Is(err, tea.ErrInterrupted) {
		return nil
	}
	return err
}

// isFinding reports whether the item is a rule that failed with a finding to
// show for it.
func (i Item) isFinding() bool {
	return i.Result == finding.ResultFail && i.Title != ""
}

func newBrowser(report Report) browser {
	b := browser{
		report:       report,
		width:        defaultWidth,
		height:       defaultHeight,
		focus:        focusList,
		severities:   []string{allFilter},
		checks:       []string{allFilter},
		findingsOnly: true,
		shown:        -1,
		detail:       viewport.New(),
		text:         viewport.New(),
		// A run with no rules to list, such as one that skipped the audit,
		// still has its report to read.
		showText: len(report.Items) == 0,
	}
	b.detail.SetHorizontalStep(sideScroll)
	b.text.SetHorizontalStep(sideScroll)
	b.text.SetContent(report.Text)

	levels := finding.Severities()
	for i := len(levels) - 1; i >= 0; i-- {
		b.severities = append(b.severities, levels[i])
	}
	seen := make(map[string]bool)
	for _, item := range report.Items {
		if !seen[item.Check] {
			seen[item.Check] = true
			b.checks = append(b.checks, item.Check)
		}
	}

	b.layout()
	b.refilter()
	return b
}

func (b browser) Init() tea.Cmd {
	return nil
}

func (b browser) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		b.width, b.height = msg.Width, msg.Height
		b.layout()
		b.showSelected()
		return b, nil

	case tea.KeyPressMsg:
		return b.onKey(msg)
	}
	return b, nil
}

// onKey routes a key press: to the search box while it is open, to the full
// report while it is shown, and otherwise to the focused pane.
func (b browser) onKey(msg tea.KeyPressMsg) (tea.Model, tea.Cmd) {
	key := msg.String()
	switch {
	case b.searching:
		b.onSearchKey(msg)
		if key == "ctrl+c" {
			return b, tea.Quit
		}
		return b, nil
	case key == "q" || key == "ctrl+c":
		return b, tea.Quit
	case b.showText:
		return b.onTextKey(msg)
	}

	switch key {
	case "t":
		b.showText = true
		return b, nil
	case "/":
		b.searching = true
		b.focus = focusList
		return b, nil
	case "a":
		b.findingsOnly = !b.findingsOnly
		b.refilter()
		return b, nil
	case "e":
		if b.evidenceCut() > 0 {
			b.fullEvidence = true
			b.showSelected()
		}
		return b, nil
	case "tab":
		b.cycleFocus(1)
		return b, nil
	case "shift+tab":
		b.cycleFocus(focusCount - 1)
		return b, nil
	}

	switch b.focus {
	case focusFilters:
		b.onFilterKey(key)
	case focusList:
		b.onListKey(key)
	case focusDetail:
		if key == "esc" {
			b.focus = focusList
			return b, nil
		}
		return b, scroll(&b.detail, msg)
	}
	return b, nil
}

// scroll moves a scrolling pane. The viewport binds no keys for its two
// ends, so those are handled here with the same keys the list uses.
func scroll(pane *viewport.Model, msg tea.KeyPressMsg) tea.Cmd {
	switch msg.String() {
	case "home", "g":
		pane.GotoTop()
		return nil
	case "end", "G":
		pane.GotoBottom()
		return nil
	}
	var cmd tea.Cmd
	*pane, cmd = pane.Update(msg)
	return cmd
}

// onSearchKey edits the search text. Every key that types something goes
// into it, letters the browser otherwise binds included.
func (b *browser) onSearchKey(msg tea.KeyPressMsg) {
	switch msg.String() {
	case "enter":
		b.searching = false
	case "esc":
		b.searching = false
		b.query = ""
		b.refilter()
	case "backspace":
		if runes := []rune(b.query); len(runes) > 0 {
			b.query = string(runes[:len(runes)-1])
			b.refilter()
		}
	default:
		// Text is empty for keys that type nothing, such as arrows.
		if msg.Text != "" {
			b.query += msg.Text
			b.refilter()
		}
	}
}

// onTextKey drives the full report. A report with no rules to list has
// nothing to go back to, so it stays open until the operator quits.
func (b browser) onTextKey(msg tea.KeyPressMsg) (tea.Model, tea.Cmd) {
	switch msg.String() {
	case "t", "esc":
		b.showText = len(b.report.Items) == 0
		return b, nil
	}
	return b, scroll(&b.text, msg)
}

// cycleFocus moves the keyboard step panes on, passing over the filter pane
// while the window is too narrow to show it.
func (b *browser) cycleFocus(step focus) {
	b.focus = (b.focus + step) % focusCount
	if b.focus == focusFilters && !b.filtersShown() {
		b.focus = (b.focus + step) % focusCount
	}
}

// onFilterKey moves through the two filter groups as one column and applies
// the option under the cursor on enter or space.
func (b *browser) onFilterKey(key string) {
	last := len(b.severities) + len(b.checks) - 1
	switch key {
	case "up", "k":
		b.filterCursor = max(b.filterCursor-1, 0)
	case "down", "j":
		b.filterCursor = min(b.filterCursor+1, last)
	case "enter", "space":
		if b.filterCursor < len(b.severities) {
			b.severity = b.filterCursor
		} else {
			b.check = b.filterCursor - len(b.severities)
		}
		b.refilter()
	}
}

// onListKey moves the selection through the visible items.
func (b *browser) onListKey(key string) {
	page := max(b.listHeight()-1, 1)
	switch key {
	case "up", "k":
		b.cursor--
	case "down", "j":
		b.cursor++
	case "pgup":
		b.cursor -= page
	case "pgdown":
		b.cursor += page
	case "home", "g":
		b.cursor = 0
	case "end", "G":
		b.cursor = len(b.visible) - 1
	case "enter":
		b.focus = focusDetail
		return
	default:
		return
	}
	b.cursor = min(max(b.cursor, 0), max(len(b.visible)-1, 0))
	b.showSelected()
}

// refilter recomputes which items the filters and the search leave visible,
// and resets the selection to the first of them.
func (b *browser) refilter() {
	needle := strings.ToLower(strings.TrimSpace(b.query))
	b.visible = b.visible[:0]
	for i, item := range b.report.Items {
		switch {
		case b.findingsOnly && !item.isFinding():
		case b.severity > 0 && (!item.isFinding() || item.Severity != b.severities[b.severity]):
		case b.check > 0 && item.Check != b.checks[b.check]:
		case needle != "" && !strings.Contains(strings.ToLower(item.Title+" "+item.Key+" "+item.Check), needle):
		default:
			b.visible = append(b.visible, i)
		}
	}
	b.cursor = 0
	b.listTop = 0
	b.showSelected()
}

// showSelected keeps the selection inside the list's window and loads the
// selected item into the detail pane. The pane starts at the top for a newly
// selected item and keeps its place when the same item is redrawn, as it is
// when the window is resized.
func (b *browser) showSelected() {
	rows := b.listHeight()
	switch {
	case b.cursor < b.listTop:
		b.listTop = b.cursor
	case b.cursor >= b.listTop+rows:
		b.listTop = b.cursor - rows + 1
	}

	if len(b.visible) == 0 {
		b.shown = -1
		b.detail.SetContent(styleMuted.Render("nothing matches the current filters"))
		return
	}
	index := b.visible[b.cursor]
	var offset int
	if index == b.shown {
		offset = b.detail.YOffset()
	} else {
		b.fullEvidence = false
	}
	b.detail.SetContent(b.detailText(b.report.Items[index]))
	b.detail.SetYOffset(offset)
	b.shown = index
}

// evidenceCut returns how many evidence lines of the selected item the
// detail pane is leaving out.
func (b browser) evidenceCut() int {
	if b.fullEvidence || b.shown < 0 {
		return 0
	}
	return max(len(b.report.Items[b.shown].Evidence)-evidencePreview, 0)
}

// layout sizes the panes to the window. A focused filter pane that no longer
// fits hands the keyboard to the list.
func (b *browser) layout() {
	if b.focus == focusFilters && !b.filtersShown() {
		b.focus = focusList
	}
	b.detail.SetWidth(b.mainWidth())
	b.detail.SetHeight(max(b.bodyHeight()-b.listHeight()-searchLines-ruleLines, 1))
	b.text.SetWidth(max(b.width, 1))
	b.text.SetHeight(b.bodyHeight())
}

func (b browser) bodyHeight() int {
	return max(b.height-headerLines-footerLines, 1)
}

// filtersShown reports whether the window is wide enough for the filter pane
// beside a main pane of at least minWidth columns.
func (b browser) filtersShown() bool {
	return b.width >= filterWidth+paneRule+minWidth
}

func (b browser) mainWidth() int {
	if !b.filtersShown() {
		return max(b.width, 1)
	}
	return b.width - filterWidth - paneRule
}

// listHeight is how many item rows the list shows: its share of the body,
// never fewer than minListHeight, and never so many that the detail pane
// loses its last line.
func (b browser) listHeight() int {
	rows := max(b.bodyHeight()*listShareNum/listShareDen, minListHeight)
	return max(min(rows, b.bodyHeight()-searchLines-ruleLines-1), 1)
}

func (b browser) View() tea.View {
	view := tea.NewView(b.render())
	view.AltScreen = true
	return view
}

// render draws the whole frame. Every line is held to the window's width and
// the frame to its height, because a line the terminal wraps or a frame
// taller than the window scrolls the alternate screen and tears the display.
func (b browser) render() string {
	var about string
	for _, part := range []string{b.report.Title, b.report.Host, b.report.When} {
		if part != "" {
			about += "  " + part
		}
	}
	header := styleTitle.Render("owatch") + styleMuted.Render(truncate(about, max(b.width-len("owatch"), 1)))
	footer := styleMuted.Render(truncate(b.help(), b.width))

	if b.showText {
		return header + "\n" + b.text.View() + "\n" + footer
	}

	main := lipgloss.JoinVertical(lipgloss.Left,
		b.searchView(),
		b.listView(),
		styleMuted.Render(strings.Repeat("─", b.mainWidth())),
		b.detail.View(),
	)
	body := fitPane(main, b.mainWidth(), b.bodyHeight())
	if b.filtersShown() {
		body = lipgloss.JoinHorizontal(lipgloss.Top,
			fitPane(b.filterView(), filterWidth, b.bodyHeight()),
			styleMuted.Render(strings.TrimRight(strings.Repeat("│\n", b.bodyHeight()), "\n")),
			body,
		)
	}
	return header + "\n" + body + "\n" + footer
}

// fitPane pads or clips text to exactly width columns and height lines.
func fitPane(text string, width, height int) string {
	return lipgloss.NewStyle().Width(width).Height(height).MaxWidth(width).MaxHeight(height).Render(text)
}

// help names the keys that do something in the focused pane.
func (b browser) help() string {
	const common = "   tab pane   / search   a all rules   t full report   q quit"
	evidence := ""
	if b.evidenceCut() > 0 {
		evidence = "   e all evidence"
	}
	switch {
	case b.showText && len(b.report.Items) == 0:
		return "full report   up/down pgup/pgdn scroll   left/right pan   q quit"
	case b.showText:
		return "full report   up/down pgup/pgdn scroll   left/right pan   t or esc back   q quit"
	case b.searching:
		return "type to search   enter keep   esc clear"
	case b.focus == focusFilters:
		return "up/down move   enter apply" + common
	case b.focus == focusDetail:
		return "up/down pgup/pgdn scroll   left/right pan   esc list" + evidence + common
	default:
		return "up/down pgup/pgdn move   enter detail" + evidence + common
	}
}

// searchView is the line above the list: the search text when there is any,
// how many items are shown of how many the scope admits, and the filters
// narrowing them. A severity filter shows only findings, since no other rule
// has a severity, and the line says so.
func (b browser) searchView() string {
	scope := "findings"
	if !b.findingsOnly && b.severity == 0 {
		scope = "rules"
	}
	status := fmt.Sprintf("%d of %d %s", len(b.visible), b.total(), scope)
	if b.severity > 0 {
		status += "  severity " + strings.ToLower(b.severities[b.severity])
	}
	if b.check > 0 {
		status += "  check " + b.checks[b.check]
	}

	var query string
	switch {
	case b.searching:
		query = "/ " + b.query + "_  "
	case b.query != "":
		query = "/ " + b.query + "  "
	default:
		status += "   / to search"
	}
	line := truncate(query+status, b.mainWidth())
	if query == "" {
		return styleMuted.Render(line)
	}
	return styleText.Render(line)
}

// total counts the items the scope admits before the other filters and the
// search: every rule, or only findings when the toggle or a severity filter
// limits it to them.
func (b browser) total() int {
	if !b.findingsOnly && b.severity == 0 {
		return len(b.report.Items)
	}
	var findings int
	for _, item := range b.report.Items {
		if item.isFinding() {
			findings++
		}
	}
	return findings
}

// filterView renders the two filter groups and the run's summary.
func (b browser) filterView() string {
	var out strings.Builder
	option := func(index int, label string, selected bool) {
		line := "  " + label
		if selected {
			line = "> " + label
		}
		style := styleMuted
		switch {
		case b.focus == focusFilters && b.filterCursor == index:
			style = styleSelected
		case selected:
			style = styleText
		}
		out.WriteString(style.Render(fmt.Sprintf("%-*s", filterWidth-1, line)) + "\n")
	}

	out.WriteString(b.paneTitle("severity", focusFilters) + "\n")
	for i, level := range b.severities {
		option(i, strings.ToLower(level), b.severity == i)
	}
	out.WriteString("\n" + b.paneTitle("check", focusFilters) + "\n")
	for i, check := range b.checks {
		option(len(b.severities)+i, check, b.check == i)
	}

	out.WriteString("\n" + styleMuted.Render("summary") + "\n")
	for _, line := range b.report.Summary {
		label := fmt.Sprintf("%-*s", summaryLabelWidth, line.Label)
		value := truncate(line.Value, max(filterWidth-1-lipgloss.Width(label), 1))
		out.WriteString(styleMuted.Render(label) + styleText.Render(value) + "\n")
	}
	return out.String()
}

// paneTitle renders a heading, lit when its pane has the keyboard.
func (b browser) paneTitle(title string, pane focus) string {
	if b.focus == pane {
		return styleTitle.Render(title)
	}
	return styleMuted.Render(title)
}

// listView renders the rows of the list that fall inside its window.
func (b browser) listView() string {
	rows := b.listHeight()
	lines := make([]string, 0, rows)
	for row := b.listTop; row < min(b.listTop+rows, len(b.visible)); row++ {
		item := b.report.Items[b.visible[row]]
		line := truncate(b.rowText(item), b.mainWidth())
		switch {
		case row == b.cursor && b.focus != focusFilters:
			line = styleSelected.Render(fmt.Sprintf("%-*s", b.mainWidth(), line))
		default:
			line = lipgloss.NewStyle().Foreground(itemColor(item)).Render(line)
		}
		lines = append(lines, line)
	}
	for len(lines) < rows {
		lines = append(lines, "")
	}
	return strings.Join(lines, "\n")
}

// rowText is one item as a single list line.
func (browser) rowText(item Item) string {
	if item.isFinding() {
		symbol, _ := finding.SeverityFormat(item.Severity)
		return fmt.Sprintf("%s %-*s%s  (%s)", symbol, resultColumn, strings.ToLower(item.Severity), item.Title, item.Check)
	}
	return fmt.Sprintf("%s %-*s%s  (%s)", resultMark(item.Result), resultColumn, string(item.Result), item.Key, item.Check)
}

// detailText renders everything known about one item for the detail pane.
func (b browser) detailText(item Item) string {
	wrap := lipgloss.NewStyle().Width(max(b.mainWidth()-1, minWidth))
	var out strings.Builder

	heading := string(item.Result)
	if item.isFinding() {
		heading = item.Severity
	}
	out.WriteString(lipgloss.NewStyle().Foreground(itemColor(item)).Bold(true).Render(strings.ToUpper(heading)) +
		styleMuted.Render("  "+item.Check+"  "+item.Key) + "\n")
	if item.Title != "" {
		out.WriteString(styleText.Bold(true).Render(wrap.Render(item.Title)) + "\n")
	}
	if item.Reason != "" {
		out.WriteString(wrap.Render(item.Reason) + "\n")
	}

	section := func(name, body string) {
		if strings.TrimSpace(body) != "" {
			out.WriteString("\n" + styleMuted.Render(name) + "\n" + wrap.Render(strings.TrimSpace(body)) + "\n")
		}
	}
	section("categories", strings.Join(item.Categories, ", "))
	section("description", item.Description)
	section("impact", item.Impact)
	section("resolution", item.Resolution)
	section("references", strings.Join(item.References, "\n"))

	if len(item.Evidence) > 0 {
		out.WriteString("\n" + styleMuted.Render(fmt.Sprintf("evidence (%d)", len(item.Evidence))) + "\n")
		lines := item.Evidence
		if !b.fullEvidence && len(lines) > evidencePreview {
			lines = lines[:evidencePreview]
		}
		out.WriteString(strings.Join(lines, "\n") + "\n")
		if cut := len(item.Evidence) - len(lines); cut > 0 {
			out.WriteString(styleNotice.Render(fmt.Sprintf("%d more; press e to load all", cut)) + "\n")
		}
	}
	return out.String()
}
