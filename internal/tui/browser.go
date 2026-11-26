// internal/tui/browser.go

package tui

import (
	"errors"
	"fmt"
	"slices"
	"strconv"
	"strings"
	"time"

	"charm.land/bubbles/v2/viewport"
	tea "charm.land/bubbletea/v2"
	"charm.land/lipgloss/v2"

	"github.com/papa0four/orkowatch/internal/security/finding"
	"github.com/papa0four/orkowatch/internal/tone"
)

const (
	// Pane geometry. The filter pane has a fixed width and is left out of a
	// window too narrow to also give the main pane minWidth columns. The
	// list takes a share of the height that remains and the detail pane the
	// rest.
	filterWidth   = 26
	paneRule      = 1
	headerLines   = 2
	footerLines   = 1
	defaultHeight = 24
	minListHeight = 4
	listShareNum  = 2
	listShareDen  = 5

	// optionLead is the columns the left pane draws before an option, its
	// marker when chosen, and countGap the least space between an option's
	// label and its count.
	optionLead = 2
	countGap   = 1

	// The banner: the brand on its right, the separator between the run, the
	// host and the time on its left, the least room kept between the two
	// sides, and the form the time is written in.
	projectName     = "Project Orko"
	productName     = "Orko Watch"
	toolCommand     = "owatch"
	bannerSeparator = " · "
	bannerGap       = "  "
	bannerTime      = "2006-01-02 15:04:05 UTC"

	// searchLines and ruleLines are what the main pane spends above and
	// between its list and detail: the search line, and the rule that
	// separates the two.
	searchLines = 1
	ruleLines   = 1

	// resultColumn is the width the severity or result label is padded to
	// in a list row.
	resultColumn = 14

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

		// FindingsNote stands in for the findings tab when there are no rules
		// to list, as when the audit was skipped. Tabs are the other sources'
		// views, in the order they are offered.
		FindingsNote string
		Tabs         []Tab

		// Start is the identifier of the tab the browser opens on. Empty, or
		// naming a tab the report does not offer, it opens on the findings.
		Start string
		Text  string

		// Refresh fetches the datasets the report was matched against and
		// matches it again, on r. A report with none offers no r.
		Refresh Refresher
	}

	// SummaryLine is one labeled figure in the browser's summary, or one
	// field of a record's detail. Tone colors the whole value, for a field
	// whose value is one meaning, such as a severity.
	SummaryLine struct {
		Label string
		Value string
		Tone  tone.Tone
	}

	// Item is one evaluated rule. A finding carries the registry's text and
	// the evidence that caused it, each piece of evidence already rendered
	// as one line. Every other rule carries its result and, where it has
	// one, the reason.
	Item struct {
		Check      string
		Key        string
		Result     finding.Result
		Reason     string
		Severity   string
		Title      string
		Categories []string

		// Weakness is the CWE entry the finding maps to, with MITRE's
		// description of it, or the reason none fits, and ClassExploited how
		// many vulnerabilities known to be exploited are of that class. CVSS
		// is the registry's baseline and HostCVSS the score on this host with
		// what it rests on, each labeled with what it is a statement about.
		// SeverityBasis says which of them Severity is.
		Weakness       string
		WeaknessAbout  string
		ClassExploited string
		CVSS           string
		HostCVSS       string
		SeverityBasis  string
		Description    string
		Impact         string
		Resolution     string
		References     []string
		Techniques     []string
		Mitigations    []string
		Evidence       []string
	}

	// itemIndex is an item's searchable text, lower-cased once when the
	// browser opens so a keystroke costs a substring test rather than a
	// conversion of every line of every item's evidence.
	itemIndex struct {
		text     string
		evidence []string
	}

	// browser is the results browser's state.
	browser struct {
		report Report

		width  int
		height int
		focus  focus

		// findings are the Findings tab's filters: severity, then check.
		findings     []*filterGroup
		filterCursor int
		sideTop      int
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
		// evidence rather than the first evidencePreview lines. evidenceTop
		// is the line of the pane its evidence heading is on, where x moves
		// the pane, or -1 when it has none.
		shown        int
		fullEvidence bool
		evidenceTop  int

		// index holds each item's searchable text, parallel to
		// report.Items. evidence is the shown item's evidence lines that
		// the search leaves in: all of them when there is no search.
		index    []itemIndex
		evidence []string

		detail   viewport.Model
		text     viewport.Model
		showText bool

		// tabs lists the views on offer and active is the one showing. panes
		// is parallel to tabs, nil for findings; queries holds each tab's
		// search while another tab is showing.
		tabs    []tabDef
		active  int
		panes   []*recordPane
		queries []string

		// refreshing is the refresh r asked for, and leave the text a
		// refresh that cannot be made here closed the browser with.
		refreshing refreshState
		leave      *Leave
	}
)

// Browse opens the results browser on report and returns when the operator
// leaves it. A refresh that cannot be made here closes it with a Leave, whose
// text is for the caller to print.
func Browse(report Report) error {
	final, err := tea.NewProgram(newBrowser(report)).Run()
	if errors.Is(err, tea.ErrInterrupted) {
		return nil
	}
	if b, ok := final.(browser); ok && err == nil && b.leave != nil {
		return *b.leave
	}
	return err
}

// isFinding reports whether the item is a rule that failed with a finding to
// show for it.
func (i Item) isFinding() bool {
	return i.Result == finding.ResultFail && i.Title != ""
}

// needsAttention reports whether the operator has something to act on or to
// know: a finding, or a rule that could not be evaluated. A rule that errored
// says nothing about the host either way, so a view limited to findings would
// hide that a check, say one that needs elevated privileges, never got an
// answer.
func (i Item) needsAttention() bool {
	return i.isFinding() || i.Result == finding.ResultError || i.Result == finding.ResultUnknown
}

func newBrowser(report Report) browser {
	b := browser{
		report:       report,
		width:        defaultWidth,
		height:       defaultHeight,
		focus:        focusList,
		findingsOnly: true,
		shown:        -1,
		detail:       viewport.New(),
		text:         viewport.New(),
	}
	b.tabs = buildTabs(report)
	b.panes = buildPanes(report, b.tabs)
	b.queries = make([]string, len(b.tabs))
	// A run with nothing to list, such as one that skipped every module,
	// still has its report to read.
	b.showText = len(b.tabs) == 0
	b.detail.KeyMap = detailKeys
	b.text.KeyMap = detailKeys
	b.detail.SetHorizontalStep(sideScroll)
	b.text.SetHorizontalStep(sideScroll)
	b.text.SetContent(report.Text)

	severity := &filterGroup{name: "severity", options: []string{allFilter}, labels: []string{allFilter}, tones: map[string]tone.Tone{}}
	levels := finding.Severities()
	for i := len(levels) - 1; i >= 0; i-- {
		severity.options = append(severity.options, levels[i])
		severity.labels = append(severity.labels, strings.ToLower(levels[i]))
		severity.tones[levels[i]] = tone.ForSeverity(levels[i])
	}
	check := &filterGroup{name: "check", options: []string{allFilter}}
	seen := make(map[string]bool)
	for _, item := range report.Items {
		if !seen[item.Check] {
			seen[item.Check] = true
			check.options = append(check.options, item.Check)
		}
	}
	check.labels = check.options
	b.findings = []*filterGroup{severity, check}

	b.index = buildIndex(report.Items)

	b.layout()
	b.refilterFindings()
	for _, p := range b.panes {
		if p != nil {
			p.refilter("")
		}
	}
	b.showSelected()
	for i, t := range b.tabs {
		if t.id == report.Start {
			b.selectTab(i)
		}
	}
	return b
}

// buildIndex lower-cases every field of every item a search looks in.
func buildIndex(items []Item) []itemIndex {
	index := make([]itemIndex, len(items))
	for i, item := range items {
		fields := []string{item.Title, item.Key, item.Check, item.Reason, item.Description,
			item.Impact, item.Resolution, item.Weakness, item.WeaknessAbout, item.ClassExploited,
			item.CVSS, item.HostCVSS, item.SeverityBasis}
		fields = append(fields, item.Categories...)
		fields = append(fields, item.References...)
		fields = append(fields, item.Techniques...)
		fields = append(fields, item.Mitigations...)
		index[i].text = strings.ToLower(strings.Join(fields, "\n"))
		index[i].evidence = make([]string, len(item.Evidence))
		for j, line := range item.Evidence {
			index[i].evidence[j] = strings.ToLower(line)
		}
	}
	return index
}

// matches reports whether needle, already lower-case, is in the item's
// fields or in any line of its evidence.
func (x itemIndex) matches(needle string) bool {
	return strings.Contains(x.text, needle) || slices.ContainsFunc(x.evidence, func(line string) bool {
		return strings.Contains(line, needle)
	})
}

func (b browser) Init() tea.Cmd {
	return nil
}

func (b browser) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	if m, cmd, ok := b.onRefreshMsg(msg); ok {
		return m, cmd
	}
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
// report while it is shown, and otherwise to the focused pane. Esc on the list
// or the left pane clears a kept search, on whichever tab shows it; the detail
// pane keeps esc for going back to the list.
func (b browser) onKey(msg tea.KeyPressMsg) (tea.Model, tea.Cmd) {
	key := msg.String()
	if m, cmd, ok := b.onRefreshKey(key); ok {
		return m, cmd
	}
	// Why the last refresh did not replace the report is shown until the
	// next key.
	b.refreshing.failed, b.refreshing.notice = "", ""
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
	case key == "esc" && b.clearsSearch():
		b.query = ""
		b.refilter()
		return b, nil
	case key == "esc" && b.escToFilters():
		// The cursor is where it was left, on the filter last applied.
		b.focus = focusFilters
		b.keepCursorVisible()
		return b, nil
	}

	if next, ok := b.onTabKey(key); ok {
		return next, nil
	}

	switch key {
	case "t":
		b.showText = true
		return b, nil
	case "r":
		if b.report.Refresh != nil {
			return b, b.startRefresh()
		}
		return b, nil
	case "/":
		if p := b.activePane(); p == nil || !p.listless() {
			b.searching = true
			b.focus = focusList
		}
		return b, nil
	case "tab":
		b.cycleFocus(1)
		return b, nil
	case "shift+tab":
		b.cycleFocus(focusCount - 1)
		return b, nil
	}

	if b.activePane() != nil {
		return b.onRecordKey(msg)
	}
	return b.onFindingKey(msg)
}

// clearsSearch reports whether esc clears the search: one is kept, and the
// keyboard is on the list or the left pane.
func (b browser) clearsSearch() bool {
	return b.query != "" && b.focus != focusDetail
}

// escToFilters reports whether esc takes the keyboard from the list back to
// the left pane: no search is kept for esc to clear first, and the left pane
// is shown.
func (b browser) escToFilters() bool {
	return b.focus == focusList && !b.clearsSearch() && b.sidebarShown()
}

// onTabKey switches tabs on a tab's letter, a digit, or a bracket, reporting
// whether the key was one. With a single tab there is nothing to switch to.
func (b browser) onTabKey(k string) (browser, bool) {
	if len(b.tabs) < 2 {
		return b, false
	}
	switch k {
	case "]":
		b.selectTab((b.active + 1) % len(b.tabs))
		return b, true
	case "[":
		b.selectTab((b.active + len(b.tabs) - 1) % len(b.tabs))
		return b, true
	}
	if i := b.tabForKey(k); i >= 0 {
		b.selectTab(i)
		return b, true
	}
	return b, false
}

// onFindingKey drives the findings tab: its two toggles, then the focused pane.
func (b browser) onFindingKey(msg tea.KeyPressMsg) (tea.Model, tea.Cmd) {
	key := msg.String()
	switch key {
	case "a":
		b.findingsOnly = !b.findingsOnly
		b.refilter()
		return b, nil
	case "x":
		if b.evidenceFolds() {
			b.fullEvidence = !b.fullEvidence
			b.showSelected()
			b.detail.SetYOffset(b.evidenceTop)
		}
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
	case "home":
		pane.GotoTop()
		return nil
	case "end":
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
		b.showText = len(b.tabs) == 0
		return b, nil
	}
	return b, scroll(&b.text, msg)
}

// cycleFocus moves the keyboard step panes on, passing over the filter pane
// while the window is too narrow to show it.
func (b *browser) cycleFocus(step focus) {
	b.focus = (b.focus + step) % focusCount
	if b.focus == focusFilters && !b.sidebarShown() {
		b.focus = (b.focus + step) % focusCount
	}
}

// filterGroups are the filters of the active tab, as the left pane walks
// them: the findings' severity and check, or the record tab's own.
func (b browser) filterGroups() []*filterGroup {
	if p := b.activePane(); p != nil {
		return p.groups
	}
	return b.findings
}

// onFilterKey moves through the left pane as one column: the sources, then
// the options of each of the active tab's filters. Enter or space applies the
// option under the cursor: it opens a source or sets a filter.
func (b *browser) onFilterKey(key string) {
	sources := len(b.tabs)
	last := sources - 1
	for _, g := range b.filterGroups() {
		last += len(g.options)
	}
	defer b.keepCursorVisible()
	switch key {
	case "up":
		b.filterCursor = max(b.filterCursor-1, 0)
	case "down":
		b.filterCursor = min(b.filterCursor+1, last)
	case "pgup":
		b.filterCursor = max(b.filterCursor-max(b.bodyHeight()-1, 1), 0)
	case "pgdown":
		b.filterCursor = min(b.filterCursor+max(b.bodyHeight()-1, 1), last)
	case "home":
		b.filterCursor = 0
	case "end":
		b.filterCursor = last
	case "enter", "space":
		option := b.filterCursor - sources
		// Enter on the source already open goes into its list, as enter on
		// a filter does; on another source it opens that one and the
		// keyboard stays here, so the next source is one key away.
		if option < 0 && b.filterCursor == b.active {
			b.focus = focusList
			return
		}
		if option < 0 {
			b.selectTab(b.filterCursor)
			return
		}
		// A filter applied hands the keyboard to the list it narrowed, ready
		// to move through or search; esc or shift+tab comes back.
		for _, g := range b.filterGroups() {
			if option < len(g.options) {
				g.chosen = option
				b.refilter()
				b.focus = focusList
				return
			}
			option -= len(g.options)
		}
	}
}

// onListKey moves the selection through the visible items.
func (b *browser) onListKey(key string) {
	page := max(b.listHeight()-1, 1)
	switch key {
	case "up":
		b.cursor--
	case "down":
		b.cursor++
	case "pgup":
		b.cursor -= page
	case "pgdown":
		b.cursor += page
	case "home":
		b.cursor = 0
	case "end":
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

// refilter recomputes what the search leaves visible on the active tab, and
// resets the selection to the first of it.
func (b *browser) refilter() {
	if p := b.activePane(); p != nil {
		p.refilter(b.needle())
		p.show(b.listHeight(), b.mainWidth())
		return
	}
	b.refilterFindings()
}

// refilterFindings recomputes which items the filters and the search leave
// visible, and resets the selection to the first of them.
func (b *browser) refilterFindings() {
	needle := strings.ToLower(strings.TrimSpace(b.query))
	b.visible = b.visible[:0]
	severity, check := b.findings[0].option(), b.findings[1].option()
	for i, item := range b.report.Items {
		switch {
		case !b.admits(item):
		case severity != "" && item.Severity != severity:
		case check != "" && item.Check != check:
		case needle != "" && !b.index[i].matches(needle):
		default:
			b.visible = append(b.visible, i)
		}
	}
	b.cursor = 0
	b.listTop = 0
	// The evidence the pane holds depends on the search, so it is rebuilt
	// even when the same item stays selected.
	b.shown = -1
	b.showFinding()
}

// needle is the search text as it is matched: trimmed and lower-case.
func (b browser) needle() string {
	return strings.ToLower(strings.TrimSpace(b.query))
}

// evidenceFor returns the lines of an item's evidence the search leaves in,
// which is all of them when nothing is being searched for.
func (b browser) evidenceFor(index int) []string {
	lines := b.report.Items[index].Evidence
	needle := b.needle()
	if needle == "" {
		return lines
	}
	var kept []string
	for i, lower := range b.index[index].evidence {
		if strings.Contains(lower, needle) {
			kept = append(kept, lines[i])
		}
	}
	return kept
}

// showSelected loads the selection of the active tab into its detail pane.
func (b *browser) showSelected() {
	if p := b.activePane(); p != nil {
		p.show(b.listHeight(), b.mainWidth())
		return
	}
	b.showFinding()
}

// showFinding keeps the selection inside the list's window and loads the
// selected item into the detail pane. The pane starts at the top for a newly
// selected item and keeps its place when the same item is redrawn, as it is
// when the window is resized.
func (b *browser) showFinding() {
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
	if index != b.shown {
		b.evidence = b.evidenceFor(index)
	}
	text, top := b.detailText(b.report.Items[index])
	b.detail.SetContent(text)
	b.detail.SetYOffset(offset)
	b.shown = index
	b.evidenceTop = top
}

// evidenceFolds reports whether the selected item has more evidence lines than
// the preview, so x switches between the preview and all of them.
func (b browser) evidenceFolds() bool {
	return b.shown >= 0 && len(b.evidence) > evidencePreview
}

// layout sizes the panes to the window. A focused filter pane that no longer
// fits hands the keyboard to the list.
func (b *browser) layout() {
	if b.focus == focusFilters && !b.sidebarShown() {
		b.focus = focusList
	}
	b.keepCursorVisible()
	b.detail.SetWidth(b.mainWidth())
	b.detail.SetHeight(max(b.bodyHeight()-b.listHeight()-searchLines-ruleLines, 1))
	b.text.SetWidth(max(b.width, 1))
	b.text.SetHeight(b.bodyHeight())
	for _, p := range b.panes {
		if p != nil {
			p.layout(*b)
		}
	}
}

func (b browser) bodyHeight() int {
	return max(b.height-headerLines-footerLines-b.tabBarHeight(), 1)
}

// sidebarShown reports whether the window is wide enough for the left pane
// beside a main pane of at least minWidth columns. The pane stays on every
// tab, so that findings from the other sources can take their place in it
// without the layout changing under the operator.
func (b browser) sidebarShown() bool {
	return b.width >= filterWidth+paneRule+minWidth
}

func (b browser) mainWidth() int {
	if !b.sidebarShown() {
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
	header := b.banner()
	footer := b.helpView()

	top := header + "\n" + b.headerRule()
	if b.tabBarHeight() > 0 {
		top += "\n" + b.tabBar()
	}

	if b.showText {
		return top + "\n" + b.text.View() + "\n" + footer
	}

	var body string
	switch p := b.activePane(); {
	case p != nil:
		body = b.recordBody(p)
	case len(b.report.Items) == 0:
		body = fitPane(styleMuted.Render(b.report.FindingsNote), b.mainWidth(), b.bodyHeight())
	default:
		main := lipgloss.JoinVertical(lipgloss.Left,
			b.searchView(),
			b.listView(),
			styleMuted.Render(strings.Repeat(ruleChar, b.mainWidth())),
			b.detail.View(),
		)
		body = fitPane(main, b.mainWidth(), b.bodyHeight())
	}
	if b.sidebarShown() {
		body = lipgloss.JoinHorizontal(lipgloss.Top,
			fitPane(b.filterView(), filterWidth, b.bodyHeight()),
			b.divider(),
			body,
		)
	}
	if replaced, ok := b.refreshBody(body); ok {
		body = replaced
	}
	if replaced, ok := b.refreshFooter(); ok {
		footer = replaced
	}
	return top + "\n" + body + "\n" + footer
}

// banner is the top line: the run, the host and when it ran on the left, and
// the brand on the right. The tool's name is in the brand, so the run is shown
// without it. A window too narrow for both drops the brand first, because the
// left side is what identifies the report.
func (b browser) banner() string {
	run := strings.TrimPrefix(b.report.Title, toolCommand+" ")
	var details []string
	for _, part := range []string{b.report.Host, readableTime(b.report.When)} {
		if part != "" {
			details = append(details, part)
		}
	}

	width := max(b.width, 1)
	plain := strings.Join(append([]string{run}, details...), bannerSeparator)
	if lipgloss.Width(plain) > width {
		return styleTitle.Render(truncate(plain, width))
	}
	left := styleTitle.Render(run)
	for _, part := range details {
		left += styleMuted.Render(bannerSeparator + part)
	}

	brand := styleProject.Render(projectName+":") + " " + styleProduct.Render(productName) + " " + styleCommand.Render("("+toolCommand+")")
	room := width - lipgloss.Width(left) - lipgloss.Width(brand)
	if room < len(bannerGap) {
		return left
	}
	return left + strings.Repeat(" ", room) + brand
}

// readableTime writes a report's RFC 3339 timestamp as a date and a time in
// UTC, and returns any other text as it is.
func readableTime(stamp string) string {
	t, err := time.Parse(time.RFC3339, stamp)
	if err != nil {
		return stamp
	}
	return t.UTC().Format(bannerTime)
}

// sourcesRule closes the left pane's table of sources, so the part of the
// pane that switches sources is set apart from the filters and summary below.
func sourcesRule() string { return styleMuted.Render(strings.Repeat(ruleChar, filterWidth)) }

// divider is the rule between the left pane and the main one, joined to the
// sources rule where that is on screen.
func (b browser) divider() string {
	window, _ := b.sidebarWindow()
	rule := sourcesRule()
	rows := make([]string, b.bodyHeight())
	for i := range rows {
		rows[i] = "│"
		if i < len(window) && window[i] == rule {
			rows[i] = "┤"
		}
	}
	return styleMuted.Render(strings.Join(rows, "\n"))
}

// headerRule is the line under the banner. It separates the banner, which
// names the run, from the panes below it, and where the left pane is shown it
// joins the rule between that pane and the main one.
func (b browser) headerRule() string {
	width := max(b.width, 1)
	if b.showText || !b.sidebarShown() {
		return styleMuted.Render(strings.Repeat(ruleChar, width))
	}
	return styleMuted.Render(strings.Repeat(ruleChar, filterWidth) + "┬" + strings.Repeat(ruleChar, max(width-filterWidth-paneRule, 0)))
}

// fitPane pads or clips text to exactly width columns and height lines.
func fitPane(text string, width, height int) string {
	return lipgloss.NewStyle().Width(width).Height(height).MaxWidth(width).MaxHeight(height).Render(text)
}

// hint is one key binding in the footer: the keys that do it, each shown in
// parentheses, and what it does. The word "or" between keys is not a key and
// is left bare.
type hint struct {
	keys   []string
	action string
}

func keyHint(action string, keys ...string) hint { return hint{keys: keys, action: action} }

// label is a hint with no keys: a word naming the mode the footer is for.
func label(text string) hint { return hint{action: text} }

// width is the columns the hint takes when drawn.
func (h hint) width() int { return lipgloss.Width(h.render()) }

// render draws the keys in parentheses, in the text color so they stand out
// from the muted action beside them.
func (h hint) render() string {
	parts := make([]string, 0, len(h.keys))
	for _, k := range h.keys {
		if k == "or" {
			parts = append(parts, styleMuted.Render(k))
			continue
		}
		parts = append(parts, styleText.Bold(true).Render("("+k+")"))
	}
	if len(parts) == 0 {
		return styleMuted.Render(h.action)
	}
	return strings.Join(parts, " ") + styleMuted.Render(" "+h.action)
}

// helpView draws the footer: the keys that do something in the focused pane,
// each in parentheses so it reads apart from the words describing it. When the
// window is too narrow for all of them the ones before the last are dropped
// from the end backward, search and pane first, so the way out always stays.
func (b browser) helpView() string {
	hints := b.help()
	const gap = 3
	total := func() int {
		n := gap * (len(hints) - 1)
		for _, h := range hints {
			n += h.width()
		}
		return n
	}
	for len(hints) > 2 && total() > b.width {
		hints = append(hints[:len(hints)-2], hints[len(hints)-1])
	}
	rendered := make([]string, len(hints))
	for i, h := range hints {
		rendered[i] = h.render()
	}
	return lipgloss.NewStyle().MaxWidth(max(b.width, 1)).Render(strings.Join(rendered, strings.Repeat(" ", gap)))
}

// help lists the key bindings that do something in the focused pane.
func (b browser) help() []hint {
	move := keyHint("move", "up/down", "pgup/pgdn")
	scroll := keyHint("scroll", "up/down", "pgup/pgdn")
	pan := keyHint("pan", "left/right")
	quit := keyHint("quit", "q")
	report := keyHint("full report", "t")
	pane := keyHint("switch pane", "tab")
	search := keyHint("search", "/")

	var tabs []hint
	if len(b.tabs) > 1 {
		tabs = []hint{keyHint("prev/next source", "[ ]")}
	}
	// common lists the hints of a pane in the order they are dropped from the end
	// when the window is narrow: movement first and kept longest, then clearing a
	// kept search, the way to the full report, the sources and the panes, and
	// last the toggles that only the findings have, then search.
	common := func(before []hint, toggles ...hint) []hint {
		out := before
		if b.clearsSearch() {
			out = append(out, keyHint("clear search", "esc"))
		}
		out = append(out, report)
		if b.report.Refresh != nil {
			out = append(out, keyHint("refresh", "r"))
		}
		out = append(out, tabs...)
		out = append(out, pane)
		out = append(out, toggles...)
		return append(out, search, quit)
	}
	findings := []hint{keyHint("all rules", "a")}
	switch {
	case b.evidenceFolds() && b.fullEvidence:
		findings = append(findings, keyHint("less evidence", "x"))
	case b.evidenceFolds():
		findings = append(findings, keyHint("all evidence", "x"))
	}

	pn := b.activePane()
	// From the list, esc goes back to the left pane once no search is kept.
	var back []hint
	if b.escToFilters() {
		back = []hint{keyHint("left pane", "esc")}
	}
	switch {
	case b.showText && len(b.tabs) == 0:
		return []hint{label("full report"), scroll, pan, quit}
	case b.showText:
		return append([]hint{scroll, pan, keyHint("back", "t", "or", "esc")}, append(tabs, quit)...)
	case b.searching:
		return []hint{label("type to search"), keyHint("keep", "enter"), keyHint("clear", "esc")}
	case b.focus == focusFilters && pn != nil && len(pn.groups) > 0:
		return common([]hint{keyHint("move", "up/down"), keyHint("open or apply", "enter")})
	case b.focus == focusFilters && pn != nil:
		return common([]hint{keyHint("move", "up/down"), keyHint("open source", "enter")})
	case pn != nil && pn.listless():
		return append([]hint{scroll, pan}, append(tabs, report, quit)...)
	case pn != nil && b.focus == focusDetail:
		return common([]hint{scroll, pan, keyHint("list", "esc")})
	case pn != nil && pn.tab.Switch.Key != "":
		return common(append([]hint{move, keyHint("detail", "enter")}, back...), keyHint(pn.tab.Switch.Hint, pn.tab.Switch.Key))
	case pn != nil:
		return common(append([]hint{move, keyHint("detail", "enter")}, back...))
	case b.focus == focusFilters:
		return common([]hint{keyHint("move", "up/down"), keyHint("apply", "enter")}, findings...)
	case b.focus == focusDetail:
		return common([]hint{scroll, pan, keyHint("list", "esc")}, findings...)
	default:
		return common(append([]hint{move, keyHint("detail", "enter")}, back...), findings...)
	}
}

// searchView is the line above the list: the search text when there is any,
// how many items are shown of how many the scope admits, and the filters
// narrowing them. The scope is named before the counts, so it reads the same
// whatever they are, one included. A severity filter shows only findings, since no other rule
// has a severity, and the line says so.
func (b browser) searchView() string {
	severity, check := b.findings[0].option(), b.findings[1].option()
	scope := "findings and errors"
	switch {
	case severity != "":
		scope = "findings"
	case !b.findingsOnly:
		scope = "rules"
	}
	status := fmt.Sprintf("%s: %d of %d", scope, len(b.visible), b.total())
	if severity != "" {
		status += "  severity " + strings.ToLower(severity)
	}
	if check != "" {
		status += "  check " + check
	}
	return b.queryLine(status)
}

// queryLine renders the line above a list: the search text when there is any,
// then the status the tab gives of what the list holds. With no search in it,
// it is the list's heading, lit while the list has the keyboard as the left
// pane's headings are.
func (b browser) queryLine(status string) string {
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
		return b.paneTitle(line, focusList)
	}
	return styleText.Render(line)
}

// admits reports whether the scope lets an item through before the other
// filters and the search: findings only when a severity is chosen, since no
// other rule has one; findings and rules that could not be evaluated in the
// default view; every rule once the toggle is on.
func (b browser) admits(item Item) bool {
	switch {
	case b.findings[0].option() != "":
		return item.isFinding()
	case b.findingsOnly:
		return item.needsAttention()
	default:
		return true
	}
}

// total counts the items the scope admits.
func (b browser) total() int {
	var admitted int
	for _, item := range b.report.Items {
		if b.admits(item) {
			admitted++
		}
	}
	return admitted
}

// filterView renders the left pane's window onto its lines: the pane is
// scrolled to keep the cursor in view when its contents are taller than the
// body, and says so at the edge that has more.
func (b browser) filterView() string {
	window, _ := b.sidebarWindow()
	return strings.Join(window, "\n")
}

// sidebarWindow returns the lines of the left pane that fit the body and the
// index of the first of them, marking where more lies above or below.
func (b browser) sidebarWindow() (window []string, top int) {
	lines, cursorLine := b.sidebarLines()
	height := b.bodyHeight()
	top = min(b.sideTop, max(len(lines)-height, 0))
	end := min(top+height, len(lines))
	window = slices.Clone(lines[top:end])
	if top > 0 && cursorLine != top {
		window[0] = styleMuted.Render("  more above")
	}
	if end < len(lines) && cursorLine != end-1 {
		window[len(window)-1] = styleMuted.Render("  more below")
	}
	return window, top
}

// keepCursorVisible scrolls the left pane just far enough that the line under
// the cursor is inside it. It runs wherever the cursor or the pane's height
// changes, so the render itself holds no state.
func (b *browser) keepCursorVisible() {
	lines, cursorLine := b.sidebarLines()
	height := b.bodyHeight()
	switch {
	case cursorLine < b.sideTop:
		b.sideTop = cursorLine
	case cursorLine >= b.sideTop+height:
		b.sideTop = cursorLine - height + 1
	}
	b.sideTop = min(max(b.sideTop, 0), max(len(lines)-height, 0))
}

// sidebarLines lays out the left pane: the sources with the key that opens
// each, then the findings filters and the run's summary. A source other than
// the findings has none of those yet, and the pane says so rather than
// leaving the space empty, so the layout is the same on every source and
// findings can later attach to them without it changing. It returns the line
// the cursor is on as well, which is what scrolling follows.
func (b browser) sidebarLines() (lines []string, cursorLine int) {
	option := func(index int, label string, t tone.Tone, selected bool) {
		if b.filterCursor == index {
			cursorLine = len(lines)
		}
		lines = append(lines, b.optionLine(index, label, t, selected))
	}

	// The sources are a table: the key that opens each, then its name, under
	// headings, with the key column as wide as the longest key or its heading so
	// the rows line up however many sources there are.
	keyWidth := len(keyHeading)
	for _, t := range b.tabs {
		keyWidth = max(keyWidth, len(t.letter))
	}
	lines = append(lines, b.paneTitle(fmt.Sprintf("  %-*s%s%s", keyWidth, keyHeading, sourceGap, sourceHeading), focusFilters))
	for i, t := range b.tabs {
		option(i, fmt.Sprintf("%-*s%s%s", keyWidth, t.letter, sourceGap, t.name), tone.Plain, b.active == i)
	}

	notApplicable := styleMuted.Render("  n/a")
	if groups := b.filterGroups(); len(groups) > 0 {
		b.groupLines(groups, func(line string) { lines = append(lines, line) }, option)
	} else {
		lines = append(lines, sourcesRule(), styleMuted.Render("severity"), notApplicable)
		lines = append(lines, "", styleMuted.Render("check"), notApplicable)
	}

	lines = append(lines, "", styleMuted.Render("summary"))
	if !b.isFindings() || len(b.report.Summary) == 0 {
		return append(lines, notApplicable+styleMuted.Render("  no findings yet")), cursorLine
	}
	for _, line := range b.report.Summary {
		label := summaryLabel(line.Label)
		value := truncate(line.Value, max(filterWidth-1-lipgloss.Width(label), 1))
		lines = append(lines, styleMuted.Render(label)+value)
	}
	return lines, cursorLine
}

// optionLine draws one option of the left pane at index: marked when it is
// selected, muted when it is not, a source in its name's style, the option
// the keyboard is on reversed, and the first word of an option with a tone in
// that tone.
func (b browser) optionLine(index int, label string, t tone.Tone, selected bool) string {
	lead := "  "
	style := styleMuted
	if selected {
		lead, style = "> ", styleText
	}
	if index < len(b.tabs) {
		style = b.tabs[index].nameStyle(style)
	}
	line := fmt.Sprintf("%-*s", filterWidth-1, lead+label)
	if b.focus == focusFilters && b.filterCursor == index {
		return styleSelected.Render(line)
	}
	if t == tone.Plain {
		return style.Render(line)
	}
	word, rest, _ := strings.Cut(line[len(lead):], " ")
	return style.Render(lead) + t.Render(word) + style.Render(" "+rest)
}

// groupLines lays out the active tab's filters in the left pane, after the
// sources: each group under its heading, each option through option, which
// knows where the cursor is, with its count where the tab counts them and in
// its tone where it carries a meaning. Headings and spacing go through
// heading.
func (b browser) groupLines(groups []*filterGroup, heading func(string), option func(index int, label string, t tone.Tone, selected bool)) {
	index := len(b.tabs)
	for at, g := range groups {
		if at == 0 {
			heading(sourcesRule())
		} else {
			heading("")
		}
		heading(b.paneTitle(g.name, focusFilters))
		widest := 0
		if len(g.counts) > 0 {
			widest = len(strconv.Itoa(slices.Max(g.counts)))
		}
		for i, label := range g.labels {
			if g.counts != nil {
				label = countedLabel(label, g.counts[i], widest)
			}
			option(index, label, g.tones[g.options[i]], g.chosen == i)
			index++
		}
	}
}

// summaryLabel is a summary figure's label in its column, cut short where it
// would otherwise run into the figure, so a space always parts the two.
func summaryLabel(label string) string {
	return fmt.Sprintf("%-*s", summaryLabelWidth, truncate(label, summaryLabelWidth-1))
}

// countedLabel is a filter option with how many records fall under it: the
// count at the pane's right edge, right-aligned in a column widest digits
// wide so a group's counts line up however large they are, and the label cut
// short where it would otherwise run into the count.
func countedLabel(label string, count, widest int) string {
	room := filterWidth - 1 - optionLead - widest - countGap
	label = truncate(label, room)
	return label + strings.Repeat(" ", room-lipgloss.Width(label)+countGap) + fmt.Sprintf("%*d", widest, count)
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
		lead, word, rest := b.rowParts(item)
		var line string
		switch {
		case row == b.cursor && b.focus != focusFilters:
			line = styleSelected.Render(fmt.Sprintf("%-*s", b.mainWidth(), truncate(lead+word+rest, b.mainWidth())))
		default:
			line = truncate(lead+itemTone(item).Render(word)+rest, b.mainWidth())
		}
		lines = append(lines, line)
	}
	for len(lines) < rows {
		lines = append(lines, "")
	}
	return strings.Join(lines, "\n")
}

// rowParts is one item as a single list line, in three parts: what leads it,
// the word that carries its severity or result, padded to its column, and the
// rest, so the word alone can be drawn in its tone.
func (b browser) rowParts(item Item) (lead, word, rest string) {
	text := b.rowText(item)
	lead, after, _ := strings.Cut(text, " ")
	return lead + " ", after[:resultColumn], after[resultColumn:]
}

// rowText is one item as a single list line.
func (browser) rowText(item Item) string {
	if item.isFinding() {
		symbol, _ := finding.SeverityFormat(item.Severity)
		return fmt.Sprintf("%s %-*s%s  (%s)", symbol, resultColumn, strings.ToLower(item.Severity), item.Title, item.Check)
	}
	line := fmt.Sprintf("%s %-*s%s  (%s)", resultMark(item.Result), resultColumn, string(item.Result), item.Key, item.Check)
	if item.Reason != "" {
		line += "  " + item.Reason
	}
	return line
}

// triggerText says what raised a finding: the rule that failed and what it
// found, the evidence recorded for it, the severity and what it rests on, and
// the ATT&CK techniques the rule is mapped to, so each of those can be
// traced back to the host observation it came from.
func triggerText(item Item) string {
	lines := []string{"rule      " + item.Key + "  (" + item.Check + " check failed)"}
	if item.Reason != "" {
		lines = append(lines, "found     "+item.Reason)
	}
	switch n := len(item.Evidence); n {
	case 0:
		lines = append(lines, "evidence  none recorded; the rule's result alone raised it")
	case 1:
		lines = append(lines, "evidence  1 entry, listed below")
	default:
		lines = append(lines, fmt.Sprintf("evidence  %d entries, listed below", n))
	}
	severity := "severity  " + item.Severity
	if item.SeverityBasis != "" {
		severity += ", " + item.SeverityBasis
	}
	lines = append(lines, severity)
	var ids []string
	for _, technique := range item.Techniques {
		if fields := strings.Fields(technique); len(fields) > 0 {
			ids = append(ids, fields[0])
		}
	}
	if len(ids) > 0 {
		lines = append(lines, "attack    "+strings.Join(ids, ", ")+", because this rule failed")
	}
	return strings.Join(lines, "\n")
}

// detailText renders everything known about one item for the detail pane, and
// returns the line its evidence heading is on, or -1 when it has no evidence.
// Evidence longer than the preview says under its heading how much is shown
// and what x shows instead, so the line x moves the pane to says what changed.
func (b browser) detailText(item Item) (string, int) {
	wrap := detailWrap(b.mainWidth())
	var out strings.Builder

	heading := string(item.Result)
	if item.isFinding() {
		heading = item.Severity
	}
	out.WriteString(itemTone(item).Style().Bold(true).Render(strings.ToUpper(heading)) +
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
	if item.isFinding() {
		section("triggered by", triggerText(item))
	}
	section("weakness", strings.TrimSpace(item.Weakness+"\n"+item.WeaknessAbout))
	section("known exploited in its class", item.ClassExploited)
	section("CVSS baseline", item.CVSS)
	section("CVSS on this host", item.HostCVSS)
	section("categories", strings.Join(item.Categories, ", "))
	section("description", item.Description)
	section("impact", item.Impact)
	section("resolution", item.Resolution)
	section("references", strings.Join(item.References, "\n"))
	section("MITRE ATT&CK, made available by this finding", strings.Join(item.Techniques, "\n"))
	section("mitigations", strings.Join(item.Mitigations, "\n"))

	if len(item.Evidence) == 0 {
		return out.String(), -1
	}
	title := fmt.Sprintf("evidence (%d)", len(item.Evidence))
	if len(b.evidence) != len(item.Evidence) {
		title = fmt.Sprintf("evidence (%d of %d match the search)", len(b.evidence), len(item.Evidence))
	}
	out.WriteString("\n")
	top := strings.Count(out.String(), "\n")
	out.WriteString(styleMuted.Render(title) + "\n")
	lines := b.evidence
	switch {
	case len(lines) <= evidencePreview:
	case b.fullEvidence:
		out.WriteString(styleNotice.Render(fmt.Sprintf("showing all %d; press x to show the first %d", len(lines), evidencePreview)) + "\n")
	default:
		out.WriteString(styleNotice.Render(fmt.Sprintf("showing the first %d; press x to show all %d", evidencePreview, len(lines))) + "\n")
		lines = lines[:evidencePreview]
	}
	out.WriteString(strings.Join(lines, "\n") + "\n")
	return out.String(), top
}
