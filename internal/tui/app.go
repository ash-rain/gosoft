package tui

import (
	"context"
	"fmt"
	"strings"

	"github.com/charmbracelet/bubbles/list"
	"github.com/charmbracelet/bubbles/textinput"
	"github.com/charmbracelet/bubbles/viewport"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"

	"godecomp/internal/ai"
	binpkg "godecomp/internal/binary"
	"godecomp/internal/decompiler"
	"godecomp/internal/symbols"
)

// ── Colours & Styles ──────────────────────────────────────────────────────

var (
	colorGreen  = lipgloss.Color("#00ff41")
	colorDim    = lipgloss.Color("#1a6e1a")
	colorBlack  = lipgloss.Color("#0d0d0d")
	colorBorder = lipgloss.Color("#1a3d1a")
	colorMuted  = lipgloss.Color("#2a6a2a")

	styleBorder = lipgloss.NewStyle().
			BorderStyle(lipgloss.RoundedBorder()).
			BorderForeground(colorBorder)

	styleBorderActive = lipgloss.NewStyle().
				BorderStyle(lipgloss.RoundedBorder()).
				BorderForeground(colorGreen)

	styleStatus = lipgloss.NewStyle().
			Foreground(colorGreen).
			Background(colorBlack).
			Padding(0, 1)

	styleTabActive = lipgloss.NewStyle().
			Foreground(colorBlack).
			Background(colorGreen).
			Bold(true).
			Padding(0, 1)

	styleTabInactive = lipgloss.NewStyle().
				Foreground(colorGreen).
				Padding(0, 1)

	styleSelected = lipgloss.NewStyle().
			Foreground(colorBlack).
			Background(colorGreen)

	styleHelp = lipgloss.NewStyle().
			Foreground(colorDim)

	styleChatLabel = lipgloss.NewStyle().
			Foreground(colorGreen).
			Bold(true)

	styleHelpBox = lipgloss.NewStyle().
			BorderStyle(lipgloss.RoundedBorder()).
			BorderForeground(colorGreen).
			Foreground(colorGreen).
			Padding(1, 2)
)

// ── Tabs ─────────────────────────────────────────────────────────────────

type leftTab int

const (
	leftTabFunctions leftTab = iota
	leftTabStrings
	leftTabImports
	leftTabSections
	leftTabCount
)

func (t leftTab) label() string {
	return [...]string{"[F]uncs", "[S]trings", "[I]mports", "[X]ections"}[t]
}

type rightTab int

const (
	rightTabSource rightTab = iota
	rightTabDisasm
	rightTabHex
	rightTabCount
)

func (t rightTab) label() string {
	return [...]string{"[1]Source", "[2]Disasm", "[3]Hex"}[t]
}

type focusArea int

const (
	focusLeft focusArea = iota
	focusRight
	focusChat
)

// ── Messages ─────────────────────────────────────────────────────────────

type decompileResultMsg struct {
	result   string
	funcName string
	err      error
}

type streamChunkMsg struct{ chunk ai.StreamChunk }
type chatResponseMsg struct{ chunk ai.StreamChunk }

// ── Model ─────────────────────────────────────────────────────────────────

type Model struct {
	binary   *binpkg.Binary
	pipeline *decompiler.Pipeline

	leftTab  leftTab
	rightTab rightTab
	focus    focusArea

	lists        [leftTabCount]list.Model
	viewer       viewport.Model
	rightContent [rightTabCount]string

	chatInput  textinput.Model
	chatActive bool
	chatBuffer strings.Builder
	chatChan   chan ai.StreamChunk

	streaming  bool
	streamChan chan ai.StreamChunk
	streamBuf  strings.Builder

	targetLang string
	statusMsg  string
	selectedFn string
	showHelp   bool

	width, height int
}

// ── Constructor ───────────────────────────────────────────────────────────

func NewModel(b *binpkg.Binary, pipeline *decompiler.Pipeline) Model {
	funcs := symbols.FunctionList(b)
	funcItems := make([]list.Item, len(funcs))
	for i, sym := range funcs {
		funcItems[i] = symbolItem{sym: sym}
	}

	strs := symbols.ExtractStrings(b)
	strItems := make([]list.Item, len(strs))
	for i, s := range strs {
		strItems[i] = stringItem{ref: s}
	}

	impItems := make([]list.Item, 0, len(b.Imports))
	for _, imp := range b.Imports {
		if imp.Name != "" || imp.Library != "" {
			impItems = append(impItems, importItem{imp: imp})
		}
	}

	secItems := make([]list.Item, 0, len(b.Sections))
	for _, sec := range b.Sections {
		if !strings.HasPrefix(sec.Name, "IL:") {
			secItems = append(secItems, sectionItem{sec: sec})
		}
	}

	d := newDelegate()
	allItems := [][]list.Item{funcItems, strItems, impItems, secItems}

	var lists [leftTabCount]list.Model
	for i := range lists {
		l := list.New(allItems[i], d, 40, 20)
		l.SetShowTitle(false)
		l.SetShowStatusBar(true)
		l.SetFilteringEnabled(true)
		lists[i] = l
	}

	chat := textinput.New()
	chat.Placeholder = "Ask AI about this binary..."
	chat.CharLimit = 500
	chat.PromptStyle = styleChatLabel
	chat.Prompt = "  Chat > "

	status := fmt.Sprintf("Ready · %s · %s", b.Format, b.Arch)
	if pipeline == nil {
		status += " · Ollama offline"
	}

	m := Model{
		binary:     b,
		pipeline:   pipeline,
		leftTab:    leftTabFunctions,
		rightTab:   rightTabSource,
		focus:      focusLeft,
		lists:      lists,
		viewer:     viewport.New(80, 20),
		chatInput:  chat,
		targetLang: "go",
		statusMsg:  status,
	}
	m.viewer.Style = lipgloss.NewStyle().Foreground(colorGreen)
	m.setRight(rightTabSource, welcomeContent(b))
	return m
}

func (m Model) Init() tea.Cmd { return nil }

// ── Update ────────────────────────────────────────────────────────────────

func (m Model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	var cmds []tea.Cmd

	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		m.width = msg.Width
		m.height = msg.Height
		m.recalcSizes()
		return m, nil

	case tea.KeyMsg:
		return m.handleKey(msg)

	case decompileResultMsg:
		m.streaming = false
		if msg.err != nil {
			m.setRight(rightTabSource, fmt.Sprintf("Error:\n\n%v", msg.err))
			m.statusMsg = "Error: " + msg.err.Error()
		} else {
			m.setRight(rightTabSource, msg.result)
			m.statusMsg = "Decompiled: " + msg.funcName
			m.rightTab = rightTabSource
		}
		m.viewer.SetContent(m.rightContent[m.rightTab])
		m.viewer.GotoTop()

	case streamChunkMsg:
		if msg.chunk.Done || msg.chunk.Error != nil {
			m.streaming = false
			result := m.streamBuf.String()
			m.streamBuf.Reset()
			if msg.chunk.Error != nil {
				result = fmt.Sprintf("Stream error: %v", msg.chunk.Error)
				m.statusMsg = "Stream error"
			} else {
				m.statusMsg = "Decompiled: " + m.selectedFn
			}
			m.setRight(rightTabSource, result)
			m.rightTab = rightTabSource
			m.viewer.SetContent(result)
			m.viewer.GotoTop()
		} else {
			m.streamBuf.WriteString(msg.chunk.Text)
			m.viewer.SetContent(m.streamBuf.String())
			cmds = append(cmds, m.waitStream())
		}

	case chatResponseMsg:
		if msg.chunk.Done || msg.chunk.Error != nil {
			m.chatBuffer.WriteString("\n")
			content := m.chatBuffer.String()
			m.setRight(rightTabSource, content)
			m.viewer.SetContent(content)
			m.viewer.GotoTop()
			m.statusMsg = "Chat complete"
		} else {
			m.chatBuffer.WriteString(msg.chunk.Text)
			m.viewer.SetContent(m.chatBuffer.String())
			cmds = append(cmds, m.waitChat())
		}
	}

	switch m.focus {
	case focusLeft:
		var cmd tea.Cmd
		m.lists[m.leftTab], cmd = m.lists[m.leftTab].Update(msg)
		cmds = append(cmds, cmd)
	case focusRight:
		var cmd tea.Cmd
		m.viewer, cmd = m.viewer.Update(msg)
		cmds = append(cmds, cmd)
	case focusChat:
		var cmd tea.Cmd
		m.chatInput, cmd = m.chatInput.Update(msg)
		cmds = append(cmds, cmd)
	}

	return m, tea.Batch(cmds...)
}

func (m Model) handleKey(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	key := msg.String()

	if m.focus == focusChat {
		switch key {
		case "enter":
			if q := strings.TrimSpace(m.chatInput.Value()); q != "" {
				m.chatInput.SetValue("")
				return m, m.sendChatMessage(q)
			}
		case "esc":
			m.chatActive = false
			m.focus = focusLeft
			m.chatInput.Blur()
		}
		var cmd tea.Cmd
		m.chatInput, cmd = m.chatInput.Update(msg)
		return m, cmd
	}

	if m.showHelp {
		m.showHelp = false
		return m, nil
	}

	if key == "ctrl+c" {
		return m, tea.Quit
	}
	if key == "esc" && m.chatActive {
		m.chatActive = false
		m.focus = focusLeft
		m.chatInput.Blur()
		return m, nil
	}

	// While list is filtering, pass through
	if m.focus == focusLeft && m.lists[m.leftTab].SettingFilter() {
		var cmd tea.Cmd
		m.lists[m.leftTab], cmd = m.lists[m.leftTab].Update(msg)
		return m, cmd
	}

	switch key {
	case "q":
		return m, tea.Quit
	case "?":
		m.showHelp = true
	case "c":
		m.chatActive = true
		m.focus = focusChat
		m.chatInput.Focus()
		return m, textinput.Blink
	case "tab":
		if m.focus == focusLeft {
			m.focus = focusRight
		} else {
			m.focus = focusLeft
		}
	case "f", "F":
		m.leftTab = leftTabFunctions
		m.focus = focusLeft
	case "s", "S":
		m.leftTab = leftTabStrings
		m.focus = focusLeft
	case "i", "I":
		m.leftTab = leftTabImports
		m.focus = focusLeft
	case "x", "X":
		m.leftTab = leftTabSections
		m.focus = focusLeft
	case "1":
		m.rightTab = rightTabSource
		m.viewer.SetContent(m.rightContent[m.rightTab])
	case "2":
		m.rightTab = rightTabDisasm
		m.viewer.SetContent(m.rightContent[m.rightTab])
	case "3":
		m.rightTab = rightTabHex
		if m.rightContent[rightTabHex] == "" {
			m.loadSectionHex()
		}
		m.viewer.SetContent(m.rightContent[m.rightTab])
	case "l":
		m.targetLang = cycleLang(m.targetLang)
		m.statusMsg = "Language: " + decompiler.LangDisplayName(m.targetLang)
	case "d", "enter":
		if m.focus == focusLeft {
			switch m.leftTab {
			case leftTabFunctions:
				return m, m.startDecompile()
			case leftTabSections:
				m.loadSectionHex()
			}
		}
	default:
		switch m.focus {
		case focusLeft:
			var cmd tea.Cmd
			m.lists[m.leftTab], cmd = m.lists[m.leftTab].Update(msg)
			return m, cmd
		case focusRight:
			var cmd tea.Cmd
			m.viewer, cmd = m.viewer.Update(msg)
			return m, cmd
		}
	}

	return m, nil
}

// ── View ─────────────────────────────────────────────────────────────────

func (m Model) View() string {
	if m.width == 0 {
		return "Loading..."
	}
	if m.showHelp {
		return m.viewHelp()
	}

	lw, rw, ch := m.dims()
	panels := lipgloss.JoinHorizontal(lipgloss.Top,
		m.viewLeft(lw, ch),
		m.viewRight(rw, ch),
	)

	hint := styleHelp.Width(m.width).Render(
		" [tab] focus  [f/s/i/x] panel  [1/2/3] view  [d] decompile  [l] lang  [c] chat  [?] help  [q] quit",
	)

	rows := []string{panels, hint}
	if m.chatActive {
		rows = append(rows, styleChatLabel.Render("Chat")+" "+m.chatInput.View())
	}
	rows = append(rows, m.viewStatus())
	return lipgloss.JoinVertical(lipgloss.Left, rows...)
}

func (m Model) viewLeft(w, h int) string {
	tabs := m.tabBar(true)
	th := lipgloss.Height(tabs)
	lh := h - th - 2
	if lh < 3 {
		lh = 3
	}
	m.lists[m.leftTab].SetSize(w-2, lh)

	border := styleBorder
	if m.focus == focusLeft {
		border = styleBorderActive
	}
	return border.Width(w).Height(h).Render(
		lipgloss.JoinVertical(lipgloss.Left, tabs, m.lists[m.leftTab].View()),
	)
}

func (m Model) viewRight(w, h int) string {
	tabs := m.tabBar(false)
	th := lipgloss.Height(tabs)
	vh := h - th - 2
	if vh < 3 {
		vh = 3
	}
	m.viewer.Width = w - 2
	m.viewer.Height = vh

	border := styleBorder
	if m.focus == focusRight {
		border = styleBorderActive
	}
	return border.Width(w).Height(h).Render(
		lipgloss.JoinVertical(lipgloss.Left, tabs, m.viewer.View()),
	)
}

func (m Model) tabBar(isLeft bool) string {
	var parts []string
	if isLeft {
		for i := leftTab(0); i < leftTabCount; i++ {
			if i == m.leftTab {
				parts = append(parts, styleTabActive.Render(i.label()))
			} else {
				parts = append(parts, styleTabInactive.Render(i.label()))
			}
		}
	} else {
		for i := rightTab(0); i < rightTabCount; i++ {
			if i == m.rightTab {
				parts = append(parts, styleTabActive.Render(i.label()))
			} else {
				parts = append(parts, styleTabInactive.Render(i.label()))
			}
		}
	}
	return lipgloss.NewStyle().Foreground(colorBorder).Render(strings.Join(parts, " "))
}

func (m Model) viewStatus() string {
	aiDot := "○"
	if m.pipeline != nil {
		aiDot = "●"
	}
	streaming := ""
	if m.streaming {
		streaming = " ⟳"
	}
	_ = aiDot
	text := fmt.Sprintf(" %s  %s/%s  %s  lang:%-7s  %s%s ",
		truncateString(m.binary.Path, 26),
		m.binary.OS, m.binary.Arch,
		m.binary.Format,
		m.targetLang,
		m.statusMsg,
		streaming,
	)
	return styleStatus.Width(m.width).Render(text)
}

func (m Model) viewHelp() string {
	help := `  GoDecomp — Keyboard Reference

  Navigation
    tab          Switch focus between left and right panel
    j / k        Move up / down in list
    /            Filter list  (esc to clear)
    esc          Close chat / close help

  Left Panel  (tabs)
    f            Functions
    s            Strings
    i            Imports
    x            Sections

  Right Panel  (tabs)
    1            Source   — AI-decompiled output
    2            Disasm   — disassembly listing
    3            Hex      — hex dump of selected section

  Actions
    d / enter    Decompile selected function  (or hex-view selected section)
    l            Cycle target language: go → c → rust → python → ts → java → csharp
    c            Chat — ask AI a question about this binary
    ?            Toggle this help
    q / ctrl+c   Quit`

	box := styleHelpBox.Width(m.width - 4).Render(help)
	pad := (m.height - lipgloss.Height(box)) / 2
	if pad < 0 {
		pad = 0
	}
	return strings.Repeat("\n", pad) + box
}

// ── Actions ───────────────────────────────────────────────────────────────

func (m *Model) startDecompile() tea.Cmd {
	if m.pipeline == nil {
		m.statusMsg = "Ollama not connected"
		return nil
	}
	sel := m.lists[leftTabFunctions].SelectedItem()
	if sel == nil {
		return nil
	}
	item, ok := sel.(symbolItem)
	if !ok {
		return nil
	}
	fn := item.sym.Name
	m.selectedFn = fn
	m.streaming = true
	m.streamBuf.Reset()
	m.statusMsg = fmt.Sprintf("Decompiling %s…", fn)
	m.rightTab = rightTabSource
	m.viewer.SetContent(fmt.Sprintf("Decompiling %s → %s…\n", fn, m.targetLang))

	b := m.binary
	pipe := m.pipeline
	lang := m.targetLang
	ch := make(chan ai.StreamChunk, 128)
	m.streamChan = ch

	return func() tea.Msg {
		err := pipe.DecompileFunctionStream(context.Background(), b, fn,
			decompiler.Options{TargetLang: lang, Stream: true}, ch)
		if err != nil {
			return streamChunkMsg{chunk: ai.StreamChunk{Error: err, Done: true}}
		}
		return m.waitStream()()
	}
}

func (m *Model) waitStream() tea.Cmd {
	ch := m.streamChan
	if ch == nil {
		return nil
	}
	return func() tea.Msg {
		chunk, ok := <-ch
		if !ok {
			return streamChunkMsg{chunk: ai.StreamChunk{Done: true}}
		}
		return streamChunkMsg{chunk: chunk}
	}
}

func (m *Model) loadSectionHex() {
	sel := m.lists[leftTabSections].SelectedItem()
	if sel == nil {
		return
	}
	item, ok := sel.(sectionItem)
	if !ok {
		return
	}
	hex := formatHex(item.sec.Data, item.sec.Offset, 16)
	m.setRight(rightTabHex, hex)
	m.rightTab = rightTabHex
	m.viewer.SetContent(hex)
	m.viewer.GotoTop()
	m.statusMsg = fmt.Sprintf("Hex: %s (%d B)", item.sec.Name, item.sec.Size)
}

func (m *Model) sendChatMessage(question string) tea.Cmd {
	if m.pipeline == nil {
		m.statusMsg = "Ollama not connected"
		return nil
	}
	b := m.binary
	funcs := symbols.FunctionList(b)
	ctx := fmt.Sprintf("Binary: %s (%s/%s, %s)\nFunctions: %d  Imports: %d  Strings: %d",
		b.Path, b.Arch, b.OS, b.Format, len(funcs), len(b.Imports), len(b.Strings))
	prompt := ctx + "\n\nQuestion: " + question
	sys := "You are a binary analysis expert. Answer questions about binary files concisely."

	m.chatBuffer.Reset()
	m.chatBuffer.WriteString("You: " + question + "\n\nAI: ")
	m.rightTab = rightTabSource
	m.viewer.SetContent(m.chatBuffer.String())
	m.statusMsg = "Sending chat…"

	ch := make(chan ai.StreamChunk, 128)
	m.chatChan = ch
	pipe := m.pipeline

	return func() tea.Msg {
		if err := pipe.AskStream(context.Background(), sys, prompt, ch); err != nil {
			return chatResponseMsg{chunk: ai.StreamChunk{Error: err, Done: true}}
		}
		return m.waitChat()()
	}
}

func (m *Model) waitChat() tea.Cmd {
	ch := m.chatChan
	if ch == nil {
		return nil
	}
	return func() tea.Msg {
		chunk, ok := <-ch
		if !ok {
			return chatResponseMsg{chunk: ai.StreamChunk{Done: true}}
		}
		return chatResponseMsg{chunk: chunk}
	}
}

// ── Helpers ───────────────────────────────────────────────────────────────

func (m *Model) setRight(tab rightTab, content string) {
	m.rightContent[tab] = content
	if tab == m.rightTab {
		m.viewer.SetContent(content)
	}
}

func (m *Model) recalcSizes() {
	lw, rw, ch := m.dims()
	for i := range m.lists {
		m.lists[i].SetSize(lw-4, ch-4)
	}
	m.viewer.Width = rw - 4
	m.viewer.Height = ch - 4
}

func (m Model) dims() (lw, rw, ch int) {
	reserved := 3
	if m.chatActive {
		reserved += 2
	}
	ch = m.height - reserved
	if ch < 6 {
		ch = 6
	}
	lw = m.width * 28 / 100
	if lw < 22 {
		lw = 22
	}
	rw = m.width - lw - 1
	if rw < 30 {
		rw = 30
	}
	return
}

func cycleLang(current string) string {
	langs := decompiler.SupportedLanguages()
	for i, l := range langs {
		if l == current {
			return langs[(i+1)%len(langs)]
		}
	}
	return "go"
}

func welcomeContent(b *binpkg.Binary) string {
	funcs := symbols.FunctionList(b)
	return fmt.Sprintf(`  GoDecomp — AI-Powered Binary Decompiler

  Binary   %s
  Format   %-12s  Arch  %s (%d-bit)
  OS       %s

  Functions  %-6d  Imports  %-6d  Strings  %d

  Select a function and press [d] or [Enter] to decompile.
  Press [c] to chat with AI about this binary.
  Press [?] for full keyboard shortcuts.
`,
		b.Path,
		b.Format, b.Arch, b.Bits, b.OS,
		len(funcs), len(b.Imports), len(b.Strings),
	)
}

func newDelegate() list.DefaultDelegate {
	d := list.NewDefaultDelegate()
	d.Styles.SelectedTitle = styleSelected
	d.Styles.SelectedDesc = styleSelected.Faint(true)
	d.Styles.NormalTitle = lipgloss.NewStyle().Foreground(colorGreen)
	d.Styles.NormalDesc = lipgloss.NewStyle().Foreground(colorMuted)
	return d
}

// Run starts the TUI application.
func Run(b *binpkg.Binary, pipeline *decompiler.Pipeline) error {
	m := NewModel(b, pipeline)
	p := tea.NewProgram(m, tea.WithAltScreen(), tea.WithMouseCellMotion())
	_, err := p.Run()
	return err
}
