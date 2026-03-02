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
	ctxpkg "godecomp/internal/context"
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
type modelsLoadedMsg struct {
	models []string
	err    error
}

// ── TUI Config ───────────────────────────────────────────────────────────

// TUIConfig holds the AI provider configuration for the TUI,
// allowing it to rebuild the pipeline when the model changes.
type TUIConfig struct {
	OllamaURL      string
	OllamaModel    string
	OpenCodeURL    string
	OpenCodeAPIKey string
	OpenCodeModel  string
}

// ── Model ─────────────────────────────────────────────────────────────────

type Model struct {
	binary   *binpkg.Binary
	pipeline *decompiler.Pipeline
	tuiCfg   TUIConfig

	leftTab  leftTab
	rightTab rightTab
	focus    focusArea

	funcTree     TreeModel
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
	cancelFunc context.CancelFunc

	// Model picker
	modelPicker     list.Model
	modelPickerOn   bool
	availableModels []string

	targetLang string
	statusMsg  string
	selectedFn string
	showHelp   bool

	width, height int
}

// ── Constructor ───────────────────────────────────────────────────────────

func NewModel(b *binpkg.Binary, pipeline *decompiler.Pipeline, cfg TUIConfig) Model {
	funcs := symbols.FunctionList(b)
	funcTree := NewTreeModel(funcs)

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
	// Functions tab uses the tree; other tabs use flat lists.
	allItems := [][]list.Item{nil, strItems, impItems, secItems}

	var lists [leftTabCount]list.Model
	for i := range lists {
		items := allItems[i]
		if items == nil {
			items = []list.Item{}
		}
		l := list.New(items, d, 40, 20)
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
		tuiCfg:     cfg,
		leftTab:    leftTabFunctions,
		rightTab:   rightTabSource,
		focus:      focusLeft,
		funcTree:   funcTree,
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

	case modelsLoadedMsg:
		if msg.err != nil {
			m.statusMsg = "Error loading models: " + msg.err.Error()
			m.modelPickerOn = false
		} else {
			m.availableModels = msg.models
			items := make([]list.Item, len(msg.models))
			for i, name := range msg.models {
				items[i] = modelItem{name: name, current: name == m.tuiCfg.OllamaModel}
			}
			d := newDelegate()
			m.modelPicker = list.New(items, d, 50, 15)
			m.modelPicker.Title = "Select Model"
			m.modelPicker.SetShowTitle(true)
			m.modelPicker.SetFilteringEnabled(true)
			m.modelPicker.SetShowStatusBar(true)
			m.modelPicker.Styles.Title = styleTabActive
			if m.width > 0 {
				pw := m.width * 40 / 100
				if pw < 40 {
					pw = 40
				}
				ph := m.height - 10
				if ph < 10 {
					ph = 10
				}
				m.modelPicker.SetSize(pw, ph)
			}
			m.modelPickerOn = true
			m.statusMsg = fmt.Sprintf("Models: %d available", len(msg.models))
		}
	}

	switch m.focus {
	case focusLeft:
		if m.leftTab != leftTabFunctions {
			var cmd tea.Cmd
			m.lists[m.leftTab], cmd = m.lists[m.leftTab].Update(msg)
			cmds = append(cmds, cmd)
		}
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

	// Model picker overlay
	if m.modelPickerOn {
		switch key {
		case "enter":
			sel := m.modelPicker.SelectedItem()
			if sel != nil {
				if item, ok := sel.(modelItem); ok {
					m.modelPickerOn = false
					return m, m.switchModel(item.name)
				}
			}
		case "esc", "q":
			m.modelPickerOn = false
			return m, nil
		default:
			var cmd tea.Cmd
			m.modelPicker, cmd = m.modelPicker.Update(msg)
			return m, cmd
		}
		return m, nil
	}

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
	if key == "esc" && m.streaming {
		m.cancelStream()
		return m, nil
	}
	if key == "esc" && m.chatActive {
		m.chatActive = false
		m.focus = focusLeft
		m.chatInput.Blur()
		return m, nil
	}

	// Tree filter mode: capture all input for the filter string.
	if m.focus == focusLeft && m.leftTab == leftTabFunctions && m.funcTree.filtering {
		switch key {
		case "esc":
			m.funcTree.filtering = false
			m.funcTree.SetFilter("")
		case "enter":
			m.funcTree.filtering = false
		case "backspace":
			f := m.funcTree.filter
			if len(f) > 0 {
				m.funcTree.SetFilter(f[:len(f)-1])
			}
		default:
			if len(key) == 1 && key >= " " {
				m.funcTree.SetFilter(m.funcTree.filter + key)
			}
		}
		return m, nil
	}

	// While list is filtering, pass through.
	if m.focus == focusLeft && m.leftTab != leftTabFunctions && m.lists[m.leftTab].SettingFilter() {
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
	case "m":
		m.statusMsg = "Loading models…"
		return m, m.loadModels()
	case " ":
		if m.focus == focusLeft && m.leftTab == leftTabFunctions {
			m.funcTree.Toggle()
			return m, nil
		}
	case "/":
		if m.focus == focusLeft {
			if m.leftTab == leftTabFunctions {
				m.funcTree.filtering = true
				m.funcTree.filter = ""
				return m, nil
			}
			// Other tabs: pass to list for its built-in filter.
			var cmd tea.Cmd
			m.lists[m.leftTab], cmd = m.lists[m.leftTab].Update(msg)
			return m, cmd
		}
	case "d", "enter":
		if m.focus == focusLeft {
			switch m.leftTab {
			case leftTabFunctions:
				if m.funcTree.SelectedSymbol() == nil {
					// Group node: toggle expand/collapse.
					m.funcTree.Toggle()
					return m, nil
				}
				return m, m.startDecompile()
			case leftTabSections:
				m.loadSectionHex()
			}
		}
	default:
		switch m.focus {
		case focusLeft:
			if m.leftTab == leftTabFunctions {
				switch key {
				case "j", "down":
					m.funcTree.Down()
				case "k", "up":
					m.funcTree.Up()
				case "pgup":
					m.funcTree.PageUp()
				case "pgdown":
					m.funcTree.PageDown()
				}
				return m, nil
			}
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
	if m.modelPickerOn {
		return m.viewModelPicker()
	}

	lw, rw, ch := m.dims()
	panels := lipgloss.JoinHorizontal(lipgloss.Top,
		m.viewLeft(lw, ch),
		m.viewRight(rw, ch),
	)

	hint := styleHelp.Width(m.width).Render(
		" [tab] focus  [f/s/i/x] panel  [1/2/3] view  [d] decompile  [l] lang  [m] model  [c] chat  [?] help  [q] quit",
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

	var content string
	if m.leftTab == leftTabFunctions {
		m.funcTree.SetSize(w-2, lh)
		content = m.funcTree.View()
	} else {
		m.lists[m.leftTab].SetSize(w-2, lh)
		content = m.lists[m.leftTab].View()
	}

	border := styleBorder
	if m.focus == focusLeft {
		border = styleBorderActive
	}
	return border.Width(w).Height(h).Render(
		lipgloss.JoinVertical(lipgloss.Left, tabs, content),
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
	text := fmt.Sprintf(" %s  %s/%s  %s  model:%-18s  lang:%-7s  %s%s ",
		truncateString(m.binary.Path, 26),
		m.binary.OS, m.binary.Arch,
		m.binary.Format,
		truncateString(m.tuiCfg.OllamaModel, 18),
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
    j / k        Move up / down in list or tree
    /            Filter by name  (esc to clear)
    esc          Cancel decompilation / close chat / close help

  Functions Tree
    +/-          Expand / collapse module groups
    space        Toggle expand / collapse
    enter / d    Decompile selected function
    /            Filter functions by name

  Left Panel  (tabs)
    f            Functions  (tree view)
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
    m            Select AI model from downloaded Ollama models
    c            Chat — ask AI a question about this binary
    esc          Cancel running decompilation or chat
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
	sym := m.funcTree.SelectedSymbol()
	if sym == nil {
		return nil
	}
	fn := sym.Name
	m.selectedFn = fn

	// Build the function context to populate the disasm and hex tabs.
	m.populateDisasm(fn)

	if m.pipeline == nil {
		m.statusMsg = "Ollama not connected — disassembly only"
		m.rightTab = rightTabDisasm
		m.viewer.SetContent(m.rightContent[rightTabDisasm])
		m.viewer.GotoTop()
		return nil
	}

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

	ctx, cancel := context.WithCancel(context.Background())
	m.cancelFunc = cancel

	return func() tea.Msg {
		err := pipe.DecompileFunctionStream(ctx, b, fn,
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

// populateDisasm builds the function context and fills the Disasm and Hex
// tabs for the given function, independently of AI decompilation.
func (m *Model) populateDisasm(funcName string) {
	funcCtx, err := decompiler.BuildFunctionContext(m.binary, funcName)
	if err != nil {
		m.setRight(rightTabDisasm, fmt.Sprintf("(disassembly error: %v)", err))
		return
	}
	m.setRight(rightTabDisasm, formatDisassembly(funcCtx.Disassembly))
	m.populateHexFromContext(funcCtx)
}

// populateHexFromContext fills the Hex tab with the raw bytes of the function.
func (m *Model) populateHexFromContext(funcCtx *ctxpkg.FunctionContext) {
	if len(funcCtx.Disassembly) == 0 {
		return
	}
	// Reconstruct raw bytes from instructions for a hex dump.
	baseAddr := funcCtx.Disassembly[0].Address
	var raw []byte
	for _, inst := range funcCtx.Disassembly {
		raw = append(raw, inst.Bytes...)
	}
	if len(raw) > 0 {
		m.setRight(rightTabHex, formatHex(raw, baseAddr, 16))
	}
}

func (m *Model) sendChatMessage(question string) tea.Cmd {
	if m.pipeline == nil {
		m.statusMsg = "Ollama not connected"
		return nil
	}
	b := m.binary
	funcs := symbols.FunctionList(b)
	binaryCtx := fmt.Sprintf("Binary: %s (%s/%s, %s)\nFunctions: %d  Imports: %d  Strings: %d",
		b.Path, b.Arch, b.OS, b.Format, len(funcs), len(b.Imports), len(b.Strings))
	prompt := binaryCtx + "\n\nQuestion: " + question
	sys := "You are a binary analysis expert. Answer questions about binary files concisely."

	m.chatBuffer.Reset()
	m.chatBuffer.WriteString("You: " + question + "\n\nAI: ")
	m.rightTab = rightTabSource
	m.viewer.SetContent(m.chatBuffer.String())
	m.statusMsg = "Sending chat…"

	ch := make(chan ai.StreamChunk, 128)
	m.chatChan = ch
	pipe := m.pipeline

	ctx, cancel := context.WithCancel(context.Background())
	m.cancelFunc = cancel

	return func() tea.Msg {
		if err := pipe.AskStream(ctx, sys, prompt, ch); err != nil {
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

func (m *Model) cancelStream() {
	if m.cancelFunc != nil {
		m.cancelFunc()
		m.cancelFunc = nil
	}
	m.streaming = false
	partial := m.streamBuf.String()
	m.streamBuf.Reset()
	if partial != "" {
		partial += "\n\n— cancelled —"
		m.setRight(rightTabSource, partial)
		m.viewer.SetContent(partial)
	} else {
		m.setRight(rightTabSource, "(cancelled)")
		m.viewer.SetContent("(cancelled)")
	}
	m.statusMsg = "Cancelled"
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
	m.funcTree.SetSize(lw-4, ch-4)
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

// ── Model Picker ──────────────────────────────────────────────────────────

// modelItem wraps an Ollama model name for the list widget.
type modelItem struct {
	name    string
	current bool
}

func (i modelItem) Title() string {
	if i.current {
		return "● " + i.name
	}
	return "  " + i.name
}
func (i modelItem) Description() string {
	if i.current {
		return "currently active"
	}
	return ""
}
func (i modelItem) FilterValue() string { return i.name }

func (m Model) viewModelPicker() string {
	title := styleHelpBox.Width(m.width - 4).Render(m.modelPicker.View())
	pad := (m.height - lipgloss.Height(title)) / 2
	if pad < 0 {
		pad = 0
	}
	return strings.Repeat("\n", pad) + title
}

func (m *Model) loadModels() tea.Cmd {
	url := m.tuiCfg.OllamaURL
	if url == "" {
		url = "http://localhost:11434"
	}
	return func() tea.Msg {
		ollama := ai.NewOllama(url, "")
		models, err := ollama.ListModels(context.Background())
		return modelsLoadedMsg{models: models, err: err}
	}
}

func (m *Model) switchModel(modelName string) tea.Cmd {
	m.tuiCfg.OllamaModel = modelName

	// Rebuild the AI pipeline with the new model.
	var providers []ai.Provider
	providers = append(providers, ai.NewOllama(m.tuiCfg.OllamaURL, modelName))
	if m.tuiCfg.OpenCodeURL != "" && m.tuiCfg.OpenCodeAPIKey != "" {
		providers = append(providers, ai.NewOpenCode(
			m.tuiCfg.OpenCodeURL,
			m.tuiCfg.OpenCodeAPIKey,
			m.tuiCfg.OpenCodeModel,
		))
	}
	router := ai.NewRouter(providers...)
	m.pipeline = decompiler.New(router)

	m.statusMsg = fmt.Sprintf("Switched to model: %s", modelName)
	return nil
}

// Run starts the TUI application.
func Run(b *binpkg.Binary, pipeline *decompiler.Pipeline, cfg TUIConfig) error {
	m := NewModel(b, pipeline, cfg)
	p := tea.NewProgram(m, tea.WithAltScreen(), tea.WithMouseCellMotion())
	_, err := p.Run()
	return err
}
