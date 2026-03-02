package tui

import (
	"context"
	"fmt"
	"strings"

	"github.com/charmbracelet/bubbles/list"
	"github.com/charmbracelet/bubbles/viewport"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"

	"godecomp/internal/ai"
	binpkg "godecomp/internal/binary"
	"godecomp/internal/decompiler"
	"godecomp/internal/symbols"
)

// Color scheme (Matrix-inspired green on black)
var (
	colorGreen  = lipgloss.Color("#00ff41")
	colorDark   = lipgloss.Color("#003300")
	colorBlack  = lipgloss.Color("#0d0d0d")
	colorBorder = lipgloss.Color("#1a3d1a")

	styleTitle = lipgloss.NewStyle().
			Foreground(colorGreen).
			Bold(true).
			Padding(0, 1)

	styleBorder = lipgloss.NewStyle().
			BorderStyle(lipgloss.RoundedBorder()).
			BorderForeground(colorBorder)

	styleStatus = lipgloss.NewStyle().
			Foreground(colorGreen).
			Background(colorBlack).
			Padding(0, 1)

	styleSelected = lipgloss.NewStyle().
			Foreground(colorBlack).
			Background(colorGreen)

	styleDim = lipgloss.NewStyle().
			Foreground(colorDark)
)

// paneType identifies which pane is focused.
type paneType int

const (
	paneSymbols paneType = iota
	paneViewer
)

// decompileResultMsg carries the decompilation result back to the TUI.
type decompileResultMsg struct {
	result string
	err    error
}

// streamChunkMsg carries a streaming chunk.
type streamChunkMsg struct {
	chunk ai.StreamChunk
}

// Model is the root Bubble Tea model.
type Model struct {
	binary       *binpkg.Binary
	symbolList   list.Model
	viewer       viewport.Model
	statusMsg    string
	pipeline     *decompiler.Pipeline
	targetLang   string
	streaming    bool
	streamBuffer strings.Builder
	width        int
	height       int
	activePane   paneType
	streamChan   chan ai.StreamChunk
	searching    bool
}

// NewModel creates a new TUI Model.
func NewModel(b *binpkg.Binary, pipeline *decompiler.Pipeline) Model {
	// Build symbol items for the list
	funcs := symbols.FunctionList(b)
	items := make([]list.Item, len(funcs))
	for i, sym := range funcs {
		items[i] = symbolItem{sym: sym}
	}

	// Configure symbol list
	delegate := list.NewDefaultDelegate()
	delegate.Styles.SelectedTitle = styleSelected
	delegate.Styles.SelectedDesc = styleSelected.Copy().Faint(true)
	delegate.Styles.NormalTitle = lipgloss.NewStyle().Foreground(colorGreen)
	delegate.Styles.NormalDesc = lipgloss.NewStyle().Foreground(colorDark)

	l := list.New(items, delegate, 40, 20)
	l.Title = "Functions"
	l.Styles.Title = styleTitle
	l.SetShowStatusBar(true)
	l.SetFilteringEnabled(true)

	// Configure viewport
	vp := viewport.New(80, 20)
	vp.Style = lipgloss.NewStyle().Foreground(colorGreen)
	vp.SetContent(welcomeMessage(b))

	statusMsg := "Ready"
	if pipeline == nil {
		statusMsg = "Ollama not connected"
	}

	return Model{
		binary:     b,
		symbolList: l,
		viewer:     vp,
		statusMsg:  statusMsg,
		pipeline:   pipeline,
		targetLang: "go",
		activePane: paneSymbols,
	}
}

func welcomeMessage(b *binpkg.Binary) string {
	return fmt.Sprintf(`GoDecomp — AI-Powered Decompiler

Binary: %s
Format: %s
Arch:   %s (%d-bit)
OS:     %s

Functions: %d
Imports:   %d
Strings:   %d

Keybindings:
  ↑/↓ or j/k  Navigate symbols
  Enter / d    Decompile selected function
  /            Search symbols
  Tab          Switch panes
  l            Cycle target language
  q / Ctrl+C   Quit
`,
		b.Path,
		b.Format,
		b.Arch, b.Bits,
		b.OS,
		countFunctions(b),
		len(b.Imports),
		len(b.Strings),
	)
}

func countFunctions(b *binpkg.Binary) int {
	count := 0
	for _, sym := range b.Symbols {
		if sym.Type == "func" {
			count++
		}
	}
	return count
}

// Init initializes the model.
func (m Model) Init() tea.Cmd {
	return nil
}

// Update handles messages and updates state.
func (m Model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	var cmds []tea.Cmd

	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		m.width = msg.Width
		m.height = msg.Height
		m.updatePaneSizes()

	case tea.KeyMsg:
		// Handle global keys first
		switch msg.String() {
		case "ctrl+c", "q":
			if !m.symbolList.SettingFilter() {
				return m, tea.Quit
			}
		case "tab":
			if m.activePane == paneSymbols {
				m.activePane = paneViewer
			} else {
				m.activePane = paneSymbols
			}
		case "l":
			if !m.symbolList.SettingFilter() {
				m.targetLang = cycleLang(m.targetLang)
				m.statusMsg = fmt.Sprintf("Target language: %s", m.targetLang)
			}
		case "enter", "d":
			if m.activePane == paneSymbols && !m.symbolList.SettingFilter() {
				return m, m.startDecompile()
			}
		}

	case decompileResultMsg:
		m.streaming = false
		if msg.err != nil {
			m.viewer.SetContent(fmt.Sprintf("Error: %v", msg.err))
			m.statusMsg = fmt.Sprintf("Error: %v", msg.err)
		} else {
			m.viewer.SetContent(msg.result)
			m.statusMsg = "Decompilation complete"
		}

	case streamChunkMsg:
		if msg.chunk.Done {
			m.streaming = false
			content := m.streamBuffer.String()
			m.viewer.SetContent(content)
			m.streamBuffer.Reset()
			m.statusMsg = "Streaming complete"
		} else if msg.chunk.Error != nil {
			m.streaming = false
			m.viewer.SetContent(fmt.Sprintf("Stream error: %v", msg.chunk.Error))
			m.statusMsg = "Stream error"
		} else {
			m.streamBuffer.WriteString(msg.chunk.Text)
			m.viewer.SetContent(m.streamBuffer.String())
			return m, m.waitForStreamChunk()
		}
	}

	// Route input to the active pane
	var cmd tea.Cmd
	if m.activePane == paneSymbols {
		m.symbolList, cmd = m.symbolList.Update(msg)
		cmds = append(cmds, cmd)
	} else {
		m.viewer, cmd = m.viewer.Update(msg)
		cmds = append(cmds, cmd)
	}

	return m, tea.Batch(cmds...)
}

// View renders the TUI.
func (m Model) View() string {
	if m.width == 0 {
		return "Loading..."
	}

	leftWidth := m.width * 30 / 100
	rightWidth := m.width - leftWidth - 3 // 3 for borders
	contentHeight := m.height - 3         // 3 for title + status bar

	// Left pane - symbol list
	leftStyle := styleBorder.Copy().Width(leftWidth).Height(contentHeight)
	if m.activePane == paneSymbols {
		leftStyle = leftStyle.BorderForeground(colorGreen)
	}
	leftPane := leftStyle.Render(m.symbolList.View())

	// Right pane - viewer
	rightStyle := styleBorder.Copy().Width(rightWidth).Height(contentHeight)
	if m.activePane == paneViewer {
		rightStyle = rightStyle.BorderForeground(colorGreen)
	}
	rightPane := rightStyle.Render(m.viewer.View())

	// Layout
	panes := lipgloss.JoinHorizontal(lipgloss.Top, leftPane, rightPane)

	// Status bar
	arch := fmt.Sprintf("%s/%s", m.binary.OS, m.binary.Arch)
	model := "Ollama not connected"
	if m.pipeline != nil {
		model = "Ollama connected"
	}
	statusText := fmt.Sprintf(" %s | %s | Lang: %s | %s | %s ",
		truncateString(m.binary.Path, 30),
		arch,
		m.targetLang,
		model,
		m.statusMsg,
	)
	status := styleStatus.Width(m.width).Render(statusText)

	return lipgloss.JoinVertical(lipgloss.Left, panes, status)
}

// updatePaneSizes updates the sizes of the panes based on terminal dimensions.
func (m *Model) updatePaneSizes() {
	leftWidth := m.width * 30 / 100
	rightWidth := m.width - leftWidth - 6 // account for borders
	contentHeight := m.height - 5         // account for borders and status bar

	if contentHeight < 5 {
		contentHeight = 5
	}
	if rightWidth < 20 {
		rightWidth = 20
	}

	m.symbolList.SetSize(leftWidth-2, contentHeight)
	m.viewer.Width = rightWidth - 2
	m.viewer.Height = contentHeight
}

// startDecompile initiates the decompilation of the selected function.
func (m *Model) startDecompile() tea.Cmd {
	if m.pipeline == nil {
		m.statusMsg = "Ollama not connected"
		return nil
	}

	selected := m.symbolList.SelectedItem()
	if selected == nil {
		m.statusMsg = "No function selected"
		return nil
	}

	item, ok := selected.(symbolItem)
	if !ok {
		return nil
	}

	funcName := item.sym.Name
	m.statusMsg = fmt.Sprintf("Decompiling %s...", funcName)
	m.viewer.SetContent(fmt.Sprintf("Decompiling %s to %s...\n", funcName, m.targetLang))

	b := m.binary
	pipeline := m.pipeline
	lang := m.targetLang

	return func() tea.Msg {
		result, err := pipeline.DecompileFunction(
			context.Background(), b, funcName,
			decompiler.Options{TargetLang: lang},
		)
		return decompileResultMsg{result: result, err: err}
	}
}

// waitForStreamChunk returns a command that waits for the next stream chunk.
func (m *Model) waitForStreamChunk() tea.Cmd {
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

// cycleLang cycles through supported target languages.
func cycleLang(current string) string {
	langs := []string{"go", "c", "rust", "python", "typescript", "java"}
	for i, l := range langs {
		if l == current {
			return langs[(i+1)%len(langs)]
		}
	}
	return "go"
}

// Run starts the TUI application.
func Run(b *binpkg.Binary, pipeline *decompiler.Pipeline) error {
	m := NewModel(b, pipeline)
	p := tea.NewProgram(m, tea.WithAltScreen(), tea.WithMouseCellMotion())
	_, err := p.Run()
	return err
}
