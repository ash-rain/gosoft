package tui

import (
	"fmt"
	"sort"
	"strings"

	binpkg "godecomp/internal/binary"
	"github.com/charmbracelet/lipgloss"
)

// ── Tree Node ─────────────────────────────────────────────────────────────

// treeNode represents a node in the symbol tree.
type treeNode struct {
	label    string
	children []*treeNode
	expanded bool
	sym      *binpkg.Symbol // non-nil for leaf (function) nodes
	count    int            // total leaf descendants
}

func (n *treeNode) isLeaf() bool { return n.sym != nil }

// flatRow is one visible row in the flattened tree.
type flatRow struct {
	node  *treeNode
	depth int
}

// ── Tree Model ────────────────────────────────────────────────────────────

// TreeModel is a collapsible tree view for the functions panel.
type TreeModel struct {
	roots     []*treeNode
	flat      []flatRow
	cursor    int
	offset    int
	width     int
	height    int
	filter    string
	filtering bool // true while the user is typing a filter
}

// NewTreeModel builds a tree from a list of function symbols, grouping by
// module path. Single-child chains are collapsed (e.g. crypto → tls becomes
// crypto/tls).
func NewTreeModel(syms []binpkg.Symbol) TreeModel {
	root := &treeNode{label: "", expanded: true}
	for i := range syms {
		parts := splitSymbolPath(syms[i].Name)
		insertPath(root, parts, &syms[i])
	}

	sortTree(root)
	collapseChains(root.children)
	countLeaves(root)

	tm := TreeModel{roots: root.children}
	// Expand top-level groups by default.
	for _, r := range tm.roots {
		if !r.isLeaf() {
			r.expanded = true
		}
	}
	tm.rebuild()
	return tm
}

// ── Path Splitting ────────────────────────────────────────────────────────

// splitSymbolPath splits a symbol name into tree path components.
// The last element is the leaf (function name), preceding ones are groups.
func splitSymbolPath(name string) []string {
	// C++ / .NET style separator.
	if strings.Contains(name, "::") {
		parts := strings.Split(name, "::")
		if len(parts) > 0 && strings.Contains(parts[0], ".") {
			nsParts := strings.Split(parts[0], ".")
			return append(nsParts, parts[1:]...)
		}
		return parts
	}

	// Go with import path: crypto/tls.(*Conn).Read
	if idx := strings.LastIndex(name, "/"); idx >= 0 {
		pathPart := name[:idx]
		rest := name[idx+1:]
		parts := strings.Split(pathPart, "/")
		if dotIdx := strings.Index(rest, "."); dotIdx > 0 {
			parts = append(parts, rest[:dotIdx])
			parts = append(parts, rest[dotIdx+1:])
		} else {
			parts = append(parts, rest)
		}
		return parts
	}

	// Go short-form: pkg.Func
	if dotIdx := strings.Index(name, "."); dotIdx > 0 {
		return []string{name[:dotIdx], name[dotIdx+1:]}
	}

	// Plain C symbol — root-level leaf.
	return []string{name}
}

// ── Tree Construction ─────────────────────────────────────────────────────

func insertPath(parent *treeNode, parts []string, sym *binpkg.Symbol) {
	if len(parts) == 0 {
		return
	}
	if len(parts) == 1 {
		parent.children = append(parent.children, &treeNode{
			label: parts[0],
			sym:   sym,
		})
		return
	}
	// Find or create group node.
	groupLabel := parts[0]
	var group *treeNode
	for _, ch := range parent.children {
		if !ch.isLeaf() && ch.label == groupLabel {
			group = ch
			break
		}
	}
	if group == nil {
		group = &treeNode{label: groupLabel}
		parent.children = append(parent.children, group)
	}
	insertPath(group, parts[1:], sym)
}

func sortTree(n *treeNode) {
	sort.Slice(n.children, func(i, j int) bool {
		a, b := n.children[i], n.children[j]
		if a.isLeaf() != b.isLeaf() {
			return !a.isLeaf() // groups before leaves
		}
		return a.label < b.label
	})
	for _, ch := range n.children {
		if !ch.isLeaf() {
			sortTree(ch)
		}
	}
}

// collapseChains merges single-child group chains:
// "crypto" → "tls" becomes "crypto/tls".
func collapseChains(nodes []*treeNode) {
	for _, n := range nodes {
		if n.isLeaf() {
			continue
		}
		for len(n.children) == 1 && !n.children[0].isLeaf() {
			child := n.children[0]
			n.label += "/" + child.label
			n.children = child.children
		}
		collapseChains(n.children)
	}
}

func countLeaves(n *treeNode) int {
	if n.isLeaf() {
		n.count = 1
		return 1
	}
	total := 0
	for _, ch := range n.children {
		total += countLeaves(ch)
	}
	n.count = total
	return total
}

// ── Flatten / Rebuild ─────────────────────────────────────────────────────

// rebuild flattens the tree based on expand/collapse and filter state.
func (tm *TreeModel) rebuild() {
	tm.flat = tm.flat[:0]
	filter := strings.ToLower(tm.filter)
	for _, r := range tm.roots {
		tm.flattenNode(r, 0, filter)
	}
	if tm.cursor >= len(tm.flat) {
		tm.cursor = len(tm.flat) - 1
	}
	if tm.cursor < 0 {
		tm.cursor = 0
	}
	tm.clampOffset()
}

func (tm *TreeModel) flattenNode(n *treeNode, depth int, filter string) {
	if filter != "" && !nodeMatches(n, filter) {
		return
	}
	tm.flat = append(tm.flat, flatRow{node: n, depth: depth})
	// When a filter is active, force groups open so matches are visible.
	if !n.isLeaf() && (n.expanded || filter != "") {
		for _, ch := range n.children {
			tm.flattenNode(ch, depth+1, filter)
		}
	}
}

func nodeMatches(n *treeNode, filter string) bool {
	if strings.Contains(strings.ToLower(n.label), filter) {
		return true
	}
	for _, ch := range n.children {
		if nodeMatches(ch, filter) {
			return true
		}
	}
	return false
}

func (tm *TreeModel) clampOffset() {
	if len(tm.flat) == 0 {
		tm.offset = 0
		return
	}
	vh := tm.viewHeight()
	if tm.offset > tm.cursor {
		tm.offset = tm.cursor
	}
	if tm.cursor >= tm.offset+vh {
		tm.offset = tm.cursor - vh + 1
	}
	if tm.offset < 0 {
		tm.offset = 0
	}
}

func (tm *TreeModel) viewHeight() int {
	h := tm.height - 1 // status line
	if tm.filtering || tm.filter != "" {
		h-- // filter prompt line
	}
	if h < 1 {
		h = 1
	}
	return h
}

// ── Navigation ────────────────────────────────────────────────────────────

// Up moves the cursor one row up.
func (tm *TreeModel) Up() {
	if tm.cursor > 0 {
		tm.cursor--
		tm.clampOffset()
	}
}

// Down moves the cursor one row down.
func (tm *TreeModel) Down() {
	if tm.cursor < len(tm.flat)-1 {
		tm.cursor++
		tm.clampOffset()
	}
}

// PageUp moves the cursor one page up.
func (tm *TreeModel) PageUp() {
	tm.cursor -= tm.viewHeight()
	if tm.cursor < 0 {
		tm.cursor = 0
	}
	tm.clampOffset()
}

// PageDown moves the cursor one page down.
func (tm *TreeModel) PageDown() {
	tm.cursor += tm.viewHeight()
	if tm.cursor >= len(tm.flat) {
		tm.cursor = len(tm.flat) - 1
	}
	if tm.cursor < 0 {
		tm.cursor = 0
	}
	tm.clampOffset()
}

// Toggle expands or collapses the group node at cursor.
func (tm *TreeModel) Toggle() {
	if len(tm.flat) == 0 {
		return
	}
	n := tm.flat[tm.cursor].node
	if !n.isLeaf() {
		n.expanded = !n.expanded
		tm.rebuild()
	}
}

// SelectedSymbol returns the function symbol at cursor, or nil for groups.
func (tm *TreeModel) SelectedSymbol() *binpkg.Symbol {
	if len(tm.flat) == 0 {
		return nil
	}
	return tm.flat[tm.cursor].node.sym
}

// SetSize sets the available rendering area.
func (tm *TreeModel) SetSize(w, h int) {
	tm.width = w
	tm.height = h
	tm.clampOffset()
}

// SetFilter applies a filter string and rebuilds the visible rows.
func (tm *TreeModel) SetFilter(f string) {
	tm.filter = f
	tm.rebuild()
}

// ── Rendering ─────────────────────────────────────────────────────────────

// View renders the tree, filter prompt, and status line.
func (tm *TreeModel) View() string {
	var sb strings.Builder
	vh := tm.viewHeight()

	if len(tm.flat) == 0 {
		empty := "  (no functions)"
		if tm.filter != "" {
			empty = "  (no matches)"
		}
		sb.WriteString(empty)
		for i := 1; i < vh; i++ {
			sb.WriteString("\n")
		}
	} else {
		end := tm.offset + vh
		if end > len(tm.flat) {
			end = len(tm.flat)
		}

		styleNorm := lipgloss.NewStyle().Foreground(colorGreen)
		styleGrp := lipgloss.NewStyle().Foreground(colorMuted)
		styleSel := styleSelected

		rendered := 0
		for i := tm.offset; i < end; i++ {
			if rendered > 0 {
				sb.WriteString("\n")
			}
			row := tm.flat[i]
			n := row.node
			indent := strings.Repeat("  ", row.depth)

			var icon string
			var label string
			var style lipgloss.Style

			if n.isLeaf() {
				icon = "  "
				label = n.label
				style = styleNorm
			} else {
				if n.expanded {
					icon = "- "
				} else {
					icon = "+ "
				}
				label = fmt.Sprintf("%s (%d)", n.label, n.count)
				style = styleGrp
			}

			line := indent + icon + label

			if tm.width > 4 && len(line) > tm.width-1 {
				line = line[:tm.width-4] + "…"
			}
			if tm.width > 0 && len(line) < tm.width {
				line += strings.Repeat(" ", tm.width-len(line))
			}

			if i == tm.cursor {
				sb.WriteString(styleSel.Render(line))
			} else {
				sb.WriteString(style.Render(line))
			}
			rendered++
		}
		// Pad remaining rows.
		for i := rendered; i < vh; i++ {
			sb.WriteString("\n")
		}
	}

	// Filter line.
	if tm.filtering {
		sb.WriteString("\n")
		sb.WriteString(lipgloss.NewStyle().Foreground(colorGreen).
			Render(fmt.Sprintf("  / %s█", tm.filter)))
	} else if tm.filter != "" {
		sb.WriteString("\n")
		sb.WriteString(lipgloss.NewStyle().Foreground(colorDim).
			Render(fmt.Sprintf("  / %s", tm.filter)))
	}

	// Status line.
	total := 0
	for _, r := range tm.roots {
		total += r.count
	}
	status := fmt.Sprintf("  %d functions · %d groups", total, len(tm.roots))
	if tm.filter != "" {
		visible := 0
		for _, r := range tm.flat {
			if r.node.isLeaf() {
				visible++
			}
		}
		status = fmt.Sprintf("  %d/%d matching", visible, total)
	}
	sb.WriteString("\n")
	sb.WriteString(lipgloss.NewStyle().Foreground(colorDim).Render(status))

	return sb.String()
}
