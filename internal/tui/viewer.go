package tui

import (
	"fmt"
	"strings"
	"unicode"

	"godecomp/internal/disasm"
)

// formatDisassembly renders a slice of instructions for the viewport.
func formatDisassembly(instructions []disasm.Instruction) string {
	if len(instructions) == 0 {
		return "(no disassembly available)"
	}
	var sb strings.Builder
	for _, inst := range instructions {
		hexBytes := make([]string, len(inst.Bytes))
		for i, b := range inst.Bytes {
			hexBytes[i] = fmt.Sprintf("%02x", b)
		}
		byteStr := strings.Join(hexBytes, " ")

		if inst.Comment != "" {
			fmt.Fprintf(&sb, "  %08x  %-20s  %-10s %-20s ; %s\n",
				inst.Address, byteStr, inst.Mnemonic, inst.OpStr, inst.Comment)
		} else {
			fmt.Fprintf(&sb, "  %08x  %-20s  %-10s %s\n",
				inst.Address, byteStr, inst.Mnemonic, inst.OpStr)
		}
	}
	return sb.String()
}

// formatHex renders data as a hex dump starting at baseAddr.
// bytesPerRow controls the column count (16 is standard).
func formatHex(data []byte, baseAddr uint64, bytesPerRow int) string {
	if len(data) == 0 {
		return "(empty section — no data)"
	}
	if bytesPerRow <= 0 {
		bytesPerRow = 16
	}

	var sb strings.Builder
	for i := 0; i < len(data); i += bytesPerRow {
		end := i + bytesPerRow
		if end > len(data) {
			end = len(data)
		}
		row := data[i:end]

		// Address
		fmt.Fprintf(&sb, "  %08x  ", baseAddr+uint64(i))

		// Hex bytes
		for j, b := range row {
			if j == bytesPerRow/2 {
				sb.WriteByte(' ')
			}
			fmt.Fprintf(&sb, "%02x ", b)
		}

		// Padding if last row is short
		missing := bytesPerRow - len(row)
		for j := 0; j < missing; j++ {
			if j+len(row) == bytesPerRow/2 {
				sb.WriteByte(' ')
			}
			sb.WriteString("   ")
		}

		sb.WriteString(" |")

		// ASCII representation
		for _, b := range row {
			if b >= 0x20 && b <= 0x7e && unicode.IsPrint(rune(b)) {
				sb.WriteByte(b)
			} else {
				sb.WriteByte('.')
			}
		}
		sb.WriteString("|\n")
	}
	return sb.String()
}

// formatSourceCode returns source code ready for display.
func formatSourceCode(source, lang string) string {
	if source == "" {
		return fmt.Sprintf("(no %s source — press [d] to decompile)", lang)
	}
	return source
}

// wrapText wraps long lines to fit within maxWidth columns.
// It preserves existing newlines and only breaks lines that exceed the width.
// For the Source tab this makes AI output and pseudo-code readable;
// Disasm/Hex tabs have fixed-width rows and are left untouched.
func wrapText(text string, maxWidth int) string {
	if maxWidth <= 0 {
		return text
	}
	lines := strings.Split(text, "\n")
	var sb strings.Builder
	for i, line := range lines {
		if i > 0 {
			sb.WriteByte('\n')
		}
		if len(line) <= maxWidth {
			sb.WriteString(line)
			continue
		}
		// Wrap at word boundaries.
		remaining := line
		first := true
		for len(remaining) > 0 {
			if !first {
				sb.WriteByte('\n')
			}
			first = false
			if len(remaining) <= maxWidth {
				sb.WriteString(remaining)
				break
			}
			// Try to break at a space.
			cut := maxWidth
			for cut > 0 && remaining[cut] != ' ' {
				cut--
			}
			if cut == 0 {
				// No space found — hard break.
				cut = maxWidth
			}
			sb.WriteString(remaining[:cut])
			remaining = strings.TrimLeft(remaining[cut:], " ")
		}
	}
	return sb.String()
}
