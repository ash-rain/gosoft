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
