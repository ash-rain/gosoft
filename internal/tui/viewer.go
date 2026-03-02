package tui

import (
	"fmt"
	"strings"

	"godecomp/internal/disasm"
)

// formatDisassembly formats a list of instructions for display in the viewport.
func formatDisassembly(instructions []disasm.Instruction) string {
	if len(instructions) == 0 {
		return "(no disassembly available)"
	}

	var sb strings.Builder
	for _, inst := range instructions {
		// Format bytes as hex
		hexBytes := make([]string, len(inst.Bytes))
		for i, b := range inst.Bytes {
			hexBytes[i] = fmt.Sprintf("%02x", b)
		}
		byteStr := strings.Join(hexBytes, " ")

		if inst.Comment != "" {
			sb.WriteString(fmt.Sprintf("  0x%08x  %-20s  %-8s  %s  ; %s\n",
				inst.Address, byteStr, inst.Mnemonic, inst.OpStr, inst.Comment))
		} else {
			sb.WriteString(fmt.Sprintf("  0x%08x  %-20s  %-8s  %s\n",
				inst.Address, byteStr, inst.Mnemonic, inst.OpStr))
		}
	}
	return sb.String()
}

// formatSourceCode formats decompiled source code for display.
func formatSourceCode(source string, lang string) string {
	if source == "" {
		return fmt.Sprintf("(no %s source code available)", lang)
	}
	return source
}

// truncateString truncates a string to maxLen and appends "..." if needed.
func truncateString(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	if maxLen <= 3 {
		return s[:maxLen]
	}
	return s[:maxLen-3] + "..."
}
