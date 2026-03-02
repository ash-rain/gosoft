package tui

import (
	"fmt"
	"strings"

	binpkg "godecomp/internal/binary"
)

// symbolItem wraps a function symbol for the left panel list.
type symbolItem struct{ sym binpkg.Symbol }

func (i symbolItem) Title() string       { return i.sym.Name }
func (i symbolItem) Description() string { return fmt.Sprintf("0x%x  %s", i.sym.Address, i.sym.Type) }
func (i symbolItem) FilterValue() string { return i.sym.Name }

// stringItem wraps an embedded string reference.
type stringItem struct{ ref binpkg.StringRef }

func (i stringItem) Title() string       { return truncateString(i.ref.Value, 60) }
func (i stringItem) Description() string { return fmt.Sprintf("0x%08x  [%s]", i.ref.Offset, i.ref.Section) }
func (i stringItem) FilterValue() string { return i.ref.Value }

// importItem wraps an imported symbol.
type importItem struct{ imp binpkg.Import }

func (i importItem) Title() string {
	if i.imp.Name != "" {
		return i.imp.Name
	}
	return i.imp.Library
}
func (i importItem) Description() string {
	if i.imp.Library != "" && i.imp.Name != "" {
		return "from " + i.imp.Library
	}
	return ""
}
func (i importItem) FilterValue() string { return i.imp.Name + " " + i.imp.Library }

// sectionItem wraps a binary section.
type sectionItem struct{ sec binpkg.Section }

func (i sectionItem) Title() string { return i.sec.Name }
func (i sectionItem) Description() string {
	flags := i.sec.Flags
	if len(flags) > 20 {
		flags = flags[:20]
	}
	dataTag := ""
	if len(i.sec.Data) == 0 {
		dataTag = " (no data)"
	}
	return fmt.Sprintf("0x%08x  %d bytes  %s%s", i.sec.Offset, i.sec.Size, flags, dataTag)
}
func (i sectionItem) FilterValue() string { return i.sec.Name }

// truncateString truncates a string to maxLen characters.
func truncateString(s string, maxLen int) string {
	s = strings.TrimSpace(s)
	if len(s) <= maxLen {
		return s
	}
	if maxLen <= 3 {
		return s[:maxLen]
	}
	return s[:maxLen-3] + "..."
}
