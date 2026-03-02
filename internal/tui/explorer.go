package tui

import (
	"fmt"

	binpkg "godecomp/internal/binary"
)

// symbolItem implements the list.Item interface for Bubble Tea list component.
type symbolItem struct {
	sym binpkg.Symbol
}

// Title returns the display title (symbol name).
func (i symbolItem) Title() string { return i.sym.Name }

// Description returns a brief description with address and type.
func (i symbolItem) Description() string {
	return fmt.Sprintf("0x%x  %s", i.sym.Address, i.sym.Type)
}

// FilterValue returns the string used for filtering.
func (i symbolItem) FilterValue() string { return i.sym.Name }
