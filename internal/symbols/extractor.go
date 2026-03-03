package symbols

import (
	"sort"
	"strings"

	"softy/internal/binary"
)

// FunctionList returns only function-type symbols sorted by address.
func FunctionList(b *binary.Binary) []binary.Symbol {
	var funcs []binary.Symbol
	for _, sym := range b.Symbols {
		if sym.Type == "func" {
			funcs = append(funcs, sym)
		}
	}
	sort.Slice(funcs, func(i, j int) bool {
		return funcs[i].Address < funcs[j].Address
	})
	return funcs
}

// FindSymbol finds a symbol by name (case-insensitive partial match).
// Returns the first match or nil if not found.
func FindSymbol(b *binary.Binary, name string) *binary.Symbol {
	nameLower := strings.ToLower(name)
	// Try exact match first
	for i := range b.Symbols {
		if strings.ToLower(b.Symbols[i].Name) == nameLower {
			return &b.Symbols[i]
		}
	}
	// Try partial match
	for i := range b.Symbols {
		if strings.Contains(strings.ToLower(b.Symbols[i].Name), nameLower) {
			return &b.Symbols[i]
		}
	}
	return nil
}

// ExtractStrings returns all StringRefs from the binary (already populated by loader).
func ExtractStrings(b *binary.Binary) []binary.StringRef {
	result := make([]binary.StringRef, len(b.Strings))
	copy(result, b.Strings)
	return result
}

// FilterStrings returns strings matching a filter keyword (case-insensitive).
func FilterStrings(b *binary.Binary, filter string) []binary.StringRef {
	if filter == "" {
		return ExtractStrings(b)
	}
	filterLower := strings.ToLower(filter)
	var result []binary.StringRef
	for _, s := range b.Strings {
		if strings.Contains(strings.ToLower(s.Value), filterLower) {
			result = append(result, s)
		}
	}
	return result
}
