package symbols

import (
	"testing"

	"godecomp/internal/binary"
)

// makeMockBinary creates a mock binary for testing.
func makeMockBinary() *binary.Binary {
	return &binary.Binary{
		Path:   "/tmp/test-binary",
		Format: binary.FormatELF,
		Arch:   binary.ArchX8664,
		Bits:   64,
		OS:     "linux",
		Symbols: []binary.Symbol{
			{Name: "main", Address: 0x1000, Size: 100, Type: "func"},
			{Name: "init", Address: 0x2000, Size: 50, Type: "func"},
			{Name: "globalVar", Address: 0x3000, Size: 8, Type: "object"},
			{Name: "helper", Address: 0x4000, Size: 200, Type: "func"},
			{Name: "unused", Address: 0x5000, Size: 10, Type: "unknown"},
		},
		Strings: []binary.StringRef{
			{Value: "Hello, World!", Offset: 0x6000, Section: ".rodata"},
			{Value: "Error occurred", Offset: 0x6100, Section: ".rodata"},
			{Value: "https://example.com", Offset: 0x6200, Section: ".rodata"},
			{Value: "debug mode", Offset: 0x6300, Section: ".data"},
		},
		Imports: []binary.Import{
			{Library: "libc.so.6", Name: "printf"},
			{Library: "libc.so.6", Name: "malloc"},
		},
	}
}

func TestFunctionList(t *testing.T) {
	b := makeMockBinary()
	funcs := FunctionList(b)

	// Should only return func-type symbols
	for _, sym := range funcs {
		if sym.Type != "func" {
			t.Errorf("expected func type, got %q for symbol %s", sym.Type, sym.Name)
		}
	}

	// Should be sorted by address
	for i := 1; i < len(funcs); i++ {
		if funcs[i].Address < funcs[i-1].Address {
			t.Errorf("functions not sorted: %s (0x%x) comes after %s (0x%x)",
				funcs[i].Name, funcs[i].Address,
				funcs[i-1].Name, funcs[i-1].Address)
		}
	}

	// Should have 3 functions (main, init, helper)
	if len(funcs) != 3 {
		t.Errorf("expected 3 functions, got %d", len(funcs))
		for _, f := range funcs {
			t.Logf("  - %s (%s)", f.Name, f.Type)
		}
	}
}

func TestFindSymbolExact(t *testing.T) {
	b := makeMockBinary()

	sym := FindSymbol(b, "main")
	if sym == nil {
		t.Fatal("expected to find 'main' symbol")
	}
	if sym.Name != "main" {
		t.Errorf("expected 'main', got %q", sym.Name)
	}
	if sym.Address != 0x1000 {
		t.Errorf("expected address 0x1000, got 0x%x", sym.Address)
	}
}

func TestFindSymbolCaseInsensitive(t *testing.T) {
	b := makeMockBinary()

	sym := FindSymbol(b, "MAIN")
	if sym == nil {
		t.Fatal("expected to find 'main' symbol (case-insensitive)")
	}
}

func TestFindSymbolPartialMatch(t *testing.T) {
	b := makeMockBinary()

	sym := FindSymbol(b, "help")
	if sym == nil {
		t.Fatal("expected to find 'helper' symbol via partial match")
	}
	if sym.Name != "helper" {
		t.Errorf("expected 'helper', got %q", sym.Name)
	}
}

func TestFindSymbolNotFound(t *testing.T) {
	b := makeMockBinary()

	sym := FindSymbol(b, "nonexistent_function_xyz")
	if sym != nil {
		t.Errorf("expected nil, got symbol %q", sym.Name)
	}
}

func TestExtractStrings(t *testing.T) {
	b := makeMockBinary()
	strs := ExtractStrings(b)

	if len(strs) != len(b.Strings) {
		t.Errorf("expected %d strings, got %d", len(b.Strings), len(strs))
	}
}

func TestFilterStrings(t *testing.T) {
	b := makeMockBinary()

	// Filter by "error"
	filtered := FilterStrings(b, "error")
	if len(filtered) == 0 {
		t.Fatal("expected at least one string matching 'error'")
	}
	for _, s := range filtered {
		if !containsCI(s.Value, "error") {
			t.Errorf("string %q does not match filter 'error'", s.Value)
		}
	}
}

func TestFilterStringsEmpty(t *testing.T) {
	b := makeMockBinary()

	// Empty filter should return all strings
	all := FilterStrings(b, "")
	if len(all) != len(b.Strings) {
		t.Errorf("expected %d strings with empty filter, got %d", len(b.Strings), len(all))
	}
}

func TestFilterStringsNoMatch(t *testing.T) {
	b := makeMockBinary()

	// Filter that matches nothing
	result := FilterStrings(b, "zzzzthiscannotmatch")
	if len(result) != 0 {
		t.Errorf("expected 0 results, got %d", len(result))
	}
}

// containsCI is a case-insensitive contains check.
func containsCI(s, substr string) bool {
	sLower := []rune(s)
	subLower := []rune(substr)
	_ = sLower
	_ = subLower
	// Simple implementation
	if len(s) < len(substr) {
		return false
	}
	sBytes := []byte(s)
	subBytes := []byte(substr)
	for i := 0; i <= len(sBytes)-len(subBytes); i++ {
		match := true
		for j, b := range subBytes {
			cb := sBytes[i+j]
			if cb >= 'A' && cb <= 'Z' {
				cb += 32
			}
			bb := b
			if bb >= 'A' && bb <= 'Z' {
				bb += 32
			}
			if cb != bb {
				match = false
				break
			}
		}
		if match {
			return true
		}
	}
	return false
}
