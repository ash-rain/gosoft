package binary

import (
	"bytes"
	"os"
	"testing"
)

func TestDetectFormatELF(t *testing.T) {
	// ELF magic: \x7fELF
	magic := []byte{0x7f, 'E', 'L', 'F', 0x02, 0x01, 0x01, 0x00}
	r := bytes.NewReader(magic)
	format := DetectFormat(r)
	if format != FormatELF {
		t.Errorf("expected ELF, got %s", format)
	}
}

func TestDetectFormatPE(t *testing.T) {
	// PE magic: MZ
	magic := []byte{'M', 'Z', 0x90, 0x00}
	r := bytes.NewReader(magic)
	format := DetectFormat(r)
	if format != FormatPE {
		t.Errorf("expected PE, got %s", format)
	}
}

func TestDetectFormatWASM(t *testing.T) {
	// WASM magic: \x00asm
	magic := []byte{0x00, 'a', 's', 'm', 0x01, 0x00, 0x00, 0x00}
	r := bytes.NewReader(magic)
	format := DetectFormat(r)
	if format != FormatWASM {
		t.Errorf("expected WASM, got %s", format)
	}
}

func TestDetectFormatMachO(t *testing.T) {
	// Mach-O little-endian 64-bit: \xcf\xfa\xed\xfe
	magic := []byte{0xcf, 0xfa, 0xed, 0xfe}
	r := bytes.NewReader(magic)
	format := DetectFormat(r)
	if format != FormatMachO {
		t.Errorf("expected MachO, got %s", format)
	}
}

func TestDetectFormatUnknown(t *testing.T) {
	magic := []byte{0xff, 0xfe, 0xfd, 0xfc}
	r := bytes.NewReader(magic)
	format := DetectFormat(r)
	if format != FormatUnknown {
		t.Errorf("expected Unknown, got %s", format)
	}
}

func TestLoadCurrentExecutable(t *testing.T) {
	exePath, err := os.Executable()
	if err != nil {
		t.Fatalf("getting executable path: %v", err)
	}

	b, err := Load(exePath)
	if err != nil {
		t.Fatalf("loading executable %q: %v", exePath, err)
	}

	if b == nil {
		t.Fatal("expected non-nil binary")
	}

	if b.Format == FormatUnknown {
		t.Errorf("expected known format, got Unknown")
	}

	if len(b.Symbols) == 0 {
		t.Log("warning: no symbols found (may be stripped binary)")
		// Not a hard failure — Go test binaries may have symbols in different places
	}

	t.Logf("Loaded binary: format=%s arch=%s bits=%d os=%s symbols=%d",
		b.Format, b.Arch, b.Bits, b.OS, len(b.Symbols))
}

func TestExtractStrings(t *testing.T) {
	data := []byte("he\x00hello\x00world\x00ab\x00this is a long string\x00")
	refs := extractStrings(data, ".test", 0)

	if len(refs) == 0 {
		t.Fatal("expected at least one string extracted")
	}

	// Should find "hello", "world", "this is a long string" (but not "he" which is too short)
	found := make(map[string]bool)
	for _, ref := range refs {
		found[ref.Value] = true
	}

	if !found["hello"] {
		t.Error("expected to find 'hello'")
	}
	if !found["world"] {
		t.Error("expected to find 'world'")
	}
	if found["he"] {
		t.Error("should not find 'he' (too short)")
	}
	if found["ab"] {
		t.Error("should not find 'ab' (too short)")
	}
}
