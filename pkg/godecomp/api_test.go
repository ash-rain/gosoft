package godecomp

import (
	"os"
	"testing"
)

func TestDefaultConfig(t *testing.T) {
	cfg := DefaultConfig()

	if cfg.OllamaURL == "" {
		t.Error("expected non-empty OllamaURL")
	}
	if cfg.OllamaModel == "" {
		t.Error("expected non-empty OllamaModel")
	}
	if cfg.DefaultLang == "" {
		t.Error("expected non-empty DefaultLang")
	}

	t.Logf("DefaultConfig: %+v", cfg)
}

func TestOpenCurrentExecutable(t *testing.T) {
	exePath, err := os.Executable()
	if err != nil {
		t.Fatalf("getting executable path: %v", err)
	}

	cfg := DefaultConfig()
	session, err := Open(exePath, cfg)
	if err != nil {
		t.Fatalf("Open(%q) returned error: %v", exePath, err)
	}

	if session == nil {
		t.Fatal("expected non-nil session")
	}
	if session.Binary == nil {
		t.Fatal("expected non-nil binary in session")
	}
	if session.Pipeline == nil {
		t.Fatal("expected non-nil pipeline in session")
	}

	t.Logf("Session binary: format=%s arch=%s bits=%d",
		session.Binary.Format, session.Binary.Arch, session.Binary.Bits)
}

func TestSessionSymbols(t *testing.T) {
	exePath, err := os.Executable()
	if err != nil {
		t.Fatalf("getting executable path: %v", err)
	}

	cfg := DefaultConfig()
	session, err := Open(exePath, cfg)
	if err != nil {
		t.Fatalf("Open() failed: %v", err)
	}

	syms := session.Symbols()
	t.Logf("Found %d function symbols in test binary", len(syms))

	// Go test binaries should have symbols
	// Note: stripped binaries may have 0 symbols
}

func TestSessionStrings(t *testing.T) {
	exePath, err := os.Executable()
	if err != nil {
		t.Fatalf("getting executable path: %v", err)
	}

	cfg := DefaultConfig()
	session, err := Open(exePath, cfg)
	if err != nil {
		t.Fatalf("Open() failed: %v", err)
	}

	strs := session.Strings()
	t.Logf("Found %d strings in test binary", len(strs))
}

func TestOpenNonExistentFile(t *testing.T) {
	cfg := DefaultConfig()
	_, err := Open("/nonexistent/path/to/binary", cfg)
	if err == nil {
		t.Error("expected error for nonexistent file, got nil")
	}
}
