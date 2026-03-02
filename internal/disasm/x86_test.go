package disasm

import (
	"strings"
	"testing"
)

func TestX86DisasmNOP(t *testing.T) {
	d := &x86Disasm{bits: 64}

	// NOP instruction: 0x90
	data := []byte{0x90}
	insts, err := d.Disassemble(data, 0x1000)
	if err != nil {
		t.Fatalf("disassemble failed: %v", err)
	}
	if len(insts) == 0 {
		t.Fatal("expected at least one instruction")
	}

	inst := insts[0]
	if !strings.EqualFold(inst.Mnemonic, "NOP") {
		t.Errorf("expected NOP, got %q", inst.Mnemonic)
	}
	if inst.Address != 0x1000 {
		t.Errorf("expected address 0x1000, got 0x%x", inst.Address)
	}
}

func TestX86DisasmMOV(t *testing.T) {
	d := &x86Disasm{bits: 64}

	// MOV RAX, RAX: 48 89 C0
	data := []byte{0x48, 0x89, 0xc0}
	insts, err := d.Disassemble(data, 0x2000)
	if err != nil {
		t.Fatalf("disassemble failed: %v", err)
	}
	if len(insts) == 0 {
		t.Fatal("expected at least one instruction")
	}

	inst := insts[0]
	if !strings.EqualFold(inst.Mnemonic, "MOV") {
		t.Errorf("expected MOV, got %q", inst.Mnemonic)
	}
	t.Logf("MOV instruction: %s %s", inst.Mnemonic, inst.OpStr)
}

func TestX86DisasmRET(t *testing.T) {
	d := &x86Disasm{bits: 64}

	// RET: C3
	data := []byte{0xc3}
	insts, err := d.Disassemble(data, 0x3000)
	if err != nil {
		t.Fatalf("disassemble failed: %v", err)
	}
	if len(insts) == 0 {
		t.Fatal("expected at least one instruction")
	}

	inst := insts[0]
	if !strings.EqualFold(inst.Mnemonic, "RET") {
		t.Errorf("expected RET, got %q", inst.Mnemonic)
	}
}

func TestX86DisasmMultiple(t *testing.T) {
	d := &x86Disasm{bits: 64}

	// NOP, MOV RAX RAX, RET
	data := []byte{0x90, 0x48, 0x89, 0xc0, 0xc3}
	insts, err := d.Disassemble(data, 0x4000)
	if err != nil {
		t.Fatalf("disassemble failed: %v", err)
	}
	if len(insts) != 3 {
		t.Errorf("expected 3 instructions, got %d", len(insts))
		for i, inst := range insts {
			t.Logf("  [%d] 0x%x: %s %s", i, inst.Address, inst.Mnemonic, inst.OpStr)
		}
	}
}

func TestX86DisasmArch(t *testing.T) {
	d32 := &x86Disasm{bits: 32}
	if d32.Arch() != "x86" {
		t.Errorf("expected x86, got %s", d32.Arch())
	}

	d64 := &x86Disasm{bits: 64}
	if d64.Arch() != "x86_64" {
		t.Errorf("expected x86_64, got %s", d64.Arch())
	}
}

func TestNewDisassembler(t *testing.T) {
	tests := []struct {
		arch    string
		wantErr bool
		wantArch string
	}{
		{"x86", false, "x86"},
		{"x86_64", false, "x86_64"},
		{"arm", false, "arm"},
		{"arm64", false, "arm64"},
		{"mips", true, ""},
		{"unknown", true, ""},
	}

	for _, tt := range tests {
		t.Run(tt.arch, func(t *testing.T) {
			d, err := New(tt.arch)
			if tt.wantErr {
				if err == nil {
					t.Errorf("expected error for arch %q", tt.arch)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if d.Arch() != tt.wantArch {
				t.Errorf("expected arch %q, got %q", tt.wantArch, d.Arch())
			}
		})
	}
}
